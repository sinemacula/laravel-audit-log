<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Keys\OwnerLock;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarker;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarkers;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Reinstates an erased owner, so a key may be created for the owner again, in a
 * generation above the floor its erasure set: an erased generation never
 * reopens, and reinstatement creates no key.
 *
 * The installation is confirmed first, once, then the reinstatement runs in one
 * `MaintenanceTransaction`: the lifecycle lock, the whole journal verified,
 * then the owner's lock, so no key of the owner is created meanwhile, and the
 * owner's latest marker read after both. A marker that does not record an
 * erasure, or no marker, is refused with a `ReinstatementRefusedException`
 * (`not_erased`), writing nothing. The marker is not trusted on its own: it
 * must name, by its id and its sequence, a row of the verified chain, signed,
 * whose payload is its digest's, that is an erasure of this owner, by the
 * fingerprint the row records, at the marker's floor. A marker that does not is
 * refused with a `JournalBrokenException`, since the journal and the markers
 * contradict each other, and nothing is written.
 *
 * Otherwise a `reinstate` row is appended onto the verified head, naming the
 * authority and the owner's fingerprint under the ring's signing key and the
 * floor, and a `reinstated` marker is inserted under the row's id, at its
 * sequence and time, with the same floor; both commit together or not at all.
 * On MySQL the owner's lock is released once the transaction has ended, however
 * it ended; elsewhere the transaction's end released it.
 *
 * A reinstatement makes new keys possible, never an old key readable again:
 * whoever holds the maintenance credentials can still change the markers, and
 * the journal makes that detectable, not impossible.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Reinstater
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction  $transaction
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Journal  $journal
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Keys\OwnerMarkers  $markers
     * @param  \SineMacula\Laravel\AuditLog\Keys\OwnerLock  $lock
     * @param  \SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint  $fingerprints
     */
    public function __construct(

        /** The frame the reinstatement runs in, behind the lifecycle lock. */
        private MaintenanceTransaction $transaction,

        /** The journal the reinstatement is appended to. */
        private Journal $journal,

        /** The signer the journal and the erasure row are verified with. */
        private JournalSigner $signer,

        /** The settings the journal's log id is read from. */
        private SealSettings $settings,

        /** The owner markers, read and inserted on the maintenance connection. */
        private OwnerMarkers $markers,

        /** The owner's lock, taken after the lifecycle lock. */
        private OwnerLock $lock,

        /** Takes the owner's fingerprint, and checks the erasure row's. */
        private OwnerFingerprint $fingerprints,
    ) {}

    /**
     * Reinstate the erased owner in one lifecycle transaction, and return what
     * it did: a `reinstate` row and a `reinstated` marker at the floor of the
     * owner's erasure.
     *
     * @param  string  $operationId
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ReinstateResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\ReinstatementRefusedException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \SineMacula\Laravel\AuditLog\Keys\OwnerLockTimeoutException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function reinstate(string $operationId, #[\SensitiveParameter] Reference $owner, Authority $authority): ReinstateResult
    {
        $this->transaction->confirm();

        $locked = null;

        try {
            return $this->transaction->run($operationId, function (Connection $connection) use ($operationId, $owner, $authority, &$locked): ReinstateResult {
                $replay = JournalReplay::start($this->signer, $this->settings->logId())->verify($connection);
                $locked = $connection;

                $this->lock->acquire($connection, $owner);

                return $this->reinstateIn($connection, $replay, $operationId, $owner, $authority);
            });
        } finally {
            if ($locked !== null) {
                $this->lock->release($locked, $owner);
            }
        }
    }

    /**
     * Reinstate the owner inside the lifecycle transaction the connection
     * holds, after the owner's lock: the latest marker checked, then the row
     * appended and the marker inserted.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  string  $operationId
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ReinstateResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\ReinstatementRefusedException
     * @throws \LogicException
     */
    private function reinstateIn(Connection $connection, JournalReplay $replay, string $operationId, #[\SensitiveParameter] Reference $owner, Authority $authority): ReinstateResult
    {
        $marker = $this->markers->latest($connection, $owner);

        if ($marker === null || !$marker->isErasure()) {
            throw ReinstatementRefusedException::notErased();
        }

        $this->checkInTheChain($connection, $replay, $marker);

        [$fingerprintKey, $fingerprint] = $this->fingerprints->of($owner);

        $floor   = $marker->generationFloor;
        $payload = ['owner_fingerprint' => $fingerprint, 'fingerprint_key' => $fingerprintKey, 'generation_floor' => $floor];
        $row     = $this->journal->append($connection, $replay, JournalKind::REINSTATE, $operationId, $authority, $payload)->lastAppended()
            ?? throw new \LogicException('The journal accepted a reinstatement its replay does not hold.');

        $this->markers->insert($connection, new OwnerMarker($row->id, $owner, MarkerTransition::REINSTATED, $floor, $row->sequence, $row->occurredAt));

        return new ReinstateResult($operationId, $row->id, $fingerprint, $fingerprintKey, $floor);
    }

    /**
     * Refuse an erased marker that names no row of the verified chain by its id
     * and sequence, or one whose row is not a signed erasure of the marker's
     * owner at the marker's floor.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  \SineMacula\Laravel\AuditLog\Keys\OwnerMarker  $marker
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     */
    private function checkInTheChain(Connection $connection, JournalReplay $replay, #[\SensitiveParameter] OwnerMarker $marker): void
    {
        $row  = self::rowOf($connection, $marker->id);
        $head = $replay->head()[0] ?? 0;

        if ($row === null || $row->sequence !== $marker->journalSequence || $row->sequence > $head) {
            throw JournalBrokenException::at(Finding::JOURNAL_GAP, $marker->id);
        }

        if (!$this->isSigned($row)) {
            throw JournalBrokenException::at(Finding::JOURNAL_SIGNATURE, $row->id);
        }

        if (!$this->recordsTheErasure($row, $marker)) {
            throw JournalBrokenException::at(Finding::JOURNAL_TRANSITION, $row->id);
        }
    }

    /**
     * Whether the row's payload is its digest's and its HMAC its own, under a
     * key the ring holds.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @return bool
     */
    private function isSigned(#[\SensitiveParameter] JournalRow $row): bool
    {
        try {
            return $row->payload !== null && $row->hasPayloadOfItsDigest() && $this->signer->verifies($row);
        } catch (\UnexpectedValueException|UnknownKeyException) {
            return false;
        }
    }

    /**
     * Whether the signed row is an erasure, in the configured log, of the
     * marker's owner by the fingerprint it records, at the marker's floor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  \SineMacula\Laravel\AuditLog\Keys\OwnerMarker  $marker
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function recordsTheErasure(#[\SensitiveParameter] JournalRow $row, #[\SensitiveParameter] OwnerMarker $marker): bool
    {
        $payload = $row->payloadMap() ?? [];
        $erasure = $row->kind === JournalKind::ERASURE && $row->logId === $this->settings->logId();

        return $erasure && ($payload['generation_floor'] ?? null) === $marker->generationFloor && $this->isPrintedIn($payload, $marker->owner);
    }

    /**
     * Whether the payload records the owner's fingerprint under the ring key it
     * names; a key the ring no longer holds proves nothing.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $payload
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return bool
     */
    private function isPrintedIn(#[\SensitiveParameter] array $payload, #[\SensitiveParameter] Reference $owner): bool
    {
        $key     = $payload['fingerprint_key']   ?? null;
        $printed = $payload['owner_fingerprint'] ?? null;

        if (!is_string($key) || !is_string($printed)) {
            return false;
        }

        try {
            return hash_equals($this->fingerprints->under($key, $owner), $printed);
        } catch (\UnexpectedValueException|UnknownKeyException) {
            return false;
        }
    }

    /**
     * The journal row of the id on the connection's writer, with its payload,
     * or `null` when there is none or it cannot be read.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $id
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\JournalRow
     *
     * @throws \InvalidArgumentException
     */
    private static function rowOf(Connection $connection, string $id): ?JournalRow
    {
        $stored = $connection->table(LifecycleTables::journalTable())->useWritePdo()->where('id', $id)->first();

        if ($stored === null) {
            return null;
        }

        try {
            return JournalRow::fromRow((array) $stored, true);
        } catch (\UnexpectedValueException) {
            // A row that cannot be read is no row of the verified chain
            return null;
        }
    }
}
