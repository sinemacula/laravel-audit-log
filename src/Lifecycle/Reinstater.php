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
 * Reinstates an erased owner, so a key may be created again above its erasure's
 * floor; an erased generation never reopens.
 *
 * The owner's marker is trusted only when it names a signed erasure row of the
 * verified chain; otherwise the journal is broken.
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
     * Reinstate the erased owner in one lifecycle transaction; on MySQL the
     * owner's lock outlives it, so it is released after.
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
     * Check the owner's latest marker, then append the `reinstate` row and
     * insert its marker.
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
     * Refuse an erased marker that does not name a signed erasure row of the
     * verified chain at its floor.
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
     * Whether the row's payload matches its digest and its HMAC verifies under
     * a ring key.
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
     * Whether the signed row is an erasure of the marker's owner in the
     * configured log, at the marker's floor.
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
     * Whether the payload records the owner's fingerprint; a key the ring no
     * longer holds proves nothing.
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
     * The journal row of the id on the writer, or `null` when there is none or
     * it cannot be read.
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
