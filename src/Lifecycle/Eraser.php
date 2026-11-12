<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Keys\KeyStore;
use SineMacula\Laravel\AuditLog\Keys\OwnerLock;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarker;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarkers;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;
use SineMacula\Laravel\AuditLog\Privacy\KeyStoreUse;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Erases an owner by destroying every key it holds and marking it erased, all
 * or nothing unless asked to go ahead in part.
 *
 * A key that does not authenticate is never destroyed; refusals write nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Eraser
{
    /** @var int The most live or superseded keys one erasure destroys. */
    public const int MAX_KEYS = 10000;

    /** @var int The most keys one tombstone update names. */
    public const int STATEMENT_IDS = 500;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction  $transaction
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Journal  $journal
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyStore  $keys
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner  $keySigner
     * @param  \SineMacula\Laravel\AuditLog\Keys\OwnerMarkers  $markers
     * @param  \SineMacula\Laravel\AuditLog\Keys\OwnerLock  $lock
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ErasureBlocks  $blocks
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PendingDeliveries  $deliveries
     * @param  \SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint  $fingerprints
     * @param  \SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy  $policy
     * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $encrypter
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** Runs the erasure behind the lifecycle lock. */
        private MaintenanceTransaction $transaction,

        /** The journal the erasure is appended to. */
        private Journal $journal,

        /** Verifies the journal. */
        private JournalSigner $signer,

        /** Gives the journal's log id. */
        private SealSettings $settings,

        /** Reads the owner's keys on the maintenance connection. */
        private KeyStore $keys,

        /** Authenticates every key of the owner. */
        private SubjectKeySigner $keySigner,

        /** The owner markers on the maintenance connection. */
        private OwnerMarkers $markers,

        /** The owner's lock, taken after the lifecycle lock. */
        private OwnerLock $lock,

        /** Decides which keys must be kept. */
        private ErasureBlocks $blocks,

        /** Counts the outbox rows older than the erasure. */
        private PendingDeliveries $deliveries,

        /** Takes the owner's fingerprint. */
        private OwnerFingerprint $fingerprints,

        /** The policy whose preservation blocks a key. */
        private RetentionPolicy $policy,

        /** The bound field encrypter, which must keep the package's key store. */
        private FieldEncrypter $encrypter,

        /** The erasure's start, which decides its outbox count and preservation. */
        private Clock $clock,
    ) {}

    /**
     * Erase the owner in one lifecycle transaction; in a run of erasures the
     * verified journal is carried from each committed erasure to the next.
     *
     * @param  string  $operationId
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  bool  $partial
     * @param  bool  $pending
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\ErasureRun  $erasures
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\RetentionConflictException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \SineMacula\Laravel\AuditLog\Keys\OwnerLockTimeoutException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     */
    public function erase(
        string $operationId,
        #[\SensitiveParameter]
        Reference $owner,
        Authority $authority,
        bool $partial,
        bool $pending,
        ?ErasureRun $erasures = null,
    ): ErasureResult {
        [$fingerprintKey, $fingerprint] = $this->fingerprints->of($owner);

        $this->refuseAnUnsupportedEncrypter($fingerprint, $fingerprintKey);

        $erasures ??= new ErasureRun;

        if (!$erasures->isConfirmed()) {
            $this->transaction->confirm();
            $erasures->confirmed();
        }

        $startedAt = $this->clock->now();
        $locked    = null;
        $run       = [
            'operation'       => $operationId,
            'authority'       => $authority,
            'partial'         => $partial,
            'pending'         => $pending,
            'started'         => StoredTime::format($startedAt),
            'fingerprint'     => $fingerprint,
            'fingerprint_key' => $fingerprintKey,
        ];

        try {
            [$result, $replay] = $this->transaction->run($operationId, function (Connection $connection) use ($owner, $run, $startedAt, $erasures, &$locked): array {
                $carried = $erasures->replay();
                $replay  = $carried === null ? JournalReplay::start($this->signer, $this->settings->logId())->verify($connection) : $carried->advance($connection);
                $locked  = $connection;

                $this->lock->acquire($connection, $owner);

                return $this->eraseIn($connection, $replay, $owner, $run, new RetentionDecisions($this->policy, $startedAt));
            });
        } finally {
            if ($locked !== null) {
                $this->lock->release($locked, $owner);
            }
        }

        $erasures->committed($replay);

        return $result;
    }

    /**
     * Refuse the erasure when the bound field encrypter does not keep the
     * package's key store, whose keys it cannot see.
     *
     * @param  string  $fingerprint
     * @param  string  $fingerprintKey
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException
     */
    private function refuseAnUnsupportedEncrypter(string $fingerprint, string $fingerprintKey): void
    {
        if (KeyStoreUse::covers($this->encrypter)) {
            return;
        }

        throw ErasureRefusedException::of(ErasureRefusal::UNSUPPORTED_ENCRYPTER, [KeyStoreUse::describe($this->encrypter)], $fingerprint, $fingerprintKey);
    }

    /**
     * Erase the owner under its lock, returning the result and the replay it
     * leaves.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  array{operation: string, authority: \SineMacula\Laravel\AuditLog\Lifecycle\Authority, partial: bool, pending: bool, started: string, fingerprint: string, fingerprint_key: string}  $run
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $decisions
     * @return array{0: \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult, 1: \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay}
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\RetentionConflictException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function eraseIn(Connection $connection, JournalReplay $replay, #[\SensitiveParameter] Reference $owner, array $run, RetentionDecisions $decisions): array
    {
        $marker  = $this->markers->latest($connection, $owner);
        $keys    = $this->authenticKeys($connection, $owner, $run);
        $holding = array_values(array_filter($keys, static fn (#[\SensitiveParameter] SubjectKeyRow $key): bool => $key->state->holdsAKey()));

        if ($holding === [] && $marker?->isErasure() === true) {
            return [ErasureResult::alreadyErased($run['operation'], $run['fingerprint'], $run['fingerprint_key']), $replay];
        }

        $pendingRows = $this->acceptedPendingRows($connection, $run);

        [$blocks, $affected] = $this->blocks->for($connection, $holding, $replay->holds(), $decisions);

        $blocked   = self::refuseUnlessPartial($blocks, $run);
        $kept      = array_fill_keys(array_map(static fn (ErasureBlock $block): string => $block->keyId, $blocks), true);
        $destroyed = array_values(array_filter($holding, static fn (#[\SensitiveParameter] SubjectKeyRow $key): bool => !isset($kept[$key->id])));
        $floor     = max([$marker->generationFloor ?? 0, ...array_map(static fn (#[\SensitiveParameter] SubjectKeyRow $key): int => $key->generation, $keys)]);
        $payload   = self::payloadOf($run, $floor, $pendingRows, $destroyed, $blocks, $affected);
        $replay    = $this->journal->append($connection, $replay, JournalKind::ERASURE, $run['operation'], $run['authority'], $payload);
        $row       = self::appended($replay);

        self::tombstone($connection, array_map(static fn (#[\SensitiveParameter] SubjectKeyRow $key): string => $key->id, $destroyed), $row->id);

        $this->markers->insert($connection, new OwnerMarker($row->id, $owner, MarkerTransition::ERASED, $floor, $row->sequence, $row->occurredAt));

        return [new ErasureResult(
            $run['operation'],
            $row->id,
            $blocks === [] ? ErasureStatus::COMPLETE : ErasureStatus::PARTIAL,
            $run['fingerprint'],
            $run['fingerprint_key'],
            count($destroyed),
            count($blocks),
            $affected,
            $blocked,
            $pendingRows > 0,
        ), $replay];
    }

    /**
     * How many outbox rows predate the erasure; any refuses it unless accepted.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  array{operation: string, authority: \SineMacula\Laravel\AuditLog\Lifecycle\Authority, partial: bool, pending: bool, started: string, fingerprint: string, fingerprint_key: string}  $run
     * @return int
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function acceptedPendingRows(Connection $connection, array $run): int
    {
        $pendingRows = $this->deliveries->olderThan($connection, $run['started']);

        if ($pendingRows > 0 && !$run['pending']) {
            throw self::refusal(ErasureRefusal::PENDING_DELIVERY, [], $run);
        }

        return $pendingRows;
    }

    /**
     * Every distinct reason the blocks give; any block refuses the erasure
     * unless it goes ahead in part.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\ErasureBlock>  $blocks
     * @param  array{operation: string, authority: \SineMacula\Laravel\AuditLog\Lifecycle\Authority, partial: bool, pending: bool, started: string, fingerprint: string, fingerprint_key: string}  $run
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function refuseUnlessPartial(array $blocks, array $run): array
    {
        $blocked = array_values(array_unique(array_merge([], ...array_map(static fn (ErasureBlock $block): array => $block->reasons, $blocks))));

        if ($blocks !== [] && !$run['partial']) {
            throw self::refusal(ErasureRefusal::BLOCKED, $blocked, $run);
        }

        return $blocked;
    }

    /**
     * The erasure row the replay accepted last.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     *
     * @throws \LogicException
     */
    private static function appended(#[\SensitiveParameter] JournalReplay $replay): JournalRow
    {
        return $replay->lastAppended() ?? throw new \LogicException('The journal accepted an erasure its replay does not hold.');
    }

    /**
     * Every key of the owner, each authenticated; more than `MAX_KEYS` holding
     * keys, or one that does not verify, refuses the erasure.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  array{operation: string, authority: \SineMacula\Laravel\AuditLog\Lifecycle\Authority, partial: bool, pending: bool, started: string, fingerprint: string, fingerprint_key: string}  $run
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function authenticKeys(Connection $connection, #[\SensitiveParameter] Reference $owner, array $run): array
    {
        $holding = $connection->table(KeyTables::subjectKeysTable())
            ->useWritePdo()
            ->where('owner_type', $owner->type)
            ->where('owner_id', $owner->id)
            ->whereIn('state', [KeyState::LIVE->value, KeyState::SUPERSEDED->value])
            ->count();

        if ($holding > self::MAX_KEYS) {
            throw self::refusal(ErasureRefusal::TOO_MANY_KEYS, [], $run);
        }

        try {
            $keys = $this->keys->ofOwner($connection, $owner);
        } catch (\UnexpectedValueException) {
            // A key too malformed to read names no id that can be trusted
            throw self::refusal(ErasureRefusal::KEY_UNVERIFIABLE, [], $run);
        }

        $unverifiable = array_values(array_filter($keys, fn (#[\SensitiveParameter] SubjectKeyRow $key): bool => !$this->isAuthentic($key)));

        if ($unverifiable !== []) {
            throw self::refusal(ErasureRefusal::KEY_UNVERIFIABLE, array_map(static fn (#[\SensitiveParameter] SubjectKeyRow $key): string => $key->id, $unverifiable), $run);
        }

        return $keys;
    }

    /**
     * Whether the key verifies under the signing key it names; a key the ring
     * does not hold proves nothing.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @return bool
     */
    private function isAuthentic(#[\SensitiveParameter] SubjectKeyRow $key): bool
    {
        try {
            return $this->keySigner->verifies($key);
        } catch (\UnexpectedValueException|UnknownKeyException) {
            return false;
        }
    }

    /**
     * The erasure row's payload, with destroyed and kept keys sorted by id.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array{operation: string, authority: \SineMacula\Laravel\AuditLog\Lifecycle\Authority, partial: bool, pending: bool, started: string, fingerprint: string, fingerprint_key: string}  $run
     * @param  int  $floor
     * @param  int  $pendingRows
     * @param  list<\SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>  $destroyed
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\ErasureBlock>  $blocks
     * @param  int  $affected
     * @return array{owner_fingerprint: string, fingerprint_key: string, generation_floor: int, partial: bool, pending_accepted: bool, pending_rows: int, destroyed: list<array{key_id: string, unit: string, generation: int, before: array{state: string, hmac: string, wrapped_digest: ?string, wrap_key_id: ?string}, after: array{state: string}}>, kept: list<array{key_id: string, unit: string, generation: int, reasons: non-empty-list<string>}>, entries_affected: int}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function payloadOf(array $run, int $floor, int $pendingRows, #[\SensitiveParameter] array $destroyed, array $blocks, int $affected): array
    {
        $kept = array_map(static fn (ErasureBlock $block): array => $block->toArray(), $blocks);

        usort($destroyed, static fn (#[\SensitiveParameter] SubjectKeyRow $a, #[\SensitiveParameter] SubjectKeyRow $b): int => strcmp($a->id, $b->id));
        usort($kept, static fn (array $a, array $b): int => strcmp($a['key_id'], $b['key_id']));

        return [
            'owner_fingerprint' => $run['fingerprint'],
            'fingerprint_key'   => $run['fingerprint_key'],
            'generation_floor'  => $floor,
            'partial'           => $run['partial'],
            'pending_accepted'  => $pendingRows > 0,
            'pending_rows'      => $pendingRows,
            'destroyed'         => array_map(static fn (#[\SensitiveParameter] SubjectKeyRow $key): array => self::destroyedEntryOf($key), $destroyed),
            'kept'              => $kept,
            'entries_affected'  => $affected,
        ];
    }

    /**
     * What the erasure row lists of a key it destroys, before and after.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @return array{key_id: string, unit: string, generation: int, before: array{state: string, hmac: string, wrapped_digest: ?string, wrap_key_id: ?string}, after: array{state: string}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function destroyedEntryOf(#[\SensitiveParameter] SubjectKeyRow $key): array
    {
        return [
            'key_id'     => $key->id,
            'unit'       => $key->unit,
            'generation' => $key->generation,
            'before'     => ['state' => $key->state->value, 'hmac' => $key->hmac, 'wrapped_digest' => $key->wrappedDigest(), 'wrap_key_id' => $key->wrapKeyId],
            'after'      => ['state' => KeyState::ERASED->value],
        ];
    }

    /**
     * Tombstone the keys in chunks, refusing a statement that does not change
     * exactly the keys it names.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  list<string>  $ids
     * @param  string  $erasureId
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private static function tombstone(Connection $connection, array $ids, string $erasureId): void
    {
        foreach (array_chunk($ids, self::STATEMENT_IDS) as $chunk) {
            $updated = $connection->table(KeyTables::subjectKeysTable())
                ->whereIn('id', $chunk)
                ->whereIn('state', [KeyState::LIVE->value, KeyState::SUPERSEDED->value])
                ->update(['state' => KeyState::ERASED->value, 'wrapped_key' => null, 'erasure_id' => $erasureId]);

            if ($updated !== count($chunk)) {
                throw new \UnexpectedValueException('A subject key changed while its owner was erased; the erasure is rolled back.');
            }
        }
    }

    /**
     * The refusal, with its reasons, for the run's owner.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal  $refusal
     * @param  list<string>  $reasons
     * @param  array{operation: string, authority: \SineMacula\Laravel\AuditLog\Lifecycle\Authority, partial: bool, pending: bool, started: string, fingerprint: string, fingerprint_key: string}  $run
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function refusal(ErasureRefusal $refusal, array $reasons, array $run): ErasureRefusedException
    {
        return ErasureRefusedException::of($refusal, $reasons, $run['fingerprint'], $run['fingerprint_key']);
    }
}
