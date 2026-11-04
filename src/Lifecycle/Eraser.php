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
 * Erases an owner: destroys every key the owner holds, so every field ever
 * encrypted for the owner, wherever it is stored, sent or replayed, reads
 * `erased`, and marks the owner erased, so no key is created for the owner
 * again until a reinstatement. All or nothing, unless asked to go ahead in
 * part.
 *
 * An erasure is refused `unsupported_encrypter`, before anything else, when the
 * bound field encrypter is not one that keeps the package's key store, since
 * the keys it made are where the package cannot see them. The installation is
 * then confirmed, once, and the erasure runs in one `MaintenanceTransaction`:
 * the lifecycle lock, the whole journal verified, or in a run of erasures the
 * replay the last one committed advanced to the journal's head, so each journal
 * row of the run is read once (`ErasureRun`), then the owner's lock, so no key
 * of the owner is created meanwhile, and every read that decides a destruction
 * after both. The owner's latest marker is read, then the owner's keys: more
 * than 10,000 live or superseded keys are refused `too_many_keys`, and every
 * key of the owner, in any state, must verify under the signing key it names,
 * or the erasure is refused `key_unverifiable`, naming the keys, since nothing
 * is destroyed that cannot be authenticated. An owner whose latest marker
 * records an erasure and who holds no live or superseded key is already erased:
 * nothing is written, and the result says so.
 *
 * The outbox rows created before the erasure started, failed ones included, are
 * counted after the lock: any refuses the erasure `pending_delivery`, unless it
 * was asked to accept them, since every field of the owner they hold is erased
 * with the key. Each live or superseded key's entries are then read through its
 * key uses and decide its blocks, from the holds of the verified chain, the
 * policy's preservation at the erasure's UTC midnight and the entries that fail
 * authentication; any block refuses the erasure `blocked`, naming every reason,
 * unless it was asked to go ahead in part, when the blocked keys are kept and
 * the rest destroyed. Every refusal throws an `ErasureRefusedException` and
 * writes nothing.
 *
 * Otherwise an `erasure` row is appended onto the verified head, naming the
 * authority, the owner's fingerprint under the ring's signing key, the new
 * generation floor (the largest of the owner's previous floor and every
 * generation of the owner's keys), whether it went ahead in part, the outbox
 * rows it accepted, each destroyed key with its state, HMAC, wrapped key digest
 * and wrapping key before and its state after, each kept key with its reasons,
 * and the entries the destroyed keys encrypted. The destroyed keys are then
 * tombstoned, erased with no wrapped key and the row's id as their erasure, by
 * updates that name live or superseded keys alone and must change exactly the
 * keys they name, or the whole erasure, row and marker included, rolls back
 * with an `UnexpectedValueException`; and an `erased` marker is inserted under
 * the row's id, at its sequence and time, at the new floor. An erasure that
 * destroys nothing, of an owner with no key or one asked to go ahead in part
 * whose every key is blocked, still marks and journals the owner. On MySQL the
 * owner's lock is released once the transaction has ended, however it ended,
 * every attempt's; elsewhere the transaction's end released it.
 *
 * An erasure revokes the owner's fields in the live store when it commits;
 * whoever holds the database credentials can still destroy or restore keys, and
 * the signatures and the journal make that detectable, not impossible.
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

    /** @var string Why an erasure rolls back when a tombstone update does not change exactly the keys it names. */
    private const string MISMATCH = 'A subject key changed while its owner was erased; the erasure is rolled back.';

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

        /** The frame the erasure runs in, behind the lifecycle lock. */
        private MaintenanceTransaction $transaction,

        /** The journal the erasure is appended to. */
        private Journal $journal,

        /** The signer the journal is verified with. */
        private JournalSigner $signer,

        /** The settings the journal's log id is read from. */
        private SealSettings $settings,

        /** Reads the owner's keys on the maintenance connection. */
        private KeyStore $keys,

        /** Authenticates every key of the owner. */
        private SubjectKeySigner $keySigner,

        /** The owner markers, read and inserted on the maintenance connection. */
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

        /** The time the erasure starts at, which its outbox count and preservation are decided by. */
        private Clock $clock,
    ) {}

    /**
     * Erase the owner in one lifecycle transaction, all or nothing unless
     * `$partial` lets the unblocked keys go, refusing outbox rows older than
     * the erasure unless `$pending` accepts them, and return what it did. In a
     * run of erasures, the run confirms the installation once and carries the
     * verified journal from each committed erasure to the next.
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
     * Refuse the erasure when the bound field encrypter is not one that keeps
     * the package's key store, naming the encrypter's class.
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
     * Erase the owner inside the lifecycle transaction the connection holds,
     * after the owner's lock: the marker and the keys read and authenticated,
     * the outbox counted, the blocks decided, then the row appended, the keys
     * tombstoned and the marker inserted; return what it did and the replay it
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
     * How many outbox rows were created before the erasure started, read after
     * the lock; any refuses the erasure unless it accepts them.
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
     * Every reason the blocks give, each once; any block refuses the erasure
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
     * The erasure row the replay accepted last, once the journal appended it.
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
     * Every key of the owner, in every state, by id, read after the locks and
     * each authenticated: more than `MAX_KEYS` live or superseded keys are
     * refused before any is read, and a key that does not verify under the
     * signing key it names, or cannot be read, refuses the erasure.
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
            // A key too malformed to read cannot be authenticated, and names no
            // id that can be trusted
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
     * The erasure row's payload: the owner's fingerprint, the floor, whether it
     * went ahead in part, the outbox rows it accepted, each destroyed key's
     * before and after and each kept key's reasons, sorted by key id, and the
     * entries affected.
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
     * What the erasure row lists of a key it destroys: its id, its unit's
     * digest and its generation, its state, HMAC, wrapped key's digest and
     * wrapping key before, and its state after.
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
     * Tombstone the keys with the erasure's id, at most 500 to a statement,
     * each statement naming live or superseded keys alone and refused unless it
     * changes exactly the keys it names.
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
                throw new \UnexpectedValueException(self::MISMATCH);
            }
        }
    }

    /**
     * The refusal, with its reasons, about the owner the run fingerprints.
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
