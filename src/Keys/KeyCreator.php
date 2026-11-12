<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Str;
use Random\RandomException;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Creates a unit's key on the key session, so it commits on its own and never
 * rolls back with a host transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeyCreator
{
    /** @var int Length of a data key, in bytes. */
    public const int DATA_KEY_BYTES = 32;

    /** @var string The isolation PostgreSQL creates a key at, as `transaction_isolation` reads it. */
    private const string READ_COMMITTED = 'read committed';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyStore  $store
     * @param  \SineMacula\Laravel\AuditLog\Keys\OwnerMarkers  $markers
     * @param  \SineMacula\Laravel\AuditLog\Keys\OwnerLock  $lock
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Contracts\KeyWrapper  $wrapper
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     */
    public function __construct(

        /** The manager the key session is opened on. */
        private DatabaseManager $database,

        /** Reads the unit's live key and largest generation. */
        private KeyStore $store,

        /** Reads the owner's latest marker. */
        private OwnerMarkers $markers,

        /** The owner's lock. */
        private OwnerLock $lock,

        /** Signs the new key's row. */
        private SubjectKeySigner $signer,

        /** Wraps the new data key, and unwraps a key found instead. */
        private KeyWrapper $wrapper,

        /** Stamps the new key's creation and id. */
        private Clock $clock,
    ) {}

    /**
     * The unit's live key and its data key, or `null` when the owner is erased
     * or a racing winner is no longer live.
     *
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyUnit  $unit
     * @return ?array{0: \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow, 1: string}
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\AuditLog\Keys\OwnerLockTimeoutException
     * @throws \Throwable
     */
    public function create(#[\SensitiveParameter] KeyUnit $unit): ?array
    {
        $session = KeySession::open($this->database);

        try {
            return $this->createOn($session->connection(), $unit);
        } finally {
            try {
                $this->lock->release($session->connection(), $unit->owner);
            } finally {
                $session->close();
            }
        }
    }

    /**
     * Create the key, taking MySQL's lock outside the transaction and
     * re-reading the winner when the unique index refuses the insert.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyUnit  $unit
     * @return ?array{0: \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow, 1: string}
     *
     * @throws \Throwable
     */
    private function createOn(Connection $connection, #[\SensitiveParameter] KeyUnit $unit): ?array
    {
        if (self::locksTheSession($connection)) {
            $this->lock->acquire($connection, $unit->owner, true);
        }

        try {
            $made = $connection->transaction(fn (Connection $connection): ?array => $this->createWithin($connection, $unit), 1);
        } catch (UniqueConstraintViolationException) {
            // A creation that raced past every lock committed first
            $winner = $this->store->liveOf($connection, $unit);

            return $winner === null ? null : [$winner, $this->unwrapped($winner)];
        }

        if ($made === null) {
            return null;
        }

        [$row, $dataKey] = $made;

        return [$row, $dataKey ?? $this->unwrapped($row)];
    }

    /**
     * Insert a new key unless the owner is erased or the unit already has a
     * live key, which is returned without its data key so it is unwrapped after
     * the transaction.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyUnit  $unit
     * @return ?array{0: \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow, 1: ?string}
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Illuminate\Database\QueryException
     * @throws \SineMacula\Laravel\AuditLog\Keys\OwnerLockTimeoutException
     * @throws \Throwable
     */
    private function createWithin(Connection $connection, #[\SensitiveParameter] KeyUnit $unit): ?array
    {
        self::readCommitted($connection);

        if (!self::locksTheSession($connection)) {
            $this->lock->acquire($connection, $unit->owner, true);
        }

        $marker = $this->markers->latest($connection, $unit->owner);

        if ($marker?->isErasure() === true) {
            return null;
        }

        $live = $this->store->liveOf($connection, $unit);

        if ($live !== null) {
            return [$live, null];
        }

        $generation = max($marker->generationFloor ?? 0, $this->store->largestGeneration($connection, $unit->digest())) + 1;

        return $this->insert($connection, $unit, $generation);
    }

    /**
     * Make, sign and insert the generation's key, storing nothing when the
     * wrapper cannot unwrap what it wrapped.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyUnit  $unit
     * @param  int  $generation
     * @return array{0: \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow, 1: string}
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     */
    private function insert(Connection $connection, #[\SensitiveParameter] KeyUnit $unit, int $generation): array
    {
        $now       = $this->clock->now();
        $id        = Str::uuid7($now)->toString();
        $dataKey   = self::dataKey();
        $wrapKeyId = $this->wrapper->currentKeyId();
        $context   = SubjectKeyRow::wrapContextOf($id, $unit->digest(), $generation, $wrapKeyId);
        $wrapped   = $this->wrapper->wrap($dataKey, $wrapKeyId, $context);

        $this->confirmOpens($dataKey, $wrapped, $wrapKeyId, $context);

        $row = $this->signer->sign(SubjectKeyRow::draft($id, $unit->owner, $unit->tenant, $unit->category, $generation, $wrapped, $wrapKeyId, StoredTime::format($now)));

        $connection->table(KeyTables::subjectKeysTable())->insert($row->toRow());

        return [$row, $dataKey];
    }

    /**
     * The data key the row wraps.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $row
     * @return string
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    private function unwrapped(#[\SensitiveParameter] SubjectKeyRow $row): string
    {
        // A live row always holds its wrapped key and wrapping key id
        return $this->wrapper->unwrap((string) $row->wrappedKey, (string) $row->wrapKeyId, $row->wrapContext());
    }

    /**
     * Confirm the wrapped key unwraps to the data key it was made from.
     *
     * @param  string  $dataKey
     * @param  string  $wrapped
     * @param  string  $wrapKeyId
     * @param  string  $context
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private function confirmOpens(#[\SensitiveParameter] string $dataKey, #[\SensitiveParameter] string $wrapped, string $wrapKeyId, string $context): void
    {
        if (hash_equals($dataKey, $this->wrapper->unwrap($wrapped, $wrapKeyId, $context))) {
            return;
        }

        throw new \UnexpectedValueException('A new key does not unwrap to its data key under its wrapping key, so it is not stored.');
    }

    /**
     * On PostgreSQL, run the creation at `read committed` so no snapshot taken
     * before the lock hides an erasure; a transaction begun elsewhere at
     * another level is refused.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private static function readCommitted(Connection $connection): void
    {
        if ($connection->getDriverName() !== 'pgsql') {
            return;
        }

        if ($connection->transactionLevel() === 1) {
            $connection->statement('SET TRANSACTION ISOLATION LEVEL READ COMMITTED');

            return;
        }

        $row   = $connection->selectOne('select current_setting(\'transaction_isolation\') as level', [], false);
        $level = is_object($row) && isset($row->level) && is_string($row->level) ? $row->level : '';

        if ($level !== self::READ_COMMITTED) {
            throw new \UnexpectedValueException('A key is created at `read committed` alone, and the transaction it would be created in is not.');
        }
    }

    /**
     * Whether the owner's lock is held on the session around the transaction,
     * as on MySQL.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    private static function locksTheSession(Connection $connection): bool
    {
        return $connection->getDriverName() === 'mysql';
    }

    /**
     * A fresh data key from the system's random source.
     *
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function dataKey(): string
    {
        try {
            return random_bytes(self::DATA_KEY_BYTES);
        } catch (RandomException) {
            throw new \UnexpectedValueException('A data key could not be drawn.');
        }
    }
}
