<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Keeps a key creation apart from an erasure or reinstatement of the same owner
 * with an advisory lock, as a first key has no row; always taken after the
 * lifecycle lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OwnerLock
{
    /** @var int Longest wait for an owner's lock, in seconds. */
    public const int WAIT_SECONDS = 10;

    /** @var string What every lock's name starts with. */
    public const string NAME_PREFIX = 'audit_log_owner_';

    /** @var int The hex characters of the digest a lock's name keeps. */
    private const int NAME_DIGEST_CHARACTERS = 32;

    /** @var int The bytes of the digest a lock's key is read from. */
    private const int KEY_BYTES = 8;

    /** @var int Most `release_lock()` calls one release makes, one per level a retried transaction may have taken. */
    private const int MAX_RELEASES = 5;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Database\FailureClassifier  $classifier
     * @param  int  $waitSeconds
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Tells PostgreSQL's lock timeout from any other failure. */
        private FailureClassifier $classifier,

        /** How long a bounded wait lasts, in seconds, from 1 to `WAIT_SECONDS`. */
        private int $waitSeconds = self::WAIT_SECONDS,
    ) {
        if ($waitSeconds < 1 || $waitSeconds > self::WAIT_SECONDS) {
            throw new \InvalidArgumentException(sprintf('An owner\'s lock waits from 1 to %d seconds.', self::WAIT_SECONDS));
        }
    }

    /**
     * The key of an owner's lock, a signed 64-bit integer.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return int
     *
     * @throws \UnexpectedValueException
     */
    public static function key(#[\SensitiveParameter] Reference $owner): int
    {
        $unpacked = unpack('J', substr(self::digest($owner, true), 0, self::KEY_BYTES));

        if (!is_array($unpacked) || !is_int($unpacked[1] ?? null)) {
            throw new \UnexpectedValueException('An owner\'s lock key could not be read.');
        }

        return $unpacked[1];
    }

    /**
     * The name of an owner's lock, within MySQL's 64 characters.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public static function name(#[\SensitiveParameter] Reference $owner): string
    {
        return self::NAME_PREFIX . substr(self::digest($owner, false), 0, self::NAME_DIGEST_CHARACTERS);
    }

    /**
     * Take the owner's lock: in the transaction on PostgreSQL, bounded only
     * when asked; on the session on MySQL, always bounded; not at all on
     * SQLite, whose one writer serialises.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  bool  $bounded
     * @return void
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\AuditLog\Keys\OwnerLockTimeoutException
     */
    public function acquire(Connection $connection, #[\SensitiveParameter] Reference $owner, bool $bounded = false): void
    {
        match ($connection->getDriverName()) {
            'pgsql'  => $this->acquireOnPostgres($connection, $owner, $bounded),
            'mysql'  => $this->acquireOnMysql($connection, $owner),
            'sqlite' => null,
            default  => self::refuseTheEngine($connection),
        };
    }

    /**
     * Release the owner's lock on MySQL as often as the session holds it, so
     * every attempt of a retried transaction is released.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    public function release(Connection $connection, #[\SensitiveParameter] Reference $owner): void
    {
        if ($connection->getDriverName() !== 'mysql') {
            return;
        }

        $name = self::name($owner);

        for ($release = 0; $release < self::MAX_RELEASES; $release++) {
            if (self::answer($connection->selectOne('select release_lock(?) as answer', [$name], false)) !== 1) {
                return;
            }
        }
    }

    /**
     * Take the transaction's advisory lock; `set local lock_timeout` bounds
     * every later lock of the transaction too, so it is set only when asked.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  bool  $bounded
     * @return void
     *
     * @throws \LogicException
     */
    private function acquireOnPostgres(Connection $connection, #[\SensitiveParameter] Reference $owner, bool $bounded): void
    {
        if ($connection->transactionLevel() === 0) {
            throw new \LogicException('On PostgreSQL an owner\'s lock is held by a transaction, and is taken only inside one.');
        }

        try {
            if ($bounded) {
                $connection->statement(sprintf('set local lock_timeout = \'%ds\'', $this->waitSeconds));
            }

            $connection->select('select pg_advisory_xact_lock(?)', [self::key($owner)], false);
        } catch (QueryException $failure) { // @phpstan-ignore catch.neverThrown
            $this->refuseTheFailure($failure);
        }
    }

    /**
     * Refuse a failed PostgreSQL lock wait as a timeout, or rethrow it without
     * its bindings.
     *
     * @param  \Illuminate\Database\QueryException  $failure
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Keys\OwnerLockTimeoutException
     */
    private function refuseTheFailure(QueryException $failure): never
    {
        if ($this->classifier->isLockTimeout($failure)) {
            throw OwnerLockTimeoutException::after($this->waitSeconds);
        }

        FailureClassifier::rethrowMasked($failure);
    }

    /**
     * Take the session's named lock, refusing any answer but granted.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Keys\OwnerLockTimeoutException
     */
    private function acquireOnMysql(Connection $connection, #[\SensitiveParameter] Reference $owner): void
    {
        if (self::answer($connection->selectOne('select get_lock(?, ?) as answer', [self::name($owner), $this->waitSeconds], false)) !== 1) {
            throw OwnerLockTimeoutException::after($this->waitSeconds);
        }
    }

    /**
     * Refuse an engine the owner's lock is not taken on.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return never
     *
     * @throws \LogicException
     */
    private static function refuseTheEngine(Connection $connection): never
    {
        throw new \LogicException(sprintf('An owner\'s lock is taken on MySQL, PostgreSQL or SQLite, and the connection is %s.', $connection->getDriverName()));
    }

    /**
     * The SHA-256 of the owner's canonical encoding, raw or in lower-case hex.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  bool  $raw
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function digest(#[\SensitiveParameter] Reference $owner, bool $raw): string
    {
        return hash('sha256', CanonicalEncoder::encode([$owner->type, $owner->id]), $raw);
    }

    /**
     * The integer a lock function answered, or `null` for anything else, such
     * as SQL's `NULL`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $row
     * @return ?int
     */
    private static function answer(#[\SensitiveParameter] mixed $row): ?int
    {
        $answer = is_object($row) ? (get_object_vars($row)['answer'] ?? null) : null;

        return match (true) {
            is_int($answer)                            => $answer,
            is_string($answer) && ctype_digit($answer) => (int) $answer,
            default                                    => null,
        };
    }
}
