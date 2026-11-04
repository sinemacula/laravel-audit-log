<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Sleep;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * The frame of every write of the lifecycle journal and the holds projection:
 * one outermost transaction on the maintenance connection whose first statement
 * takes the lifecycle lock.
 *
 * An operation (a hold, a release, a prune run, an import, a rebuild) first
 * calls `confirm()`, once, never per transaction and never in a dry run: the
 * installation id, which the migrations seed, is ensured through the storage
 * connection, written there only if it was lost, and must read the same through
 * the maintenance one, so the operation's rows land in the database that holds
 * the entries and the seals. Each of its transactions then goes through
 * `run()`, which refuses to start while the maintenance or the storage
 * connection is already in a transaction, so a lifecycle transaction is never a
 * savepoint of the host's and commits on its own.
 *
 * Each attempt sets `read committed` for the next transaction on MySQL, then
 * begins the framework's transaction, whose first statement updates the lock's
 * one row with a token naming the operation and a fresh random suffix, so the
 * update always changes the row and its affected count is 1 on every engine; a
 * missing row is refused. On PostgreSQL the transaction's isolation is then
 * read and must be `read committed`, its default. On MySQL and PostgreSQL the
 * update takes the row lock; on SQLite it is a real write, so it takes the
 * database's write lock on PHP 8.3 and 8.4 alike, before the transaction has
 * read anything. Every decision read of the work follows the lock, inside the
 * same transaction, so it sees every operation committed before the lock was
 * granted. The lock gives exclusion, not fairness: an operation waiting for it
 * is not promised a turn ahead of one that asks later.
 *
 * An attempt lost to a concurrent operation (a deadlock, a serialisation
 * failure, a lock wait timeout or a locked database) is rolled back whole and
 * made again after a jittered wait, its work run afresh, up to three times; the
 * fourth loss is a `LifecycleContentionException`. A lost connection is never
 * retried, since its commit may have happened, and anything else propagates
 * unchanged. The work's result is returned only once its transaction has
 * committed, so a caller keeps nothing a rolled-back attempt produced.
 *
 * The lock serialises the package's own lifecycle operations and nothing else:
 * whoever holds the maintenance credentials can still change the tables, and
 * the journal and the seals make that detectable, not impossible.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MaintenanceTransaction
{
    /** @var int The attempts an operation makes in all: the first and up to three retries. */
    public const int MAX_ATTEMPTS = 4;

    /** @var int The bound of the wait after the first lost attempt, in milliseconds; each later bound doubles it. */
    public const int JITTER_BASE_MS = 20;

    /** @var int The greatest bound of any wait, in milliseconds. */
    public const int JITTER_MAX_MS = 1000;

    /** @var int Longest operation id, in bytes, so the token fits the lock's 64 characters after its colon and 16 hex characters. */
    public const int MAX_OPERATION_ID_BYTES = 47;

    /** @var int The id of the lock's one row. */
    private const int LOCK_ROW = 1;

    /** @var int The random bytes of a token's suffix, drawn per attempt. */
    private const int TOKEN_BYTES = 8;

    /** @var string How the lock's time is written: UTC to the microsecond, as every time the package stores. */
    private const string TIME_FORMAT = 'Y-m-d H:i:s.u';

    /** @var string The isolation level every lifecycle transaction runs at, as PostgreSQL names it. */
    private const string READ_COMMITTED = 'read committed';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Database\FailureClassifier  $classifier
     * @param  \SineMacula\Laravel\AuditLog\Database\InstallationIdentity  $identity
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     */
    public function __construct(

        /** The connections the maintenance and storage connections are resolved from on every call. */
        private DatabaseManager $database,

        /** Tells a failure a concurrent operation causes from a lost connection and anything else. */
        private FailureClassifier $classifier,

        /** The installation's identity, confirmed once per operation. */
        private InstallationIdentity $identity,

        /** The time the lock and the installation id are written at. */
        private Clock $clock,
    ) {}

    /**
     * Ensure the installation id through the storage connection and confirm the
     * maintenance connection reads the same one; an operation calls this once,
     * before its first transaction, and never in a dry run.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     */
    public function confirm(): void
    {
        $this->identity->confirm($this->clock->now());
    }

    /**
     * Run the work in one outermost transaction on the maintenance connection,
     * behind the lifecycle lock, and return its result once the transaction has
     * committed. An attempt lost to a concurrent operation is rolled back and
     * made again after a jittered wait, the work run afresh, up to three times;
     * a refusal (an operation id that is empty or longer than 47 bytes, a
     * transaction already open, a missing lock row, another isolation level)
     * and any other failure propagate.
     *
     * @template TResult
     *
     * @param  string  $operationId
     * @param  \Closure(\Illuminate\Database\Connection): TResult  $work
     * @return TResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \Throwable
     */
    public function run(string $operationId, #[\SensitiveParameter] \Closure $work): mixed
    {
        self::checkOperationId($operationId);

        $connection = $this->database->connection(StorageConnection::forMaintenance());

        $this->refuseInsideATransaction($connection);

        for ($attempt = 1;; $attempt++) {
            try {
                return $this->attempt($connection, $operationId, $work);
            } catch (\Throwable $exception) {
                if (!$this->isLostToAConcurrentOperation($connection, $exception)) {
                    throw $exception;
                }

                if ($attempt >= self::MAX_ATTEMPTS) {
                    throw LifecycleContentionException::after(self::MAX_ATTEMPTS);
                }

                self::waitAfter($attempt);
            }
        }
    }

    /**
     * Make one attempt: on MySQL set `read committed` for the next transaction,
     * then, in the framework's transaction, take the lock, check the isolation
     * on PostgreSQL, and run the work.
     *
     * @template TResult
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $operationId
     * @param  \Closure(\Illuminate\Database\Connection): TResult  $work
     * @return TResult
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    private function attempt(Connection $connection, string $operationId, #[\SensitiveParameter] \Closure $work): mixed
    {
        $token = $operationId . ':' . bin2hex(random_bytes(self::TOKEN_BYTES));
        $at    = $this->clock->now()->utc()->format(self::TIME_FORMAT);

        if (in_array($connection->getDriverName(), ['mysql', 'mariadb'], true)) {
            $connection->statement('SET TRANSACTION ISOLATION LEVEL READ COMMITTED');
        }

        return $connection->transaction(static function (Connection $connection) use ($token, $at, $work): mixed {
            self::lock($connection, $token, $at);
            self::checkIsolation($connection);

            return $work($connection);
        }, 1);
    }

    /**
     * Whether the failed attempt was lost to a concurrent operation, so a fresh
     * one may not meet the failure: a deadlock, a serialisation failure, a lock
     * wait timeout or a locked database. A lost connection never is, since its
     * commit may have happened. Short of a lost connection, a transaction the
     * driver still holds after a failed commit is rolled back first, so
     * whatever follows begins afresh.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \Throwable  $exception
     * @return bool
     */
    private function isLostToAConcurrentOperation(Connection $connection, #[\SensitiveParameter] \Throwable $exception): bool
    {
        if ($this->classifier->isLostConnection($exception)) {
            return false;
        }

        self::abandon($connection);

        return $this->classifier->isConcurrencyError($exception) || $this->classifier->isLockTimeout($exception);
    }

    /**
     * Refuse to start while the maintenance or the storage connection is in a
     * transaction: the operation would become a savepoint of the host's and
     * commit only with it.
     *
     * @param  \Illuminate\Database\Connection  $maintenance
     * @return void
     *
     * @throws \LogicException
     */
    private function refuseInsideATransaction(Connection $maintenance): void
    {
        if ($maintenance->transactionLevel() === 0 && $this->database->connection(StorageConnection::name())->transactionLevel() === 0) {
            return;
        }

        throw new \LogicException('A lifecycle operation runs in a transaction of its own on the maintenance connection, and refuses to run inside one.');
    }

    /**
     * Refuse an operation id that is empty, or too long for its token to fit
     * the lock's column.
     *
     * @param  string  $operationId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkOperationId(string $operationId): void
    {
        if ($operationId !== '' && strlen($operationId) <= self::MAX_OPERATION_ID_BYTES) {
            return;
        }

        throw new \InvalidArgumentException(sprintf('A lifecycle operation\'s id must be from 1 to %d bytes.', self::MAX_OPERATION_ID_BYTES));
    }

    /**
     * Take the lock: update its one row with the attempt's token and time, as
     * the transaction's first statement, and refuse when no row was updated.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $token
     * @param  string  $at
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleLockException
     */
    private static function lock(Connection $connection, #[\SensitiveParameter] string $token, string $at): void
    {
        $updated = $connection->table(LifecycleTables::lockTable())
            ->where('id', self::LOCK_ROW)
            ->update(['token' => $token, 'locked_at' => $at]);

        if ($updated !== 1) {
            throw LifecycleLockException::missing();
        }
    }

    /**
     * On PostgreSQL, refuse a transaction that does not run at `read
     * committed`; other engines are not asked.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleLockException
     */
    private static function checkIsolation(Connection $connection): void
    {
        if ($connection->getDriverName() !== 'pgsql') {
            return;
        }

        $row   = $connection->selectOne('select current_setting(\'transaction_isolation\') as level', [], false);
        $level = is_object($row) && isset($row->level) && is_string($row->level) ? $row->level : '';

        if ($level !== self::READ_COMMITTED) {
            throw LifecycleLockException::isolation($level);
        }
    }

    /**
     * Wait before the next attempt a random time no longer than the bound of
     * the attempt that was lost: 20 milliseconds after the first, doubling
     * after each, up to a second.
     *
     * @param  int  $attempt
     * @return void
     *
     * @throws \Random\RandomException
     */
    private static function waitAfter(int $attempt): void
    {
        $bound = min(self::JITTER_MAX_MS, self::JITTER_BASE_MS * 2 ** ($attempt - 1));

        Sleep::for(random_int(0, $bound))->milliseconds();
    }

    /**
     * Roll back a transaction the driver still holds once the framework holds
     * none, as a commit that failed leaves it, without connecting when there is
     * no connection yet.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     */
    private static function abandon(Connection $connection): void
    {
        $pdo = $connection->getRawPdo();

        if ($connection->transactionLevel() > 0 || !$pdo instanceof \PDO || !$pdo->inTransaction()) {
            return;
        }

        $pdo->rollBack();
    }
}
