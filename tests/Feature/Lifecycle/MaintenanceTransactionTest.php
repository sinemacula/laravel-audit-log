<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterval;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Sleep;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Database\InstallationMismatchException;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleLockException;
use SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction;
use Tests\TestCase;

/**
 * Feature tests for the frame of every lifecycle transaction, on whichever
 * engine the suite runs against: the lock row's update is the first statement
 * of the framework's transaction, on the maintenance connection, with a token
 * naming the operation that changes on every attempt; an operation is refused
 * inside a transaction on either connection, and when the lock row is missing;
 * the installation is confirmed once, before any lock, writing nothing but its
 * id; a failure a concurrent operation causes is retried whole, the work run
 * afresh, after a jittered wait, up to three times, and only a committed result
 * is returned; a lost connection and any other failure propagate unchanged; and
 * MySQL's isolation is set before each transaction while PostgreSQL's is
 * asserted.
 *
 * A maintenance connection that reaches the same database is a second
 * connection to the worker's database, sharing the in-memory database's own
 * connection on SQLite, where each connection would otherwise open a database
 * of its own. One that reaches another installation has a table prefix of its
 * own, so it reads another state table, as a second database would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MaintenanceTransaction::class)]
final class MaintenanceTransactionTest extends TestCase
{
    /** @var string A second connection to the worker's database. */
    private const string MAINTENANCE = 'audit_maintenance';

    /** @var string A connection that reaches another installation's state table. */
    private const string OTHER = 'audit_other';

    /** @var string The operation every test runs, unless it names another. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string When every operation runs. */
    private const string NOW = '2026-11-01 12:00:00.123456';

    /** @var string How MySQL reports a deadlock. */
    private const string DEADLOCK = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction';

    /** @var string How MySQL reports a lock wait timeout. */
    private const string LOCK_TIMEOUT = 'SQLSTATE[HY000]: General error: 1205 Lock wait timeout exceeded; try restarting transaction';

    /** @var string How PostgreSQL reports a statement cancelled by its lock timeout. */
    private const string PG_LOCK_TIMEOUT = 'SQLSTATE[55P03]: Lock not available: 7 ERROR:  canceling statement due to lock timeout';

    /** @var string How SQLite reports a busy snapshot or a locked database. */
    private const string BUSY = 'SQLSTATE[HY000]: General error: 5 database is locked';

    /** @var string How MySQL reports a lost connection. */
    private const string LOST = 'SQLSTATE[HY000]: General error: 2006 MySQL server has gone away';

    /** @var string What a lock token is for the operation every test runs: its id, a colon and 16 random hex characters. */
    private const string TOKEN = '/\A01932b4e-9000-7000-8000-0000000000a1:[0-9a-f]{16}\z/';

    /**
     * Freeze the clock and fake sleeping, so a retry waits no time.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        Sleep::fake();
    }

    /**
     * Roll back any transaction a test left open, put the clock and sleeping
     * back, drop the other installation's state table and forget both
     * connections.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $config = app(ConfigRepository::class);

        foreach ([self::MAINTENANCE, self::CONNECTION] as $name) {
            if (!$config->has('database.connections.' . $name)) {
                continue;
            }

            $connection = DB::connection($name);

            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }

        if ($config->has('database.connections.' . self::OTHER)) {
            DB::connection(self::OTHER)->getSchemaBuilder()->dropIfExists(IntegrityTables::stateTable());
        }

        DB::purge(self::MAINTENANCE);
        DB::purge(self::OTHER);

        Sleep::fake(false);
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * The lock row's update is the first statement inside the framework's
     * transaction, the work's reads follow it, and the commit ends it: on MySQL
     * the isolation is set just before the transaction begins, and on
     * PostgreSQL it is read straight after the lock.
     *
     * @return void
     */
    public function testTheLockIsTheFirstStatement(): void
    {
        $log = $this->statements();

        $result = $this->maintenance()->run(self::OPERATION, static fn (Connection $connection): int => $connection->table(LifecycleTables::journalTable())->count());

        $expected = match ($this->driver()) {
            'mysql' => ['set isolation', 'begin', 'lock', 'select journal', 'commit'],
            'pgsql' => ['begin', 'lock', 'isolation', 'select journal', 'commit'],
            default => ['begin', 'lock', 'select journal', 'commit'],
        };

        self::assertSame(0, $result);
        self::assertSame($expected, $log->getArrayCopy());
    }

    /**
     * The lock row keeps the token of the operation that last took it, its id,
     * a colon and 16 random hex characters, and the clock's instant to the
     * microsecond.
     *
     * @return void
     */
    public function testTheLockRowKeepsTheTokenAndTheTime(): void
    {
        $this->maintenance()->run(self::OPERATION, static fn (): null => null);

        $row = (array) DB::connection(self::CONNECTION)->table(LifecycleTables::lockTable())->where('id', 1)->first();

        self::assertMatchesRegularExpression(self::TOKEN, (string) $row['token']);
        self::assertSame(53, strlen((string) $row['token']));
        self::assertSame(self::NOW, (string) $row['locked_at']);
    }

    /**
     * Rows of `[maintenance connection]`: the storage connection itself, and a
     * second connection to its database.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideMaintenanceConnections(): iterable
    {
        yield from [
            'the storage connection'  => [null],
            'a connection of its own' => [self::MAINTENANCE],
        ];
    }

    /**
     * An operation asked for while the maintenance connection is in a
     * transaction is refused before it takes the lock or runs any work: it
     * would be a savepoint of that transaction and commit only with it.
     *
     * @param  ?string  $maintenance
     * @return void
     */
    #[DataProvider('provideMaintenanceConnections')]
    public function testItRefusesInsideATransactionOnTheMaintenanceConnection(?string $maintenance): void
    {
        if ($maintenance !== null) {
            $this->sameDatabase();
        }

        DB::connection($maintenance ?? self::CONNECTION)->beginTransaction();

        $this->assertRefusedInsideATransaction();
    }

    /**
     * An operation asked for while the storage connection is in a transaction
     * is refused too, though the maintenance connection is another: the host's
     * transaction may hold what the operation would decide on.
     *
     * @return void
     */
    public function testItRefusesInsideATransactionOnTheStorageConnection(): void
    {
        $this->sameDatabase();

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->assertRefusedInsideATransaction();
    }

    /**
     * A work that asks for a lifecycle operation of its own is refused, and its
     * own operation is rolled back and never retried.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANestedOperationIsRefused(): void
    {
        $transaction = $this->maintenance();

        try {
            $transaction->run(self::OPERATION, static function () use ($transaction): void {
                $transaction->run('01932b4e-9000-7000-8000-0000000000a2', static fn (): null => null);
            });

            self::fail('Expected the nested operation to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('A lifecycle operation runs in a transaction of its own on the maintenance connection, and refuses to run inside one.', $exception->getMessage());
        }

        self::assertNull($this->lockToken());
        self::assertSame(0, DB::connection(self::CONNECTION)->transactionLevel());

        Sleep::assertNeverSlept();
    }

    /**
     * A maintenance connection that reaches another installation is refused by
     * `confirm()` before anything reads or writes the lock.
     *
     * @return void
     */
    public function testAMismatchedInstallationRefusesBeforeTheLock(): void
    {
        $this->otherDatabase();

        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', self::OTHER);

        $log = $this->statements();

        try {
            $this->maintenance()->confirm();

            self::fail('Expected the installation to be refused.');
        } catch (InstallationMismatchException $exception) {
            self::assertSame('The storage and maintenance connections reach different installations.', $exception->getMessage());
        }

        self::assertNotSame([], $log->getArrayCopy());
        self::assertSame([], array_values(array_filter($log->getArrayCopy(), static fn (string $statement): bool => str_contains($statement, 'lock'))));
        self::assertNull($this->lockToken());
    }

    /**
     * `confirm()` reads the installation id the migrations seed and writes
     * nothing; on an installation that lost it, it writes the id and nothing
     * else: one insert into the state table, beside its reads. Neither takes
     * the lock or begins a transaction.
     *
     * @return void
     */
    public function testConfirmWritesNothingButAMissingInstallationId(): void
    {
        $state = DB::connection(self::CONNECTION)->table(IntegrityTables::stateTable());
        $log   = $this->statements();

        $this->maintenance()->confirm();

        self::assertSame(['select state'], $log->getArrayCopy());

        (clone $state)->delete();
        $log->exchangeArray([]);

        $this->maintenance()->confirm();

        self::assertSame(['select state', 'insert state', 'select state'], $log->getArrayCopy());
        self::assertSame([InstallationIdentity::NAME], (clone $state)->pluck('name')->all());
        self::assertNull($this->lockToken());
    }

    /**
     * With a maintenance connection of its own to the same database,
     * `confirm()` reads the id the storage connection reads through it too, and
     * passes.
     *
     * @return void
     */
    public function testConfirmReadsTheIdThroughTheMaintenanceConnection(): void
    {
        $this->sameDatabase();

        $connections = [];

        DB::listen(static function (QueryExecuted $query) use (&$connections): void {
            $connections[] = $query->connectionName;
        });

        $this->maintenance()->confirm();

        self::assertSame([self::CONNECTION, self::MAINTENANCE], $connections);
    }

    /**
     * `run()` never confirms the installation: an operation confirms it once,
     * so its transactions, chunk after chunk, read nothing of the state table.
     *
     * @return void
     */
    public function testRunDoesNotConfirmPerTransaction(): void
    {
        $log = $this->statements();

        $this->maintenance()->run(self::OPERATION, static fn (): null => null);
        $this->maintenance()->run(self::OPERATION, static fn (): null => null);

        self::assertSame([], array_values(array_filter($log->getArrayCopy(), static fn (string $statement): bool => str_contains($statement, 'state'))));
        self::assertSame(0, self::markers(DB::connection(self::CONNECTION))->count());
    }

    /**
     * A missing lock row is refused inside the transaction, before any work
     * runs, which is rolled back and never retried.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMissingLockRowRefuses(): void
    {
        DB::connection(self::CONNECTION)->table(LifecycleTables::lockTable())->delete();

        $ran = false;

        try {
            $this->maintenance()->run(self::OPERATION, static function () use (&$ran): void {
                $ran = true;
            });

            self::fail('Expected the missing lock row to be refused.');
        } catch (LifecycleLockException $exception) {
            self::assertSame('The lifecycle lock row is missing; run the migrations, which seed it.', $exception->getMessage());
        }

        self::assertFalse($ran);
        self::assertSame(0, DB::connection(self::CONNECTION)->transactionLevel());

        Sleep::assertNeverSlept();
    }

    /**
     * With a maintenance connection of its own, the work runs on it, inside its
     * one transaction, and the lock is taken there, while the storage
     * connection holds no transaction.
     *
     * @return void
     */
    public function testTheWorkRunsOnTheMaintenanceConnection(): void
    {
        $this->sameDatabase();

        $locks = [];

        DB::listen(static function (QueryExecuted $query) use (&$locks): void {
            if (self::labelOf($query->sql) !== 'lock') {
                return;
            }

            $locks[] = $query->connectionName;
        });

        $seen = $this->maintenance()->run(self::OPERATION, self::levelsSeenBy(...));

        self::assertSame([self::MAINTENANCE, 1, 0], $seen);
        self::assertSame([self::MAINTENANCE], $locks);
        self::assertMatchesRegularExpression(self::TOKEN, (string) $this->lockToken());
    }

    /**
     * Rows of `[failure]`: each failure a concurrent operation causes, as its
     * driver or the framework raises it.
     *
     * @return iterable<string, array{0: \Closure(): \Throwable}>
     */
    public static function provideConcurrencyFailures(): iterable
    {
        yield from [
            'a deadlock'                => [static fn (): \Throwable => self::failure(self::DEADLOCK)],
            'a serialisation failure'   => [static fn (): \Throwable => self::serialisationFailure()],
            'a lock wait timeout'       => [static fn (): \Throwable => self::failure(self::LOCK_TIMEOUT)],
            'a PostgreSQL lock timeout' => [static fn (): \Throwable => self::failure(self::PG_LOCK_TIMEOUT, '55P03')],
            'a locked SQLite database'  => [static fn (): \Throwable => self::failure(self::BUSY)],
            'the framework\'s deadlock' => [static fn (): \Throwable => new DeadlockException('A nested transaction deadlocked.')],
        ];
    }

    /**
     * Each failure a concurrent operation causes rolls the attempt back whole
     * and makes it again, three times; the fourth is contention, naming the
     * four attempts and carrying none of the failures, and nothing any attempt
     * wrote is committed.
     *
     * @param  \Closure(): \Throwable  $failure
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideConcurrencyFailures')]
    public function testAConcurrencyFailureIsRetriedThreeTimesThenFails(\Closure $failure): void
    {
        $calls = 0;

        $exception = self::thrownBy(function () use (&$calls, $failure): void {
            $this->maintenance()->run(self::OPERATION, static function (Connection $connection) use (&$calls, $failure): void {
                $calls++;

                self::writeMarker($connection, "test.attempt.{$calls}");

                throw $failure();
            });
        });

        self::assertInstanceOf(LifecycleContentionException::class, $exception);
        self::assertSame('A lifecycle operation lost to concurrent operations 4 times and was abandoned; nothing it attempted was committed.', $exception->getMessage());
        self::assertNull($exception->getPrevious());

        self::assertSame(4, $calls);
        self::assertSame(4, MaintenanceTransaction::MAX_ATTEMPTS);
        self::assertSame(0, self::markers(DB::connection(self::CONNECTION))->count());
        self::assertNull($this->lockToken());

        Sleep::assertSleptTimes(3);
    }

    /**
     * The lock's own update timing out on a lock wait is retried like any other
     * loss, and an attempt that then takes the lock runs the work once and
     * commits.
     *
     * @return void
     */
    public function testALockWaitThatTimesOutIsRetried(): void
    {
        $this->raiseOnTheLock(self::failure(self::LOCK_TIMEOUT), 2);

        $calls  = 0;
        $result = $this->maintenance()->run(self::OPERATION, static function () use (&$calls): string {
            $calls++;

            return 'locked';
        });

        self::assertSame('locked', $result);
        self::assertSame(1, $calls);
        self::assertMatchesRegularExpression(self::TOKEN, (string) $this->lockToken());

        Sleep::assertSleptTimes(2);
    }

    /**
     * Each retry waits a random time no longer than the bound of the attempt
     * that was lost: 20 milliseconds after the first, 40 after the second and
     * 80 after the third.
     *
     * @return void
     */
    public function testEachRetryWaitsAJitteredTime(): void
    {
        $waits = $this->waitsDuring(1);

        self::assertCount(3, $waits);

        foreach ([20, 40, 80] as $retry => $bound) {
            self::assertGreaterThanOrEqual(0, $waits[$retry], "Retry {$retry} waited less than nothing.");
            self::assertLessThanOrEqual($bound, $waits[$retry], "Retry {$retry} waited past its bound.");
        }

        self::assertSame(20, MaintenanceTransaction::JITTER_BASE_MS);
        self::assertSame(1000, MaintenanceTransaction::JITTER_MAX_MS);
    }

    /**
     * The waits are random within their bound, not fixed at it: over many
     * operations that each lose three attempts, they differ, and some exceed
     * the first bound.
     *
     * @return void
     */
    public function testTheWaitsAreRandomWithinTheirBound(): void
    {
        $waits = $this->waitsDuring(30);

        self::assertCount(90, $waits);
        self::assertGreaterThan(1, count(array_unique($waits)));
        self::assertGreaterThan(MaintenanceTransaction::JITTER_BASE_MS, max($waits), 'The bound did not grow past the first.');
    }

    /**
     * A lost connection is never retried, since its commit may have happened:
     * the failure propagates unchanged, after one attempt and no wait, whether
     * the work or the lock met it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALostConnectionIsNeverRetried(): void
    {
        $lost  = self::failure(self::LOST);
        $calls = 0;

        $thrown = self::thrownBy(function () use (&$calls, $lost): void {
            $this->maintenance()->run(self::OPERATION, static function () use (&$calls, $lost): void {
                $calls++;

                throw $lost;
            });
        });

        self::assertSame($lost, $thrown);

        self::assertSame(1, $calls);

        $this->raiseOnTheLock($lost, 1);

        try {
            $this->maintenance()->run(self::OPERATION, static fn (): null => null);

            self::fail('Expected the lost connection to propagate.');
        } catch (QueryException $exception) {
            self::assertSame($lost, $exception);
        }

        Sleep::assertNeverSlept();
    }

    /**
     * Rows of `[failure]`: failures no concurrent operation causes, a data
     * failure whose driver message quotes a deadlock's phrase among them.
     *
     * @return iterable<string, array{0: \Closure(): \Throwable}>
     */
    public static function provideOtherFailures(): iterable
    {
        yield from [
            'a runtime failure'  => [static fn (): \Throwable => new \RuntimeException('The work failed.')],
            'a logic failure'    => [static fn (): \Throwable => new \LogicException('The work is wrong.')],
            'a unique violation' => [static fn (): \Throwable => self::uniqueViolation()],
            'a quoted deadlock'  => [static fn (): \Throwable => self::failure('SQLSTATE[22001]: String data, right truncated: Deadlock found when trying to get lock', '22001')],
            'a lock exception'   => [static fn (): \Throwable => LifecycleLockException::missing()],
        ];
    }

    /**
     * Any other failure propagates unchanged after one attempt and no wait, and
     * what the attempt wrote is rolled back.
     *
     * @param  \Closure(): \Throwable  $failure
     * @return void
     */
    #[DataProvider('provideOtherFailures')]
    public function testAnyOtherFailurePropagatesUnchanged(\Closure $failure): void
    {
        $thrown = $failure();
        $calls  = 0;

        $exception = self::thrownBy(function () use (&$calls, $thrown): void {
            $this->maintenance()->run(self::OPERATION, static function (Connection $connection) use (&$calls, $thrown): void {
                $calls++;

                self::writeMarker($connection, 'test.attempt');

                throw $thrown;
            });
        });

        self::assertSame($thrown, $exception);

        self::assertSame(1, $calls);
        self::assertSame(0, self::markers(DB::connection(self::CONNECTION))->count());
        self::assertNull($this->lockToken());

        Sleep::assertNeverSlept();
    }

    /**
     * The token names the operation and changes on every attempt: two
     * transactions of one operation under a frozen clock both take the lock,
     * which an update writing the values already there would not on MySQL, and
     * a retried attempt draws a token of its own.
     *
     * @return void
     */
    public function testTheTokenNamesTheOperationAndChangesOnEveryAttempt(): void
    {
        $tokens = [];

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query, array $bindings) use (&$tokens): void {
            if (self::labelOf($query) !== 'lock') {
                return;
            }

            $tokens[] = $bindings[0];
        });

        $transaction = $this->maintenance();

        self::assertSame('first', $transaction->run(self::OPERATION, static fn (): string => 'first'));
        self::assertSame('second', $transaction->run(self::OPERATION, static fn (): string => 'second'));

        $this->raiseOnTheLock(self::failure(self::DEADLOCK), 1);

        self::assertSame('third', $transaction->run(self::OPERATION, static fn (): string => 'third'));

        self::assertCount(4, $tokens);
        self::assertCount(4, array_unique($tokens));

        foreach ($tokens as $token) {
            self::assertIsString($token);
            self::assertMatchesRegularExpression(self::TOKEN, $token);
        }

        self::assertSame(end($tokens), $this->lockToken());
    }

    /**
     * An attempt whose commit is lost to a concurrent operation is rolled back
     * whole, though its work returned, and the next attempt runs the work
     * afresh: only the committed attempt's result is returned, and only its
     * writes remain, with no transaction left behind on the connection.
     *
     * @return void
     */
    public function testARetriedAttemptRunsTheWorkAfreshAndReturnsOnlyTheCommittedResult(): void
    {
        $this->raiseOnCommit(self::failure(self::BUSY));

        $calls  = new \ArrayObject;
        $result = $this->maintenance()->run(self::OPERATION, static function (Connection $connection) use ($calls): string {
            $calls->append(true);

            self::writeMarker($connection, "test.attempt.{$calls->count()}");

            return "attempt {$calls->count()}";
        });

        $connection = DB::connection(self::CONNECTION);

        self::assertSame('attempt 2', $result);
        self::assertCount(2, $calls);
        self::assertSame(['test.attempt.2'], self::markers($connection)->pluck('name')->all());
        self::assertSame(0, $connection->transactionLevel());
        self::assertFalse($connection->getPdo()->inTransaction());

        Sleep::assertSleptTimes(1);
    }

    /**
     * A commit that fails for any other reason returns no result, leaves none
     * of the attempt's writes and no transaction behind, and the next operation
     * on the connection runs as any other.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedCommitLeavesNoTransactionBehind(): void
    {
        $failure = new \RuntimeException('The commit failed.');

        $this->raiseOnCommit($failure);

        try {
            $this->maintenance()->run(self::OPERATION, static function (Connection $connection): string {
                self::writeMarker($connection, 'test.uncommitted');

                return 'uncommitted';
            });

            self::fail('Expected the failed commit to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        $connection = DB::connection(self::CONNECTION);

        self::assertFalse($connection->getPdo()->inTransaction());
        self::assertSame(0, self::markers($connection)->count());
        self::assertSame('next', $this->maintenance()->run(self::OPERATION, static fn (): string => 'next'));
    }

    /**
     * An operation id is refused when it is empty, or longer than 47 bytes, so
     * a token always fits the lock's 64 characters; one of 47 bytes takes the
     * lock.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOperationIdTooLongForTheTokenIsRefused(): void
    {
        foreach (['', str_repeat('a', 48)] as $operationId) {
            try {
                $this->maintenance()->run($operationId, static fn (): null => null);

                self::fail('Expected the operation id to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A lifecycle operation\'s id must be from 1 to 47 bytes.', $exception->getMessage());
            }
        }

        $this->maintenance()->run(str_repeat('a', 47), static fn (): null => null);

        self::assertSame(64, strlen((string) $this->lockToken()));
        self::assertSame(47, MaintenanceTransaction::MAX_OPERATION_ID_BYTES);
    }

    /**
     * On MySQL the isolation is set to `read committed` immediately before
     * every attempt's transaction begins, a retried one included.
     *
     * @return void
     */
    public function testOnMySqlTheIsolationIsSetBeforeTheTransaction(): void
    {
        if ($this->driver() !== 'mysql') {
            self::markTestSkipped('Only MySQL sets the next transaction\'s isolation.');
        }

        $this->raiseOnTheLock(self::failure(self::DEADLOCK), 1);

        $log = $this->statements();

        $this->maintenance()->run(self::OPERATION, static fn (): null => null);

        self::assertSame(['set isolation', 'begin', 'rollback', 'set isolation', 'begin', 'lock', 'commit'], $log->getArrayCopy());
    }

    /**
     * On PostgreSQL the isolation is read straight after the lock, and a
     * session whose transactions run at another level is refused, rolled back
     * and never retried, before any work runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnPostgresTheIsolationIsAsserted(): void
    {
        if ($this->driver() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL is asked for its isolation.');
        }

        $connection = DB::connection(self::CONNECTION);
        $ran        = false;

        $connection->statement('set session characteristics as transaction isolation level repeatable read');

        try {
            $this->maintenance()->run(self::OPERATION, static function () use (&$ran): void {
                $ran = true;
            });

            self::fail('Expected the isolation to be refused.');
        } catch (LifecycleLockException $exception) {
            self::assertSame('The maintenance connection\'s transactions are `repeatable read`; a lifecycle operation needs `read committed`.', $exception->getMessage());
        } finally {
            $connection->statement('set session characteristics as transaction isolation level read committed');
        }

        self::assertFalse($ran);
        self::assertNull($this->lockToken());

        Sleep::assertNeverSlept();

        $log = $this->statements();

        $this->maintenance()->run(self::OPERATION, static fn (): null => null);

        self::assertSame(['begin', 'lock', 'isolation', 'commit'], $log->getArrayCopy());
    }

    /**
     * Assert an operation is refused for the transaction already open, before
     * it takes the lock or runs its work.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function assertRefusedInsideATransaction(): void
    {
        $ran = false;
        $log = $this->statements();

        try {
            $this->maintenance()->run(self::OPERATION, static function () use (&$ran): void {
                $ran = true;
            });

            self::fail('Expected the operation to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('A lifecycle operation runs in a transaction of its own on the maintenance connection, and refuses to run inside one.', $exception->getMessage());
        }

        self::assertFalse($ran);
        self::assertSame([], $log->getArrayCopy());

        Sleep::assertNeverSlept();
    }

    /**
     * The waits slept while the number of operations each lose three attempts
     * to a locked database before they commit, in milliseconds.
     *
     * @param  int  $operations
     * @return list<int>
     */
    private function waitsDuring(int $operations): array
    {
        $waits = [];

        Sleep::whenFakingSleep(static function (CarbonInterval $duration) use (&$waits): void {
            $waits[] = (int) $duration->totalMilliseconds;
        });

        for ($operation = 0; $operation < $operations; $operation++) {
            $this->raiseOnTheLock(self::failure(self::BUSY), 3);
            $this->maintenance()->run(self::OPERATION, static fn (): null => null);
        }

        return $waits;
    }

    /**
     * Raise the failure in place of the lock's update, the number of times
     * given, on whichever connection runs it.
     *
     * @param  \Throwable  $failure
     * @param  int  $times
     * @return void
     */
    private function raiseOnTheLock(#[\SensitiveParameter] \Throwable $failure, int $times): void
    {
        $raise = static function (string $query) use ($failure, &$times): void {
            if ($times === 0 || self::labelOf($query) !== 'lock') {
                return;
            }

            $times--;

            throw $failure;
        };

        DB::connection(self::CONNECTION)->beforeExecuting($raise);
    }

    /**
     * Raise the failure as the first outermost commit is about to be made, as a
     * commit lost to a concurrent operation fails, leaving the driver's
     * transaction open.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    private function raiseOnCommit(#[\SensitiveParameter] \Throwable $failure): void
    {
        $raised = false;

        Event::listen(TransactionCommitting::class, static function () use ($failure, &$raised): void {
            if ($raised) {
                return;
            }

            $raised = true;

            throw $failure;
        });
    }

    /**
     * Record each statement and each transaction event from now on, in order,
     * as its label.
     *
     * @return \ArrayObject<int, string>
     */
    private function statements(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $log */
        $log = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($log): void {
            $log->append(self::labelOf($query->sql));
        });

        Event::listen(TransactionBeginning::class, static function () use ($log): void {
            $log->append('begin');
        });
        Event::listen(TransactionCommitted::class, static function () use ($log): void {
            $log->append('commit');
        });
        Event::listen(TransactionRolledBack::class, static function () use ($log): void {
            $log->append('rollback');
        });

        return $log;
    }

    /**
     * The token the lock row holds, or `null` when no operation has taken it.
     *
     * @return ?string
     */
    private function lockToken(): ?string
    {
        $token = DB::connection(self::CONNECTION)->table(LifecycleTables::lockTable())->where('id', 1)->value('token');

        return is_string($token) ? $token : null;
    }

    /**
     * The transaction frame the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction
     */
    private function maintenance(): MaintenanceTransaction
    {
        return app(MaintenanceTransaction::class);
    }

    /**
     * The driver of the worker's connection.
     *
     * @return string
     */
    private function driver(): string
    {
        return DB::connection(self::CONNECTION)->getDriverName();
    }

    /**
     * Configure `MAINTENANCE`, a second connection to the worker's database, as
     * the maintenance connection: on SQLite it shares the in-memory database's
     * connection.
     *
     * @return void
     */
    private function sameDatabase(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::MAINTENANCE, $config->array('database.connections.' . self::CONNECTION));
        $config->set('audit-log.storage.maintenance_connection', self::MAINTENANCE);

        $root = DB::connection(self::CONNECTION);

        if ($root->getDriverName() !== 'sqlite') {
            return;
        }

        $same = DB::connection(self::MAINTENANCE);

        $same->setPdo($root->getPdo());
        $same->setReadPdo($root->getPdo());
    }

    /**
     * Configure `OTHER`, a connection to another installation's state table,
     * holding an installation id of its own.
     *
     * @return void
     */
    private function otherDatabase(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::OTHER, [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'other_']);

        $connection = DB::connection(self::OTHER);
        $schema     = $connection->getSchemaBuilder();

        $schema->dropIfExists(IntegrityTables::stateTable());
        $schema->create(IntegrityTables::stateTable(), static function (Blueprint $table): void {
            $table->string('name', 64)->primary();
            $table->text('value');
            $table->dateTime('updated_at', 6);
        });

        $connection->table(IntegrityTables::stateTable())->insert([
            'name'       => InstallationIdentity::NAME,
            'value'      => json_encode(['id' => '01932b4e-9000-7000-8000-00000000abcd']),
            'updated_at' => '2026-10-01 00:00:00.000000',
        ]);
    }

    /**
     * What the call throws, failing the test when it throws nothing.
     *
     * @param  \Closure(): void  $call
     * @return \Throwable
     */
    private static function thrownBy(\Closure $call): \Throwable
    {
        try {
            $call();
        } catch (\Throwable $exception) {
            return $exception;
        }

        self::fail('Expected the call to throw.');
    }

    /**
     * What the work sees of the transactions: the connection it runs on, that
     * connection's transaction level, and the storage connection's.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return array{0: string, 1: int, 2: int}
     */
    private static function levelsSeenBy(Connection $connection): array
    {
        return [(string) $connection->getName(), $connection->transactionLevel(), DB::connection(self::CONNECTION)->transactionLevel()];
    }

    /**
     * Write a row of the state table under the name, as the work of an attempt
     * writes, so a test can see which attempts committed.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $name
     * @return void
     */
    private static function writeMarker(Connection $connection, string $name): void
    {
        $connection->table(IntegrityTables::stateTable())->insert(['name' => $name, 'value' => '{}', 'updated_at' => self::NOW]);
    }

    /**
     * A query of the markers the work of the attempts wrote: the rows of the
     * state table but the installation id the migrations seed.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return \Illuminate\Database\Query\Builder
     */
    private static function markers(Connection $connection): Builder
    {
        return $connection->table(IntegrityTables::stateTable())->where('name', '!=', InstallationIdentity::NAME);
    }

    /**
     * What a statement is, for a log: the lock, the isolation set or read, or
     * its verb and the package table it names.
     *
     * @param  string  $sql
     * @return string
     */
    private static function labelOf(string $sql): string
    {
        $sql    = strtolower($sql);
        $tables = [
            'lock'    => LifecycleTables::lockTable(),
            'journal' => LifecycleTables::journalTable(),
            'state'   => IntegrityTables::stateTable(),
        ];

        if (preg_match('/^update \W?' . preg_quote($tables['lock'], '/') . '\W/', $sql) === 1) {
            return 'lock';
        }

        if ($sql === 'set transaction isolation level read committed') {
            return 'set isolation';
        }

        if (str_contains($sql, 'current_setting(\'transaction_isolation\')')) {
            return 'isolation';
        }

        foreach ($tables as $label => $table) {
            if (preg_match('/\W' . preg_quote($table, '/') . '\W/', $sql . ' ') === 1) {
                return explode(' ', $sql)[0] . ' ' . $label;
            }
        }

        return $sql;
    }

    /**
     * A failure as its driver raises it, wrapped as the framework wraps a
     * failed statement.
     *
     * @param  string  $message
     * @param  ?string  $state
     * @return \Illuminate\Database\QueryException
     */
    private static function failure(string $message, ?string $state = null): QueryException
    {
        $driver = new \PDOException($message);

        if ($state !== null) {
            $driver->errorInfo = [$state, 0, ''];
        }

        return new QueryException(self::CONNECTION, 'update lock', [], $driver);
    }

    /**
     * A serialisation failure known by its SQLSTATE alone, as PostgreSQL raises
     * it: its code is the string `40001`, and no phrase the framework
     * recognises is in its message.
     *
     * @return \Illuminate\Database\QueryException
     */
    private static function serialisationFailure(): QueryException
    {
        $driver = new class ('SQLSTATE[40001]: Serialization failure: 7 ERROR:  could not serialize access due to concurrent update') extends \PDOException {
            /**
             * Constructor.
             *
             * @param  string  $message
             */
            public function __construct(string $message)
            {
                parent::__construct($message);

                $this->code      = '40001';
                $this->errorInfo = ['40001', 7, ''];
            }
        };

        return new QueryException(self::CONNECTION, 'update lock', [], $driver);
    }

    /**
     * A unique violation, as the framework raises one.
     *
     * @return \Illuminate\Database\UniqueConstraintViolationException
     */
    private static function uniqueViolation(): UniqueConstraintViolationException
    {
        $driver = new \PDOException('SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry');

        $driver->errorInfo = ['23000', 1062, ''];

        return new UniqueConstraintViolationException(self::CONNECTION, 'insert into journal', [], $driver);
    }
}
