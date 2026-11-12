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
use Tests\Concerns\ConnectsSecondDatabases;
use Tests\TestCase;

/**
 * Feature tests for the frame of every lifecycle transaction.
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
    use ConnectsSecondDatabases;

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
     * Roll back any open transaction, restore the clock and sleep, and drop the
     * other state table.
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
     * transaction.
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
     * The lock row keeps the last operation's token and the clock's instant to
     * the microsecond.
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
     * Rows of `[maintenance connection]`.
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
     * An operation is refused inside a maintenance transaction, which it would
     * only be a savepoint of.
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
     * An operation is refused inside a storage transaction, which may hold what
     * it decides on.
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
     * A nested lifecycle operation is refused and never retried.
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
     * Another installation is refused by `confirm()` before the lock.
     *
     * @return void
     */
    public function testAMismatchedInstallationRefusesBeforeTheLock(): void
    {
        $this->otherDatabase();

        DB::connection(self::OTHER)->table(IntegrityTables::stateTable())->insert([
            'name'       => InstallationIdentity::NAME,
            'value'      => json_encode(['id' => '01932b4e-9000-7000-8000-00000000abcd']),
            'updated_at' => '2026-10-01 00:00:00.000000',
        ]);

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
     * `confirm()` writes nothing but a missing installation id, without the
     * lock or a transaction.
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
     * `confirm()` reads the installation id through a maintenance connection of
     * its own.
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
     * `run()` never confirms the installation.
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
     * A missing lock row is refused before any work runs, and never retried.
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
     * With a maintenance connection of its own, the work and the lock run on
     * it.
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
     * Rows of `[failure]`: each failure a concurrent operation causes.
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
     * A concurrency failure is retried three times, then reported as contention
     * with nothing committed.
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
     * A lock wait timeout on the lock is retried like any other loss.
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
     * Each retry waits a random time up to 20, 40 and then 80 milliseconds.
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
     * The waits are random within their bound.
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
     * A lost connection is never retried, since its commit may have happened.
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
     * Rows of `[failure]`: failures no concurrent operation causes.
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
     * Any other failure propagates unchanged after one attempt.
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
     * The token changes on every attempt, since MySQL skips an update that
     * changes nothing.
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
     * A retried attempt runs the work afresh and returns only the committed
     * result.
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
     * A failed commit leaves no writes and no transaction behind.
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
     * An operation id that is empty or over 47 bytes is refused, so a token
     * fits 64 characters.
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
     * On MySQL the isolation is set to `read committed` before every attempt's
     * transaction.
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
     * On PostgreSQL a session at another isolation level is refused before any
     * work runs.
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
     * Assert an operation is refused for the open transaction, before the lock
     * or its work.
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
     * The waits slept, in milliseconds, while each operation loses three
     * attempts.
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
     * given.
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
     * Raise the failure at the first outermost commit, leaving the driver's
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
     * Record each statement and transaction event from now on, in order, as its
     * label.
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
     * The connection the work runs on, its transaction level, and the storage
     * connection's.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return array{0: string, 1: int, 2: int}
     */
    private static function levelsSeenBy(Connection $connection): array
    {
        return [(string) $connection->getName(), $connection->transactionLevel(), DB::connection(self::CONNECTION)->transactionLevel()];
    }

    /**
     * Write a state table row under the name, so a test can see which attempts
     * committed.
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
     * A query of the markers the attempts wrote, excluding the seeded
     * installation id.
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
     * its verb and table.
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
     * A serialisation failure known by its SQLSTATE `40001` alone, as
     * PostgreSQL raises it.
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
