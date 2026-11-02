<?php

declare(strict_types = 1);

namespace Tests\Integration\Stores;

use Illuminate\Database\DeadlockException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RecordConflictException;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for duplicates that race, each stored in a process and on a
 * connection of its own against a shared database server: the second insert
 * waits on the first's uncommitted row, then resolves against it once it is
 * committed, to a success when the content is the same and a conflict when it
 * differs; on MySQL inside a REPEATABLE READ snapshot that predates the first's
 * commit, through the shared locking read; and a lock wait that times out
 * inside a host transaction propagates as Laravel's `DeadlockException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAuditStore::class)]
final class ConcurrentDuplicatesTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var int How long the first side holds its transaction open once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var int How long the first side holds its transaction open past the second's lock wait timeout, in microseconds. */
    private const int TIMEOUT_HOLD_MICROSECONDS = 2500000;

    /** @var float The least time, in seconds, the second side must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second side waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var string The id both sides store under. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string Directory the second side reports its outcome in. */
    private string $outcomes;

    /**
     * Prepare the outcomes directory, on a shared database server with `pcntl`
     * only.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $this->outcomes = sys_get_temp_dir() . '/audit-duplicate-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the outcomes.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob(($this->outcomes ?? sys_get_temp_dir() . '/none') . '/*') ?: [] as $file) {
            unlink($file);
        }

        if (isset($this->outcomes) && is_dir($this->outcomes)) {
            rmdir($this->outcomes);
        }

        parent::tearDown();
    }

    /**
     * The second store of one record waits on the first's uncommitted row and,
     * once it is committed, finds it the same record: one row, and a success.
     *
     * @return void
     */
    public function testAConcurrentDuplicateWithTheSameContentStoresOneRow(): void
    {
        $finalised = $this->finalised('1200.00');

        $second = $this->race(fn () => $this->store()->store($finalised), fn () => $this->store()->store($finalised));

        self::assertSame(['stored' => true], $second['outcome']);
        self::assertSame(1, $this->entryCount());
    }

    /**
     * The second store of other content under the same id waits on the first's
     * uncommitted row and, once it is committed, is a conflict; the first row
     * is the only one.
     *
     * @return void
     */
    public function testAConcurrentDuplicateWithDifferentContentIsAConflict(): void
    {
        $first = $this->finalised('1200.00');
        $other = $this->finalised('1200.01');

        $second = $this->race(fn () => $this->store()->store($first), fn () => $this->store()->store($other));

        $message = 'An audit entry with id ' . self::ID . ' already exists with different captured content.';

        self::assertSame(['thrown' => RecordConflictException::class, 'message' => $message], $second['outcome']);
        self::assertSame(1, $this->entryCount());
        self::assertSame($first->hmac, $this->storedRow(self::ID)['hmac']);
    }

    /**
     * On MySQL, a second side whose REPEATABLE READ snapshot was taken before
     * the first committed, so a plain read would miss the first's row, still
     * resolves its duplicate to a success, because the store's shared locking
     * read is a current read.
     *
     * @return void
     */
    public function testOnMySqlAConcurrentDuplicateIsResolvedInsideARepeatableReadSnapshot(): void
    {
        if (DB::connection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL reads a REPEATABLE READ snapshot by default.');
        }

        $finalised = $this->finalised('1200.00');

        $second = $this->race(fn () => $this->store()->store($finalised), function () use ($finalised): void {
            $connection = DB::connection();

            $connection->beginTransaction();

            $snapshot = $connection->table(EntrySettings::table())->count();

            $this->store()->store($finalised);

            $plain = $connection->table(EntrySettings::table())->count();

            $connection->commit();

            if ($snapshot !== 0 || $plain !== 0) {
                throw new \LogicException(sprintf('The snapshot saw %d rows before and %d after.', $snapshot, $plain));
            }
        });

        self::assertSame(['stored' => true], $second['outcome']);
        self::assertSame(1, $this->entryCount());
    }

    /**
     * On MySQL, a second side whose insert waits on the first's row longer than
     * its lock wait timeout, inside a host transaction, fails with Laravel's
     * `DeadlockException`, which the store lets propagate.
     *
     * @return void
     */
    public function testOnMySqlALockWaitTimeoutInsideAHostTransactionPropagates(): void
    {
        if (DB::connection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL times out a lock wait by a session setting of a second.');
        }

        $finalised = $this->finalised('1200.00');

        $second = $this->race(fn () => $this->store()->store($finalised), function () use ($finalised): void {
            $connection = DB::connection();

            $connection->statement('SET SESSION innodb_lock_wait_timeout = 1');
            $connection->beginTransaction();

            try {
                $this->store()->store($finalised);
            } finally {
                $connection->rollBack();
            }
        }, self::TIMEOUT_HOLD_MICROSECONDS);

        self::assertSame(DeadlockException::class, $second['outcome']['thrown'] ?? null);
        self::assertSame(1, $this->entryCount());
    }

    /**
     * Run the first side inside a transaction in this process and the second in
     * a forked one, started once the first has written, then hold the first's
     * transaction open and commit it: the second's outcome and how long it
     * waited.
     *
     * @param  \Closure(): void  $first
     * @param  \Closure(): void  $second
     * @param  int  $hold
     * @return array{outcome: array{stored?: true, thrown?: class-string, message?: string}, waited: float}
     */
    private function race(\Closure $first, \Closure $second, int $hold = self::HOLD_MICROSECONDS): array
    {
        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            $this->runInChild($second);
        }

        DB::beginTransaction();

        $first();

        touch("{$this->outcomes}/start");
        usleep($hold);

        DB::commit();

        pcntl_waitpid($pid, $status);

        $reported = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($reported);
        self::assertArrayNotHasKey('error', $reported);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $reported['waited']);

        /** @var array{outcome: array{stored?: true, thrown?: class-string, message?: string}, waited: float} $reported */
        return $reported;
    }

    /**
     * In the forked process: wait to be started, run the second side on a
     * connection of its own, report its outcome (stored, or the exception it
     * threw) and how long it took, or that it was never started, and end
     * without running the parent's shutdown.
     *
     * @param  \Closure(): void  $second
     * @return never
     */
    private function runInChild(\Closure $second): never
    {
        $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

        while (!is_file("{$this->outcomes}/start") && microtime(true) < $deadline) {
            usleep(5000);
        }

        $started = microtime(true);

        try {
            $second();

            $outcome = ['stored' => true];
        } catch (\Throwable $exception) {
            $outcome = ['thrown' => $exception::class, 'message' => $exception->getMessage()];
        }

        $report = is_file("{$this->outcomes}/start")
            ? ['outcome' => $outcome, 'waited' => microtime(true) - $started]
            : ['error' => 'The second side was never started.'];

        file_put_contents("{$this->outcomes}/outcome", json_encode($report));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * The captured record under the shared id with the amount given, finalised
     * on the frozen clock.
     *
     * @param  string  $amount
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function finalised(string $amount): FinalisedRecord
    {
        return $this->finaliser()->finalise(RecordFactory::captured(['amount' => $amount], self::ID));
    }
}
