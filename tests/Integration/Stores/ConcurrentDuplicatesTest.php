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
 * Integration tests for duplicates raced from separate processes.
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
     * Prepare the outcomes directory; needs a shared server and `pcntl`.
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
     * A racing duplicate of the same content waits, then succeeds with one row.
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
     * A racing duplicate with different content waits, then is a conflict.
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
     * On MySQL, a duplicate inside an older REPEATABLE READ snapshot resolves
     * through the locking read.
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
     * On MySQL, a lock wait timeout in a host transaction propagates.
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
     * Two writers of one bundle leave one entry and one artifact.
     *
     * @return void
     */
    public function testConcurrentWritersOfOneBundleLeaveOneEntryAndOneArtifact(): void
    {
        $bundle = $this->finaliser()->finalise(RecordFactory::bundled());

        $second = $this->race(fn () => $this->store()->store($bundle), fn () => $this->store()->store($bundle));

        self::assertSame(['stored' => true], $second['outcome']);
        self::assertSame(1, $this->entryCount());
        self::assertSame(1, $this->storageConnection()->table(EntrySettings::artifactsTable())->count());
        self::assertSame($bundle->hmac, $this->storedRow($bundle->record->id)['hmac']);
    }

    /**
     * Race the first side, in a transaction here, against the second in a fork;
     * the second's outcome and wait.
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
     * In the fork, run the second side on its own connection, report its
     * outcome and wait, and exit without the parent's shutdown.
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
     * The captured record under the shared id with the amount, finalised.
     *
     * @param  string  $amount
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function finalised(string $amount): FinalisedRecord
    {
        return $this->finaliser()->finalise(RecordFactory::captured(['amount' => $amount], self::ID));
    }
}
