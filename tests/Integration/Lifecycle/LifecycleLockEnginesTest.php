<?php

declare(strict_types = 1);

namespace Tests\Integration\Lifecycle;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction;
use Tests\Concerns\RunsKilledChildren;
use Tests\TestCase;

/**
 * Integration tests for the lifecycle lock between real processes, SQLite on a
 * WAL file; the processes meet on file gates, not timing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MaintenanceTransaction::class)]
final class LifecycleLockEnginesTest extends TestCase
{
    use RunsKilledChildren;

    /** @var string The operation that takes the lock first. */
    private const string FIRST = '01932b4e-9000-7000-8000-0000000000f1';

    /** @var string The operation that asks for the lock while the first holds it. */
    private const string SECOND = '01932b4e-9000-7000-8000-0000000000f2';

    /** @var string The gate the holding child opens once it has the lock. */
    private const string ARRIVED = 'arrived';

    /** @var string The gate that lets the holding child go on to commit. */
    private const string RELEASE = 'release';

    /** @var string The gate that releases the racing children together. */
    private const string START = 'start';

    /** @var string The file each process names what it did inside the lock in. */
    private const string LINES = 'lines';

    /** @var int How long the holding child keeps the lock once released, in microseconds, so a broken lock would be overtaken. */
    private const int HOLD_MICROSECONDS = 200000;

    /** @var int How long a racing operation pauses inside the lock, in microseconds. */
    private const int RACE_PAUSE_MICROSECONDS = 2000;

    /** @var int The operations each racing child runs. */
    private const int RACE_OPERATIONS = 25;

    /**
     * Remove what the children shared once the migrations have rolled back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * An operation asking for a held lock waits for the holder's commit.
     *
     * @return void
     */
    public function testASecondOperationWaitsForTheFirstsCommit(): void
    {
        $child = $this->startChild(function (): void {
            $this->transaction()->run(self::FIRST, function (Connection $connection): void {
                $this->openGate(self::ARRIVED);
                $this->awaitGate(self::RELEASE);

                usleep(self::HOLD_MICROSECONDS);

                $this->appendToChildFile(self::LINES, 'first committing');
                $this->appendJournalRow($connection, 1, self::FIRST);
            });
        });

        $this->awaitGate(self::ARRIVED);
        $this->releaseAsTheLockIsAskedFor();

        $seen = $this->transaction()->run(self::SECOND, function (Connection $connection): int {
            $this->appendToChildFile(self::LINES, 'second locked');

            return $connection->table(LifecycleTables::journalTable())->count();
        });

        $this->assertKilled($this->waitForChild($child));

        self::assertSame(1, $seen);
        self::assertSame(['first committing', 'second locked'], $this->childFileLines(self::LINES));
        self::assertStringStartsWith(self::SECOND . ':', (string) $this->lockToken());
    }

    /**
     * The first read after the lock sees a row committed while waiting.
     *
     * @return void
     */
    public function testAReadAfterTheLockSeesARowCommittedWhileWaiting(): void
    {
        $child = $this->startChild(function (): void {
            $this->transaction()->run(self::FIRST, function (Connection $connection): void {
                $this->openGate(self::ARRIVED);
                $this->awaitGate(self::RELEASE);

                usleep(self::HOLD_MICROSECONDS);

                $this->appendJournalRow($connection, 1, self::FIRST);
            });
        });

        $this->awaitGate(self::ARRIVED);

        $maintenance = DB::connection(StorageConnection::forMaintenance());

        self::assertNull($maintenance->table(LifecycleTables::journalTable())->max('sequence'));

        $this->releaseAsTheLockIsAskedFor();

        $head = $this->transaction()->run(self::SECOND, static function (Connection $connection): array {
            $row = $connection->table(LifecycleTables::journalTable())->orderByDesc('sequence')->first(['sequence', 'operation_id']);

            return $row === null ? [] : [(int) $row->sequence, (string) $row->operation_id];
        });

        $this->assertKilled($this->waitForChild($child));

        self::assertSame([1, self::FIRST], $head);
    }

    /**
     * On SQLite the lock is the first statement of the framework's transaction.
     *
     * @return void
     */
    public function testOnSqliteTheLockIsTakenInsideTheFrameworksTransaction(): void
    {
        if (DB::connection(StorageConnection::forMaintenance())->getDriverName() !== 'sqlite') {
            self::markTestSkipped('Only SQLite takes its write lock with the lock row\'s update.');
        }

        $log = [];

        Event::listen(TransactionBeginning::class, static function () use (&$log): void {
            $log[] = 'begin';
        });

        Event::listen(TransactionCommitted::class, static function () use (&$log): void {
            $log[] = 'commit';
        });

        DB::listen(static function (QueryExecuted $query) use (&$log): void {
            $log[] = explode(' ', strtolower($query->sql))[0];
        });

        $locked = $this->transaction()->run(self::FIRST, fn (Connection $connection): bool => $connection->transactionLevel() === 1 && !$this->canAnotherWriterBegin());

        self::assertTrue($locked, 'Another connection could begin a write while the lock was held.');
        self::assertSame(['begin', 'update', 'commit'], $log);
        self::assertTrue($this->canAnotherWriterBegin(), 'The write lock outlived the commit.');
    }

    /**
     * Two processes racing operations never interleave.
     *
     * @return void
     */
    public function testTwoOperationsNeverInterleave(): void
    {
        $first  = $this->startRacer('first');
        $second = $this->startRacer('second');

        $this->openGate(self::START);

        $this->assertKilled($this->waitForChild($first));
        $this->assertKilled($this->waitForChild($second));

        $lines = $this->childFileLines(self::LINES);

        self::assertCount(4 * self::RACE_OPERATIONS, $lines);

        foreach (array_chunk($lines, 2) as $index => [$begin, $end]) {
            self::assertMatchesRegularExpression('/\A(first|second) begin\z/', $begin, "Operation {$index} did not begin alone.");
            self::assertSame(str_replace(' begin', ' end', $begin), $end, "Operation {$index} was interleaved.");
        }

        foreach (['first', 'second'] as $name) {
            self::assertCount(self::RACE_OPERATIONS, array_keys($lines, "{$name} begin", true), "Not every operation of the {$name} racer ran.");
        }
    }

    /**
     * Put the database on a file SQLite can share across a fork, in WAL mode.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->useFileDatabaseOnSqlite($app);

        $config = app(ConfigRepository::class);
        $key    = 'database.connections.' . self::CONNECTION;

        if ($config->get($key . '.driver') !== 'sqlite') {
            return;
        }

        $config->set($key . '.journal_mode', 'wal');
    }

    /**
     * Start a child that runs its operations once the start gate opens.
     *
     * @param  string  $name
     * @return int
     */
    private function startRacer(string $name): int
    {
        return $this->startChild(function () use ($name): void {
            $transaction = $this->transaction();

            $this->awaitGate(self::START);

            for ($operation = 0; $operation < self::RACE_OPERATIONS; $operation++) {
                $transaction->run(sprintf('01932b4e-9000-7000-8000-%012d', $operation), function () use ($name): void {
                    $this->appendToChildFile(self::LINES, "{$name} begin");

                    usleep(self::RACE_PAUSE_MICROSECONDS);

                    $this->appendToChildFile(self::LINES, "{$name} end");
                });
            }
        });
    }

    /**
     * Open the release gate as this process asks for the lock.
     *
     * @return void
     */
    private function releaseAsTheLockIsAskedFor(): void
    {
        $released = false;
        $pattern  = '/^update \W?' . preg_quote(LifecycleTables::lockTable(), '/') . '\W/';

        DB::connection(StorageConnection::forMaintenance())->beforeExecuting(function (string $query) use (&$released, $pattern): void {
            if ($released || preg_match($pattern, $query) !== 1) {
                return;
            }

            $released = true;

            $this->openGate(self::RELEASE);
        });
    }

    /**
     * Append a row shaped as a journal row, at the sequence, for the operation.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  int  $sequence
     * @param  string  $operationId
     * @return void
     */
    private function appendJournalRow(Connection $connection, int $sequence, string $operationId): void
    {
        $connection->table(LifecycleTables::journalTable())->insert([
            'id'             => sprintf('01932b4e-9000-7000-8000-%012d', $sequence),
            'sequence'       => $sequence,
            'log_id'         => 'lock-test',
            'kind'           => 'hold',
            'operation_id'   => $operationId,
            'occurred_at'    => '2026-11-01 12:00:00.000000',
            'payload'        => '{}',
            'payload_digest' => hash('sha256', '{}'),
            'previous_hmac'  => null,
            'key_id'         => 'lock-test',
            'hmac'           => hash('sha256', 'lock-test'),
        ]);
    }

    /**
     * Whether another SQLite connection may begin a write without waiting.
     *
     * @return bool
     */
    private function canAnotherWriterBegin(): bool
    {
        $path = app(ConfigRepository::class)->string('database.connections.' . self::CONNECTION . '.database');
        $pdo  = new \PDO('sqlite:' . $path, null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);

        $pdo->exec('pragma busy_timeout = 0');

        try {
            $pdo->exec('begin immediate');
            $pdo->exec('rollback');

            return true;
        } catch (\PDOException) {
            // The database's write lock is held by another connection
            return false;
        }
    }

    /**
     * The token the lock row holds, or `null` when no operation has taken it.
     *
     * @return ?string
     */
    private function lockToken(): ?string
    {
        $token = DB::connection(StorageConnection::name())->table(LifecycleTables::lockTable())->where('id', 1)->value('token');

        return is_string($token) ? $token : null;
    }

    /**
     * The transaction frame the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction
     */
    private function transaction(): MaintenanceTransaction
    {
        return app(MaintenanceTransaction::class);
    }
}
