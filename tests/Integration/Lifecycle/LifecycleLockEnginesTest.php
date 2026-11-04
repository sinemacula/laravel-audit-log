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
 * Integration tests for the lifecycle lock between real processes, on whichever
 * engine the suite runs against: an operation that asks for the lock while
 * another holds it waits for that one's commit; its first read after the lock
 * sees a row the other committed while it waited (MySQL's `read committed`,
 * PostgreSQL's default, SQLite's one writer); on SQLite the lock is the
 * database's write lock, taken by the first statement of the framework's
 * transaction on whatever PHP runs; and two operations racing again and again
 * never interleave.
 *
 * SQLite runs on a file in WAL mode, as the operations guidance advises, so a
 * read never blocks another process's commit and only the lock's update makes
 * an operation wait. The processes meet on file gates rather than on timing; a
 * pause inside a held lock only makes an interleaving likely should the lock
 * fail, and no assertion measures time.
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
     * An operation asking for the lock while another holds it waits for that
     * one's commit: it runs only after the holder's last write inside the lock,
     * which it then reads as committed, and it takes the lock after it.
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
     * A row the holder appends and commits while another operation waits for
     * the lock is seen by that operation's first read after the lock, as the
     * journal's head: MySQL's `read committed` reads it, PostgreSQL's default
     * does, and SQLite's write lock begins the waiter's reading only once it is
     * granted.
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
     * On SQLite the lock is taken inside the framework's transaction, by its
     * first statement, on whatever PHP runs: the framework's begin and the
     * lock's update come first, and while the work runs no other connection can
     * begin a write until the commit.
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
     * Two processes racing operation after operation never interleave: each
     * operation's lines, written inside the lock with a pause between them,
     * stay together, and every operation of both is there.
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
     * Start a child that, once the start gate opens, runs its operations one
     * after another, each writing its begin and end lines inside the lock.
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
     * Open the release gate just before this process's next lock statement
     * runs, so the holder goes on to commit while this process waits for the
     * lock.
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
     * Whether a second connection to the SQLite file may begin a write at once,
     * waiting for no other.
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
