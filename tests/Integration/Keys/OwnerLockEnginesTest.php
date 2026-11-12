<?php

declare(strict_types = 1);

namespace Tests\Integration\Keys;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition;
use SineMacula\Laravel\AuditLog\Keys\KeySession;
use SineMacula\Laravel\AuditLog\Keys\OwnerLock;
use SineMacula\Laravel\AuditLog\Keys\OwnerLockTimeoutException;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarker;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarkers;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\RunsKilledChildren;
use Tests\TestCase;

/**
 * Integration tests for an owner's lock between real processes; SQLite takes
 * none and relies on its write lock. No assertion measures time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OwnerLock::class)]
final class OwnerLockEnginesTest extends TestCase
{
    use RunsKilledChildren;

    /** @var string The gate the holding child opens once it holds the lock. */
    private const string HELD = 'held';

    /** @var string The gate that lets the holding child go on to commit. */
    private const string RELEASE = 'release';

    /** @var int How long the holding child keeps the lock once released, in microseconds, so a broken lock would be overtaken. */
    private const int HOLD_MICROSECONDS = 200000;

    /** @var string PostgreSQL's try for the advisory lock, held to the end of its transaction. */
    private const string TRY_LOCK = 'select pg_try_advisory_xact_lock(?) as answer';

    /** @var string The marker the holding child writes inside the lock. */
    private const string MARKER_ID = '01932b4e-e000-7000-8000-000000000001';

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
     * On MySQL and PostgreSQL a second holder waits for the first's commit,
     * then reads the marker it committed.
     *
     * @return void
     */
    public function testASecondHolderWaitsForTheFirstsCommit(): void
    {
        $this->skipOnSqlite();

        $owner = self::owner();
        $child = $this->startChild(function () use ($owner): void {
            $this->holding($owner, function (Connection $connection) use ($owner): void {
                $this->openGate(self::HELD);
                $this->awaitGate(self::RELEASE);

                usleep(self::HOLD_MICROSECONDS);

                app(OwnerMarkers::class)->insert($connection, new OwnerMarker(self::MARKER_ID, $owner, MarkerTransition::ERASED, 1, 1, '2026-11-01T12:00:00.000000Z'));
            });
        });

        $this->awaitGate(self::HELD);

        $storage = DB::connection(StorageConnection::name());

        self::assertNull(app(OwnerMarkers::class)->latest($storage, $owner));

        $this->releaseAsTheLockIsAskedFor($storage);

        $seen = $this->holding($owner, static fn (Connection $connection): ?OwnerMarker => app(OwnerMarkers::class)->latest($connection, $owner), $storage);

        $this->assertKilled($this->waitForChild($child));

        self::assertNotNull($seen);
        self::assertSame(self::MARKER_ID, $seen->id);
    }

    /**
     * On MySQL and PostgreSQL a bounded wait past the limit is refused, naming
     * the wait alone, and the transaction is left to roll back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWaitPastTheLimitIsRefused(): void
    {
        $this->skipOnSqlite();

        $owner = self::owner();
        $child = $this->startChild(function () use ($owner): void {
            $this->holding($owner, function (): void {
                $this->openGate(self::HELD);
                $this->awaitGate(self::RELEASE);
            });
        });

        $this->awaitGate(self::HELD);

        $storage = DB::connection(StorageConnection::name());
        $lock    = new OwnerLock(new FailureClassifier, 1);

        try {
            $storage->transaction(static function (Connection $connection) use ($lock, $owner): void {
                $lock->acquire($connection, $owner, true);
            });
            self::fail('Expected the wait to be refused.');
        } catch (OwnerLockTimeoutException $exception) {
            self::assertSame('An owner\'s lock was not granted within 1 seconds; nothing that waited for it was committed.', $exception->getMessage());
            self::assertNull($exception->getPrevious());
        } finally {
            $lock->release($storage, $owner);
            $this->openGate(self::RELEASE);
        }

        self::assertSame(0, $storage->transactionLevel());

        $this->assertKilled($this->waitForChild($child));
    }

    /**
     * On SQLite the write lock serialises holders: no other write begins until
     * the first commits.
     *
     * @return void
     */
    public function testOnSqliteTheWriteLockSerialisesTheHolders(): void
    {
        $storage = DB::connection(StorageConnection::name());

        if ($storage->getDriverName() !== 'sqlite') {
            self::markTestSkipped('Only SQLite serialises the holders by its write lock alone.');
        }

        $owner = self::owner();

        $storage->transaction(function (Connection $connection) use ($owner): void {
            app(OwnerLock::class)->acquire($connection, $owner, true);

            self::assertTrue($this->canAnotherWriterBegin(), 'The lock took the write lock before anything was written.');

            app(OwnerMarkers::class)->insert($connection, new OwnerMarker(self::MARKER_ID, $owner, MarkerTransition::ERASED, 1, 1, '2026-11-01T12:00:00.000000Z'));

            self::assertFalse($this->canAnotherWriterBegin(), 'Another writer began while a holder had written.');
        });

        self::assertTrue($this->canAnotherWriterBegin(), 'The write lock outlived the commit.');
    }

    /**
     * A release after several takings on one session frees every level for
     * another session.
     *
     * @return void
     */
    public function testAReleaseAfterRetriesFreesEveryLevel(): void
    {
        $storage = DB::connection(StorageConnection::name());
        $owner   = self::owner();
        $lock    = app(OwnerLock::class);

        if ($storage->getDriverName() === 'mysql') {
            foreach (range(1, 3) as $attempt) {
                $lock->acquire($storage, $owner, true);
            }

            self::assertFalse($this->isFreeElsewhere($owner));

            $lock->release($storage, $owner);

            self::assertTrue($this->isFreeElsewhere($owner));

            return;
        }

        $storage->transaction(static function (Connection $connection) use ($lock, $owner): void {
            foreach (range(1, 3) as $attempt) {
                $lock->acquire($connection, $owner, true);
            }
        });

        $lock->release($storage, $owner);

        self::assertTrue($this->isFreeElsewhere($owner));
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
     * The owner every test locks.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(): Reference
    {
        return Reference::of('App\Models\User', '42');
    }

    /**
     * Skip a test of a lock SQLite does not take.
     *
     * @return void
     */
    private function skipOnSqlite(): void
    {
        if (DB::connection(StorageConnection::name())->getDriverName() !== 'sqlite') {
            return;
        }

        self::markTestSkipped('SQLite takes no owner lock; its write lock serialises the holders.');
    }

    /**
     * Run the work holding the owner's lock as key creation does: on MySQL
     * around the transaction, elsewhere inside it, on the connection given or a
     * session of its own.
     *
     * @template TResult
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  \Closure(\Illuminate\Database\Connection): TResult  $work
     * @param  ?\Illuminate\Database\Connection  $connection
     * @return TResult
     */
    private function holding(Reference $owner, \Closure $work, ?Connection $connection = null): mixed
    {
        $session = $connection === null ? KeySession::open(app('db')) : null;
        $connection ??= $session?->connection();
        $lock = app(OwnerLock::class);

        self::assertInstanceOf(Connection::class, $connection);

        $mysql = $connection->getDriverName() === 'mysql';

        try {
            if ($mysql) {
                $lock->acquire($connection, $owner, true);
            }

            return $connection->transaction(static function (Connection $connection) use ($lock, $owner, $mysql, $work): mixed {
                if (!$mysql) {
                    $lock->acquire($connection, $owner, true);
                }

                return $work($connection);
            });
        } finally {
            $lock->release($connection, $owner);
            $session?->close();
        }
    }

    /**
     * Open the release gate just before this process's lock statement runs, so
     * the holder commits while it waits.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     */
    private function releaseAsTheLockIsAskedFor(Connection $connection): void
    {
        $released = false;

        $connection->beforeExecuting(function (string $query) use (&$released): void {
            if ($released || (!str_contains($query, 'get_lock(') && !str_contains($query, 'pg_advisory_xact_lock('))) {
                return;
            }

            $released = true;

            $this->openGate(self::RELEASE);
        });
    }

    /**
     * Whether another session takes the owner's lock at once, or on SQLite can
     * begin a write.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return bool
     */
    private function isFreeElsewhere(Reference $owner): bool
    {
        $session    = KeySession::open(app('db'));
        $connection = $session->connection();

        try {
            return match ($connection->getDriverName()) {
                'mysql' => in_array(self::answerOf($connection->selectOne('select is_free_lock(?) as answer', [OwnerLock::name($owner)])), [1, '1'], true),
                'pgsql' => $connection->transaction(static fn (Connection $pg): bool => self::answerOf($pg->selectOne(self::TRY_LOCK, [OwnerLock::key($owner)])) === true),
                default => $this->canAnotherWriterBegin(),
            };
        } finally {
            $session->close();
        }
    }

    /**
     * What a lock function answered in the row.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $row
     * @return bool|int|string|null
     */
    private static function answerOf(mixed $row): bool|int|string|null
    {
        $answer = is_object($row) ? (get_object_vars($row)['answer'] ?? null) : null;

        return is_bool($answer) || is_int($answer) || is_string($answer) ? $answer : null;
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
}
