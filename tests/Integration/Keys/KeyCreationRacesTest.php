<?php

declare(strict_types = 1);

namespace Tests\Integration\Keys;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\ConnectionEstablished;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Keys\KeyCreator;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Keys\OwnerLockTimeoutException;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarkers;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Eraser;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\RunsKilledChildren;
use Tests\TestCase;

/**
 * Integration tests for an owner's first key racing the owner's erasure, in
 * processes of their own, on whichever engine the suite runs against and on a
 * file database on SQLite: whichever commits first, no key of the owner
 * survives the erasure live. A creation that waits for the owner's lock while
 * an erasure holds it sees the erasure's marker and makes no key, or on SQLite
 * fails closed as busy; and a key committed before the erasure's lock is
 * destroyed by it.
 *
 * SQLite runs on a file in WAL mode, as the operations guidance advises. The
 * processes meet on file gates rather than on timing; a pause inside a held
 * lock only makes an overtaking likely should the lock fail, and no assertion
 * measures time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyCreator::class)]
#[CoversClass(Eraser::class)]
final class KeyCreationRacesTest extends TestCase
{
    use MakesSubjectKeys, RunsKilledChildren;

    /** @var string When every erasure starts, before a child moves its clock on. */
    private const string NOW = '2026-11-04 10:00:00.000000';

    /** @var int How many times the first key and the erasure race. */
    private const int ROUNDS = 25;

    /** @var string The category every key is made in. */
    private const string CATEGORY = 'billing';

    /** @var string The gate a child opens once it holds the locks. */
    private const string HELD = 'held';

    /** @var string The gate that lets a child go on. */
    private const string RELEASE = 'release';

    /** @var string The file a child writes what it made to. */
    private const string RESULTS = 'results';

    /** @var int How long a child keeps its locks once released, in microseconds, so a broken lock would be overtaken. */
    private const int HOLD_MICROSECONDS = 200000;

    /** @var int The longest an erasure waits before racing a round's creation, in microseconds. */
    private const int JITTER_MICROSECONDS = 20000;

    /** @var string What a creation that made or found a key writes. */
    private const string MADE = 'made';

    /** @var string What a creation that made no key writes. */
    private const string NONE = 'none';

    /** @var string What a creation that failed closed as SQLite's busy insert writes. */
    private const string BUSY = 'busy';

    /** @var string What a creation that failed closed waiting for the owner's lock writes. */
    private const string TIMED_OUT = 'timed out';

    /** @var list<int> SQLite's result codes for a busy database: `SQLITE_BUSY` and `SQLITE_BUSY_SNAPSHOT`. */
    private const array SQLITE_BUSY = [5, 517];

    /**
     * Stop the clock and bind the package's key wrapper.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $this->keyWrapper();
    }

    /**
     * Put the clock back, and remove what the children shared once the
     * migrations have rolled back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * An owner's first key racing the owner's erasure never survives it: in
     * every round, whichever commits first, the owner holds no live key once
     * both are done and is marked erased, and a key the creation made is erased
     * by the erasure.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFirstKeyRacingAnErasureNeverSurvivesIt(): void
    {
        for ($round = 1; $round <= self::ROUNDS; $round++) {
            $owner = Reference::of('App\Models\User', sprintf('race-%d', $round));
            $child = $this->startChild(function () use ($owner, $round): void {
                $this->awaitGate(sprintf('go-%d', $round));
                $this->appendToChildFile(self::RESULTS . $round, $this->create($owner));
            });

            $this->openGate(sprintf('go-%d', $round));

            // A jitter lets either side win a round, whichever order the engine
            // would otherwise favour; no assertion depends on it
            usleep(random_int(0, self::JITTER_MICROSECONDS));

            $result = $this->erase($owner);

            $this->waitForChild($child);

            $made = $this->childFileLines(self::RESULTS . $round);
            $keys = $this->keysOf($owner);

            self::assertCount(1, $made, "Round {$round} wrote no result.");
            self::assertSame([], array_filter($keys, static fn (SubjectKeyRow $key): bool => $key->state->holdsAKey()), "A key survived the erasure in round {$round}.");
            self::assertSame(MarkerTransition::ERASED, app(OwnerMarkers::class)->latest($this->keyConnection(), $owner)?->transition, "Round {$round}.");
            self::assertSame(count($keys), $result->keysDestroyed, "Round {$round}.");

            foreach ($keys as $key) {
                self::assertSame($result->erasureId, $key->erasureId, "Round {$round}.");
            }
        }
    }

    /**
     * A creation that asks for the owner's lock while an erasure holds it sees
     * the erasure once it commits, and makes no key; on SQLite, which has no
     * owner's lock, its insert fails closed as busy instead. Either way no key
     * of the owner is live.
     *
     * @return void
     */
    public function testACreatorWaitingOnTheOwnerSeesTheErasure(): void
    {
        $owner = self::owner();
        $child = $this->startChild(function () use ($owner): void {
            CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(1));

            $this->pauseOnceTheOwnerIsLocked();

            $this->appendToChildFile(self::RESULTS, (string) json_encode($this->erase($owner)->toArray()));
        });

        $this->awaitGate(self::HELD);
        $this->releaseAsTheCreatorAsksForTheOwner();

        $made = $this->create($owner);

        $this->assertKilled($this->waitForChild($child));

        $sqlite = DB::connection(StorageConnection::name())->getDriverName() === 'sqlite';

        self::assertContains($made, $sqlite ? [self::NONE, self::BUSY] : [self::NONE]);
        self::assertSame([], $this->keysOf($owner));
        self::assertSame(MarkerTransition::ERASED, app(OwnerMarkers::class)->latest($this->keyConnection(), $owner)?->transition);
    }

    /**
     * A creation on a session whose transactions default to `repeatable read`,
     * as a server, a role or the connection's own settings may make them, still
     * sees an erasure that committed while it waited for the owner's lock: on
     * PostgreSQL its transaction is set to `read committed` before any snapshot
     * is taken, and on MySQL the owner's lock is taken before it begins. No key
     * of the owner is live.
     *
     * @return void
     */
    public function testACreatorAtRepeatableReadWaitingOnTheOwnerSeesTheErasure(): void
    {
        $driver = DB::connection(StorageConnection::name())->getDriverName();

        if ($driver === 'sqlite') {
            self::markTestSkipped('SQLite has no isolation levels; its single writer serialises a creation with an erasure.');
        }

        $owner = self::owner();
        $child = $this->startChild(function () use ($owner): void {
            CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(1));

            $this->pauseOnceTheOwnerIsLocked();

            $this->appendToChildFile(self::RESULTS, (string) json_encode($this->erase($owner)->toArray()));
        });

        $this->awaitGate(self::HELD);
        $this->defaultToRepeatableRead($driver);
        $this->releaseAsTheCreatorAsksForTheOwner();

        $made = $this->create($owner);

        $this->assertKilled($this->waitForChild($child));

        self::assertSame(self::NONE, $made);
        self::assertSame([], $this->keysOf($owner));
        self::assertSame(MarkerTransition::ERASED, app(OwnerMarkers::class)->latest($this->keyConnection(), $owner)?->transition);
    }

    /**
     * A key committed after an erasure started but before its lock is destroyed
     * by it: the erasure reads the owner's keys after its lock.
     *
     * @return void
     */
    public function testAKeyCommittedBeforeTheErasuresLockIsDestroyedByIt(): void
    {
        $owner = self::owner();
        $child = $this->startChild(function () use ($owner): void {
            CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(1));

            $this->pauseBeforeTheLifecycleLock();

            $this->appendToChildFile(self::RESULTS, (string) json_encode($this->erase($owner)->toArray()));
        });

        $this->awaitGate(self::HELD);

        self::assertSame(self::MADE, $this->create($owner));

        $this->openGate(self::RELEASE);
        $this->assertKilled($this->waitForChild($child));

        $result = json_decode($this->childFileLines(self::RESULTS)[0], true);
        $keys   = $this->keysOf($owner);

        self::assertIsArray($result);
        self::assertSame(['complete', 1], [$result['status'] ?? null, $result['keys_destroyed'] ?? null]);
        self::assertCount(1, $keys);
        self::assertSame([KeyState::ERASED, $result['erasure_id'] ?? null], [$keys[0]->state, $keys[0]->erasureId]);
    }

    /**
     * Put the database on a file SQLite can share across a fork, in WAL mode,
     * as the operations guidance advises: a creation that read before an
     * erasure's commit then fails its insert as busy, and a reader never holds
     * back a writer's commit.
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
     * Create the owner's key in the category through the key creator, and say
     * what came of it: a key made or found, none, or one of the two documented
     * ways a creation fails closed, which drop the field it was for: SQLite's
     * busy insert, and a wait for the owner's lock that ran out. Anything else
     * thrown is a fault, rethrown so the test fails.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return string
     *
     * @throws \Throwable
     */
    private function create(Reference $owner): string
    {
        try {
            return $this->keyCreator()->create(new KeyUnit($owner, null, self::CATEGORY)) === null ? self::NONE : self::MADE;
        } catch (OwnerLockTimeoutException) {
            return self::TIMED_OUT;
        } catch (QueryException $exception) {
            return self::busy($exception);
        }
    }

    /**
     * What a creation that failed a statement writes: busy when it found
     * SQLite's database busy; any other failure is rethrown.
     *
     * @param  \Illuminate\Database\QueryException  $exception
     * @return string
     *
     * @throws \Illuminate\Database\QueryException
     */
    private static function busy(QueryException $exception): string
    {
        if (!self::isBusy($exception)) {
            throw $exception;
        }

        return self::BUSY;
    }

    /**
     * Whether the failed statement found SQLite's database busy: its driver
     * code `SQLITE_BUSY` or `SQLITE_BUSY_SNAPSHOT`, or its message saying the
     * database is locked.
     *
     * @param  \Illuminate\Database\QueryException  $exception
     * @return bool
     */
    private static function isBusy(QueryException $exception): bool
    {
        if (DB::connection(StorageConnection::name())->getDriverName() !== 'sqlite') {
            return false;
        }

        $code = $exception->errorInfo[1] ?? null;

        return in_array($code, self::SQLITE_BUSY, true) || str_contains($exception->getMessage(), 'database is locked');
    }

    /**
     * Make every connection the parent establishes from now on, the key session
     * among them, default its transactions to `repeatable read`, as a server or
     * role setting would.
     *
     * @param  string  $driver
     * @return void
     */
    private function defaultToRepeatableRead(string $driver): void
    {
        $statement = $driver === 'pgsql'
            ? 'set session characteristics as transaction isolation level repeatable read'
            : 'set session transaction isolation level repeatable read';

        Event::listen(ConnectionEstablished::class, static function (ConnectionEstablished $event) use ($statement): void {
            $event->connection->statement($statement);
        });
    }

    /**
     * Erase the owner, all or nothing, with the eraser the container builds.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult
     */
    private function erase(Reference $owner): ErasureResult
    {
        return app(Eraser::class)->erase('01932b4e-9000-7000-8000-0000000000a1', $owner, new Authority(Reference::of('App\Models\User', '7'), 'case.review'), false, false);
    }

    /**
     * In a child: once the erasure's first statement after the owner's lock,
     * the read of the owner's marker, has run, open the held gate, wait for the
     * release gate, and keep the locks briefly after it.
     *
     * @return void
     */
    private function pauseOnceTheOwnerIsLocked(): void
    {
        $paused  = false;
        $pattern = '/^select .* from \W?' . preg_quote(KeyTables::ownerErasuresTable(), '/') . '\W/';

        DB::listen(function (QueryExecuted $query) use (&$paused, $pattern): void {
            if ($paused || preg_match($pattern, $query->sql) !== 1) {
                return;
            }

            $paused = true;

            $this->openGate(self::HELD);
            $this->awaitGate(self::RELEASE);

            usleep(self::HOLD_MICROSECONDS);
        });
    }

    /**
     * In a child: just before the erasure's lifecycle lock statement runs, open
     * the held gate and wait for the release gate.
     *
     * @return void
     */
    private function pauseBeforeTheLifecycleLock(): void
    {
        $paused = false;

        DB::connection(StorageConnection::forMaintenance())->beforeExecuting(function (string $query) use (&$paused): void {
            if ($paused || !str_starts_with($query, 'update') || !str_contains($query, 'lifecycle_lock')) {
                return;
            }

            $paused = true;

            $this->openGate(self::HELD);
            $this->awaitGate(self::RELEASE);
        });
    }

    /**
     * Open the release gate just before the creator's first statement that
     * waits on the owner, on whichever connection its key session opens:
     * MySQL's and PostgreSQL's owner's lock, or on SQLite, which takes none,
     * its read of the owner's marker.
     *
     * @return void
     */
    private function releaseAsTheCreatorAsksForTheOwner(): void
    {
        $released = false;
        $markers  = KeyTables::ownerErasuresTable();
        $release  = function (string $query) use (&$released, $markers): void {
            $asks = str_contains($query, 'get_lock(') || str_contains($query, 'pg_advisory_xact_lock(') || str_contains($query, $markers);

            if ($released || !$asks) {
                return;
            }

            $released = true;

            $this->openGate(self::RELEASE);
        };

        DB::connection(StorageConnection::name())->beforeExecuting($release);

        Event::listen(ConnectionEstablished::class, static function (ConnectionEstablished $event) use ($release): void {
            $event->connection->beforeExecuting($release);
        });
    }

    /**
     * Every key of the owner, in id order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>
     */
    private function keysOf(Reference $owner): array
    {
        return array_values(array_filter($this->storedSubjectKeys(), static fn (SubjectKeyRow $key): bool => $key->ownerId === $owner->id && $key->ownerType === $owner->type));
    }

    /**
     * The owner the single races erase.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(): Reference
    {
        return Reference::of('App\Models\User', '42');
    }
}
