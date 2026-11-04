<?php

declare(strict_types = 1);

namespace Tests\Integration\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Eraser;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\RunsKilledChildren;
use Tests\TestCase;

/**
 * Integration tests for erasures racing holds and each other, in processes of
 * their own, on whichever engine the suite runs against and on a file database
 * on SQLite. The lifecycle lock orders them: a hold committed before the
 * erasure's lock blocks it, an erasure committed first stands and the hold that
 * waited for its lock follows it in the journal, and two erasures of one owner
 * destroy each key once, the second finding the owner already erased.
 *
 * The processes meet on file gates rather than on timing; a pause inside a held
 * lock only makes an overtaking likely should the lock fail, and no assertion
 * measures time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Eraser::class)]
final class ErasureRacesTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail, RunsKilledChildren;

    /** @var string When every capture and erasure runs, before a child moves its clock on. */
    private const string NOW = '2026-11-04 10:00:00.000000';

    /** @var string The gate a child opens once it reached its lock, before the phase's name. */
    private const string ARRIVED = 'arrived-';

    /** @var string The gate that lets a child go on, before the phase's name. */
    private const string RELEASE = 'release-';

    /** @var string The file a child writes its result to. */
    private const string RESULTS = 'results';

    /** @var int How long a child keeps the lock once released, in microseconds, so a broken lock would be overtaken. */
    private const int HOLD_MICROSECONDS = 200000;

    /** @var string The category every key and entry is in. */
    private const string CATEGORY = 'finance';

    /**
     * Stop the clock, bind the package's key wrapper, and store an entry
     * encrypted under each of the owner's two keys.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $this->keyWrapper();

        foreach ([self::tenant(), Reference::of('organisation', 'org_02')] as $tenant) {
            [$key] = $this->makeSubjectKey(self::owner(), $tenant, self::CATEGORY);

            $this->seedEntry(['tenant_id' => $tenant->id, 'properties' => ['card' => ['v' => 1, 'k' => $key->id, 'c' => 'Y2lwaGVydGV4dA']]], id: Str::uuid7()->toString());
        }
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
     * A hold committed while the erasure waits for the lock is committed first:
     * the erasure, reading the chain after its lock, sees the hold and is
     * refused, and every key stays live.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHoldCommittedFirstBlocksTheErasure(): void
    {
        $child = $this->startChild(function (): void {
            CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(1));

            $this->pauseOnceLocked('hold');

            $hold = app(HoldKeeper::class)->place('01932b4e-9000-7000-8000-0000000000b1', HoldScope::tenants(self::tenant()), self::authority(), HoldBasis::LEGAL_CLAIM, null);

            $this->appendToChildFile(self::RESULTS, $hold->id);
        });

        $this->awaitGate(self::ARRIVED . 'hold');
        $this->releaseAsTheLockIsAskedFor('hold');

        $refusal = null;

        try {
            app(Eraser::class)->erase('01932b4e-9000-7000-8000-0000000000a1', self::owner(), self::authority(), false, false);
        } catch (ErasureRefusedException $exception) {
            $refusal = $exception;
        }

        $this->assertKilled($this->waitForChild($child));

        self::assertNotNull($refusal, 'The erasure was not refused.');
        self::assertSame(ErasureRefusal::BLOCKED, $refusal->refusal());
        self::assertSame(['held:' . $this->childFileLines(self::RESULTS)[0]], $refusal->reasons());
        self::assertSame([KeyState::LIVE, KeyState::LIVE], $this->states());
        self::assertSame([JournalKind::HOLD], $this->kinds());
    }

    /**
     * An erasure committed while a hold waits for the lock stands: every key is
     * destroyed, and the hold commits after it, later in the journal.
     *
     * @return void
     */
    public function testAnErasureCommittedFirstStandsAndTheHoldFollows(): void
    {
        $child = $this->startChild(function (): void {
            CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(1));

            $this->pauseOnceLocked('erasure');

            $result = app(Eraser::class)->erase('01932b4e-9000-7000-8000-0000000000a1', self::owner(), self::authority(), false, false);

            $this->appendToChildFile(self::RESULTS, (string) json_encode($result->toArray()));
        });

        $this->awaitGate(self::ARRIVED . 'erasure');
        $this->releaseAsTheLockIsAskedFor('erasure');

        app(HoldKeeper::class)->place('01932b4e-9000-7000-8000-0000000000b1', HoldScope::tenants(self::tenant()), self::authority(), HoldBasis::LEGAL_CLAIM, null);

        $this->assertKilled($this->waitForChild($child));

        $result = json_decode($this->childFileLines(self::RESULTS)[0], true);

        self::assertIsArray($result);
        self::assertSame(['complete', 2], [$result['status'] ?? null, $result['keys_destroyed'] ?? null]);
        self::assertSame([KeyState::ERASED, KeyState::ERASED], $this->states());
        self::assertSame([JournalKind::ERASURE, JournalKind::HOLD], $this->kinds());
    }

    /**
     * Two erasures of one owner destroy each key once: whichever takes the lock
     * first destroys every key, and the other finds the owner already erased
     * and writes nothing.
     *
     * @return void
     */
    public function testTwoErasuresOfOneOwnerDestroyEachKeyOnce(): void
    {
        $children = [];

        foreach (['first' => 1, 'second' => 2] as $phase => $seconds) {
            $children[] = $this->startChild(function () use ($phase, $seconds): void {
                CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds($seconds));

                $this->pauseBeforeTheLock($phase);

                $result = app(Eraser::class)->erase(sprintf('01932b4e-9000-7000-8000-0000000000a%d', $seconds), self::owner(), self::authority(), false, false);

                $this->appendToChildFile(self::RESULTS, (string) json_encode($result->toArray()));
            });
        }

        $this->awaitGate(self::ARRIVED . 'first');
        $this->awaitGate(self::ARRIVED . 'second');
        $this->openGate(self::RELEASE . 'first');
        $this->openGate(self::RELEASE . 'second');

        foreach ($children as $child) {
            $this->assertKilled($this->waitForChild($child));
        }

        $results  = array_map(static fn (string $line): array => (array) json_decode($line, true), $this->childFileLines(self::RESULTS));
        $statuses = array_column($results, 'status');

        sort($statuses);

        $erasures = array_values(array_filter($this->journalRows(), static fn (array $row): bool => $row['kind'] === JournalKind::ERASURE->value));

        self::assertSame(['already_erased', 'complete'], $statuses);
        self::assertSame(2, array_sum(array_column($results, 'keys_destroyed')));
        self::assertCount(1, $erasures);

        foreach ($this->storedSubjectKeys() as $key) {
            self::assertSame([KeyState::ERASED, $erasures[0]['id']], [$key->state, $key->erasureId]);
        }
    }

    /**
     * Put the database on a file SQLite can share across a fork.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->useFileDatabaseOnSqlite($app);
    }

    /**
     * In a child: once its lock statement has run, inside the transaction, open
     * the phase's arrival gate, wait for its release gate, and keep the lock
     * briefly after it.
     *
     * @param  string  $phase
     * @return void
     */
    private function pauseOnceLocked(string $phase): void
    {
        $paused  = false;
        $pattern = self::lockPattern();

        DB::listen(function (QueryExecuted $query) use (&$paused, $pattern, $phase): void {
            if ($paused || preg_match($pattern, $query->sql) !== 1) {
                return;
            }

            $paused = true;

            $this->openGate(self::ARRIVED . $phase);
            $this->awaitGate(self::RELEASE . $phase);

            usleep(self::HOLD_MICROSECONDS);
        });
    }

    /**
     * In a child: just before its lock statement runs, open the phase's arrival
     * gate and wait for its release gate.
     *
     * @param  string  $phase
     * @return void
     */
    private function pauseBeforeTheLock(string $phase): void
    {
        $paused  = false;
        $pattern = self::lockPattern();

        DB::connection(StorageConnection::forMaintenance())->beforeExecuting(function (string $query) use (&$paused, $pattern, $phase): void {
            if ($paused || preg_match($pattern, $query) !== 1) {
                return;
            }

            $paused = true;

            $this->openGate(self::ARRIVED . $phase);
            $this->awaitGate(self::RELEASE . $phase);
        });
    }

    /**
     * Open the phase's release gate just before this process's next lock
     * statement runs, so the child goes on to commit while this process waits
     * for the lock.
     *
     * @param  string  $phase
     * @return void
     */
    private function releaseAsTheLockIsAskedFor(string $phase): void
    {
        $released = false;
        $pattern  = self::lockPattern();

        DB::connection(StorageConnection::forMaintenance())->beforeExecuting(function (string $query) use (&$released, $pattern, $phase): void {
            if ($released || preg_match($pattern, $query) !== 1) {
                return;
            }

            $released = true;

            $this->openGate(self::RELEASE . $phase);
        });
    }

    /**
     * The pattern of the lifecycle lock's statement.
     *
     * @return string
     */
    private static function lockPattern(): string
    {
        return '/^update \W?' . preg_quote(LifecycleTables::lockTable(), '/') . '\W/';
    }

    /**
     * The state of every key, in id order.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState>
     */
    private function states(): array
    {
        return array_values(array_map(static fn (SubjectKeyRow $key): KeyState => $key->state, $this->storedSubjectKeys()));
    }

    /**
     * The kind of every journal row, in order.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind>
     */
    private function kinds(): array
    {
        return array_map(static fn (array $row): JournalKind => JournalRow::fromRow($row, false)->kind, $this->journalRows());
    }

    /**
     * The owner every race erases.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(): Reference
    {
        return Reference::of('user', '42');
    }

    /**
     * The tenant the held entry is for.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function tenant(): Reference
    {
        return Reference::of('organisation', 'org_01');
    }

    /**
     * The authority every erasure and hold is made with.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('user', '7'), 'case.review');
    }
}
