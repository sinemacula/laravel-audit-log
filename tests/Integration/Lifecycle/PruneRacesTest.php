<?php

declare(strict_types = 1);

namespace Tests\Integration\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalPruneLedger;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneChunk;
use SineMacula\Laravel\AuditLog\Lifecycle\Pruner;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Integration tests for prunes racing holds, releases and each other in
 * processes of their own; no entry held before a chunk's lock is deleted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Pruner::class)]
#[CoversClass(PruneChunk::class)]
final class PruneRacesTest extends TestCase
{
    use RunsKilledChildren, SealsEntries, WritesTheJournal;

    /** @var string When every run starts. */
    private const string NOW = '2026-12-15 15:00:00';

    /** @var string When every entry is recorded. */
    private const string RECORDED_AT = '2026-12-02 12:00:00';

    /** @var string When every seal is made. */
    private const string SEALED_AT = '2026-12-02 13:00:00';

    /** @var string When every entry happened: past its thirty days. */
    private const string OLD = '2026-11-01T10:00:00.000000Z';

    /** @var string The operation every hold and release is placed under. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string The gate a pruning child opens once it reached its chunk's lock, before the phase's name. */
    private const string ARRIVED = 'arrived-';

    /** @var string The gate that lets a pruning child go on, before the phase's name. */
    private const string RELEASE = 'release-';

    /** @var string The file a pruning child writes its result to. */
    private const string RESULTS = 'results';

    /** @var int How long a pruning child keeps the lock once released, in microseconds, so a broken lock would be overtaken. */
    private const int HOLD_MICROSECONDS = 200000;

    /** @var int The lock statement of a run's first chunk: the start's is the first. */
    private const int CHUNK_LOCK = 2;

    /**
     * Stop the clock, keep thirty days, and store and seal the entries.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        app(ConfigRepository::class)->set('audit-log.retention.after_days', 30);
        app()->bind(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
        app()->bind(PruneLedger::class, JournalPruneLedger::class);

        $this->sealAt(self::SEALED_AT);

        for ($index = 0; $index < 3; $index++) {
            $this->storeEntry();
        }

        $this->sealAll();
    }

    /**
     * Put the clock back and remove the children's files after the rollback.
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
     * A hold racing a prune never loses an entry held before the chunk's lock.
     *
     * @return void
     */
    public function testAHoldRacingAPruneNeverLosesAHeldRow(): void
    {
        $child = $this->startPruneThatWaits(true, 'first', 1);

        $this->awaitGate(self::ARRIVED . 'first');
        $this->hold();
        $this->openGate(self::RELEASE . 'first');
        $this->assertKilled($this->waitForChild($child));

        self::assertSame([0, 3], $this->deletedAndHeld());
        self::assertSame(3, $this->entriesLeft());
        $this->assertNoHeldEntryWasDeleted();

        $this->release(app(HoldKeeper::class)->active()[0]);

        $child = $this->startPruneThatWaits(false, 'second', 2);

        $this->awaitGate(self::ARRIVED . 'second');
        $this->releaseAsTheLockIsAskedFor('second');
        $this->hold();
        $this->assertKilled($this->waitForChild($child));

        self::assertSame([3, 0], $this->deletedAndHeld());
        self::assertSame(0, $this->entriesLeft());
        $this->assertNoHeldEntryWasDeleted();
    }

    /**
     * Two prunes racing over one seal never cover a member twice.
     *
     * @return void
     */
    public function testTwoPrunesNeverCoverOneMemberTwice(): void
    {
        $first  = $this->startPruneThatWaits(true, 'first', 1);
        $second = $this->startPruneThatWaits(true, 'second', 2);

        $this->awaitGate(self::ARRIVED . 'first');
        $this->awaitGate(self::ARRIVED . 'second');
        $this->openGate(self::RELEASE . 'first');
        $this->openGate(self::RELEASE . 'second');

        $this->assertKilled($this->waitForChild($first));
        $this->assertKilled($this->waitForChild($second));

        $positions = array_merge(...array_map(static fn (PruneRecord $record): array => $record->positions(), $this->records()));

        self::assertSame(0, $this->entriesLeft());
        self::assertSame([0, 1, 2], $positions);
        self::assertSame(3, array_sum(array_column($this->results(), 'deleted')));
        self::assertSame(['pruned'], $this->verifiedSegments());
    }

    /**
     * A release racing a prune is ordered by the lock.
     *
     * @return void
     */
    public function testAReleaseRacingAPruneIsOrdered(): void
    {
        $hold  = $this->hold();
        $child = $this->startPruneThatWaits(false, 'first', 1);

        $this->awaitGate(self::ARRIVED . 'first');
        $this->releaseAsTheLockIsAskedFor('first');
        $this->release($hold);
        $this->assertKilled($this->waitForChild($child));

        self::assertSame([0, 3], $this->deletedAndHeld());
        self::assertSame(3, $this->entriesLeft());
        self::assertSame(3, app(Pruner::class)->run()->deleted);

        for ($index = 0; $index < 3; $index++) {
            $this->storeEntry();
        }

        $this->sealAll();

        $hold  = $this->hold();
        $child = $this->startPruneThatWaits(true, 'second', 2);

        $this->awaitGate(self::ARRIVED . 'second');
        $this->release($hold);
        $this->openGate(self::RELEASE . 'second');
        $this->assertKilled($this->waitForChild($child));

        self::assertSame([3, 0], $this->deletedAndHeld());
        self::assertSame(0, $this->entriesLeft());
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
     * Start a pruning child that meets the phase's gates at the chunk lock; its
     * clock runs ahead so its ids never repeat this process's.
     *
     * @param  bool  $before
     * @param  string  $phase
     * @param  int  $seconds
     * @return int
     */
    private function startPruneThatWaits(bool $before, string $phase, int $seconds): int
    {
        return $this->startChild(function () use ($before, $phase, $seconds): void {
            CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds($seconds));

            self::pauseAtTheChunkLock($before, function () use ($phase, $before): void {
                $this->openGate(self::ARRIVED . $phase);
                $this->awaitGate(self::RELEASE . $phase);

                usleep($before ? 0 : self::HOLD_MICROSECONDS);
            });

            $this->appendToChildFile(self::RESULTS, (string) json_encode(app(Pruner::class)->run()->toArray()));
        });
    }

    /**
     * Run the pause just before or just after the first chunk's lock.
     *
     * @param  bool  $before
     * @param  \Closure(): void  $pause
     * @return void
     */
    private static function pauseAtTheChunkLock(bool $before, \Closure $pause): void
    {
        $locks   = 0;
        $pattern = '/^update \W?' . preg_quote(LifecycleTables::lockTable(), '/') . '\W/';
        $count   = static function (string $sql) use (&$locks, $pattern, $pause): void {
            if (preg_match($pattern, $sql) !== 1 || ++$locks !== self::CHUNK_LOCK) {
                return;
            }

            $pause();
        };

        if ($before) {
            DB::connection(StorageConnection::forMaintenance())->beforeExecuting(static fn (string $query) => $count($query));

            return;
        }

        DB::listen(static fn (QueryExecuted $query) => $count($query->sql));
    }

    /**
     * Open the phase's release gate as this process asks for the lock.
     *
     * @param  string  $phase
     * @return void
     */
    private function releaseAsTheLockIsAskedFor(string $phase): void
    {
        $released = false;
        $pattern  = '/^update \W?' . preg_quote(LifecycleTables::lockTable(), '/') . '\W/';

        $this->maintenance()->beforeExecuting(function (string $query) use (&$released, $pattern, $phase): void {
            if ($released || preg_match($pattern, $query) !== 1) {
                return;
            }

            $released = true;

            $this->openGate(self::RELEASE . $phase);
        });
    }

    /**
     * Assert no entry held before a chunk's lock was deleted.
     *
     * @return void
     */
    private function assertNoHeldEntryWasDeleted(): void
    {
        $rows  = array_map(static fn (array $row): JournalRow => JournalRow::fromRow($row, false), $this->journalRows());
        $prune = array_values(array_filter($rows, static fn (JournalRow $row): bool => $row->kind === JournalKind::PRUNE));
        $holds = array_values(array_filter($rows, static fn (JournalRow $row): bool => $row->kind === JournalKind::HOLD));

        foreach ($prune as $pruneRow) {
            foreach ($holds as $holdRow) {
                $placedAfter = $holdRow->sequence > $pruneRow->sequence;
                $released    = array_filter($rows, static fn (JournalRow $row): bool => $row->kind === JournalKind::RELEASE && $row->holdId === $holdRow->holdId);
                $before      = array_filter($released, static fn (JournalRow $row): bool => $row->sequence < $pruneRow->sequence);

                self::assertTrue($placedAfter || $before !== [], 'A prune deleted entries a hold held before its lock.');
            }
        }
    }

    /**
     * What the last pruning child deleted and found held.
     *
     * @return array{0: int, 1: int}
     */
    private function deletedAndHeld(): array
    {
        $results = $this->results();
        $last    = end($results);

        self::assertIsArray($last);

        return [(int) $last['deleted'], (int) $last['held']];
    }

    /**
     * The results the pruning children wrote, in order.
     *
     * @return list<array<string, bool|int|string|null>>
     */
    private function results(): array
    {
        /** @var list<array<string, bool|int|string|null>> $results */
        $results = array_map(static fn (string $line): array => (array) json_decode($line, true), $this->childFileLines(self::RESULTS));

        return $results;
    }

    /**
     * Every prune record the journal holds, in order.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>
     */
    private function records(): array
    {
        $rows = array_filter($this->journalRows(), static fn (array $row): bool => $row['kind'] === JournalKind::PRUNE->value);

        return array_values(array_map(static function (array $row): PruneRecord {
            $payload = JournalRow::fromRow($row, true)->payloadMap() ?? [];

            self::assertIsArray($payload['record'] ?? null);

            return PruneRecord::fromArray($payload['record']);
        }, $rows));
    }

    /**
     * Verify the whole log through the journal's ledger.
     *
     * @return list<string>
     */
    private function verifiedSegments(): array
    {
        /** @var \ArrayObject<int, string> $segments */
        $segments = new \ArrayObject;

        app(Verifier::class)->verify(VerificationRange::whole(), static function (SegmentReport $report) use ($segments): void {
            $segments->append($report->integrity->value);
        });

        return array_values($segments->getArrayCopy());
    }

    /**
     * Place a hold of every entry, and return it.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Hold
     */
    private function hold(): Hold
    {
        return app(HoldKeeper::class)->place(self::OPERATION, HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM, null);
    }

    /**
     * Release the hold.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Hold  $hold
     * @return void
     */
    private function release(Hold $hold): void
    {
        app(HoldKeeper::class)->release(self::OPERATION, $hold->id, self::authority());
    }

    /**
     * The authority every hold and release is made under.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review');
    }

    /**
     * Store a captured record past its retention, recorded at the test's time.
     *
     * @return void
     */
    private function storeEntry(): void
    {
        $finaliser = new RecordFinaliser(FrozenClock::at(self::RECORDED_AT), app(RecordSigner::class));

        app(DatabaseAuditStore::class)->store($finaliser->finalise(RecordFactory::withFields(['occurred_at' => self::OLD])));
    }

    /**
     * How many entries are left.
     *
     * @return int
     */
    private function entriesLeft(): int
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table())->count();
    }

    /**
     * The maintenance connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function maintenance(): Connection
    {
        return DB::connection(StorageConnection::forMaintenance());
    }
}
