<?php

declare(strict_types = 1);

namespace Tests\Integration\Integrity;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\SealCommand;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\VerificationSummary;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalPruneLedger;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneChunk;
use SineMacula\Laravel\AuditLog\Lifecycle\Pruner;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneResult;
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
 * Integration tests for the pruner killed by `SIGKILL` at every boundary of a
 * chunk and its run; each starts from three anchored seals of `finance`,
 * `security` and `audit` entries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Pruner::class)]
#[CoversClass(PruneChunk::class)]
#[CoversClass(Verifier::class)]
#[CoversClass(SegmentVerifier::class)]
final class PruneBoundariesTest extends TestCase
{
    use RunsKilledChildren, SealsEntries, WritesTheJournal;

    /** @var string When every seal of the setup is made and anchored. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When every prune runs, and every later seal is made: a day after the entries' cut-off. */
    private const string PRUNED_AT = '2026-11-03 10:00:00';

    /** @var string When every verification runs: past the anchoring grace of every seal. */
    private const string VERIFIED_AT = '2026-11-03T11:00:00.000000Z';

    /** @var list<string> The category of each seal's entries, by its place. */
    private const array CATEGORIES = ['finance', 'security', 'audit'];

    /** @var string The operation every hold and release is placed under. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string The disk the anchor writes to. */
    private const string DISK = 'anchors';

    /** @var string A lock statement, as the engine is sent it. */
    private const string LOCK = '/^update \W?audit_log_lifecycle_lock\W/';

    /** @var string An insert of a journal row, as the engine is sent it. */
    private const string JOURNAL_INSERT = '/^insert into \W?audit_log_lifecycle\W/';

    /** @var int The top-level commit of a run's first chunk: its start's is the first. */
    private const int CHUNK_COMMIT = 2;

    /** @var int The top-level commit of a run's finish when it pruned one chunk. */
    private const int FINISH_COMMIT = 3;

    /** @var array<string, array{0: string, 1: int, 2: bool}> Each boundary of a run's start before its commit: the statement, which of them, and whether the kill comes before it. */
    private const array START_BOUNDARIES = [
        'before the start lock' => [self::LOCK, 1, true],
        'after the start lock'  => [self::LOCK, 1, false],
        'after the policy row'  => [self::JOURNAL_INSERT, 1, false],
        'after the start row'   => [self::JOURNAL_INSERT, 2, false],
        'as the start commits'  => ['committing', 1, false],
    ];

    /** @var array<string, array{0: string, 1: int, 2: bool}> Each boundary of a chunk before its commit: the statement, which of them, and whether the kill comes before it. */
    private const array BOUNDARIES = [
        'before the lock'            => [self::LOCK, 2, true],
        'after the lock'             => [self::LOCK, 2, false],
        'after the candidate read'   => ['/^select \* from \W?audit_log_entries\W? where \W?id\W? in/', 1, false],
        'after the artifacts delete' => ['/^delete from \W?audit_log_artifacts\W/', 1, false],
        'after the receipts delete'  => ['/^delete from \W?audit_log_deliveries\W/', 1, false],
        'after the entries delete'   => ['/^delete from \W?audit_log_entries\W/', 1, false],
        'after the journal row'      => ['prune row', 1, false],
        'before the commit'          => ['committing', self::CHUNK_COMMIT, false],
    ];

    /** @var ?string The directory the anchor's disk is rooted at. */
    private ?string $anchorRoot = null;

    /**
     * Bind a shared disk anchor, the journal's ledger and the policy, and make
     * three anchored seals of two entries each.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new SealCommand);

        CarbonImmutable::setTestNow(self::SEALED_AT);

        $this->anchorRoot = rtrim($this->childFile(''), '/') . '-anchors';

        $disk = Storage::build(['driver' => 'local', 'root' => $this->anchorRoot]);

        app()->bind(PruneLedger::class, JournalPruneLedger::class);
        app()->bind(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
        app()->instance(CheckpointAnchor::class, new DiskAnchor($disk, self::DISK, 'audit-log-anchors', app(SealSettings::class)->logId()));

        foreach (self::CATEGORIES as $minute => $category) {
            $this->storeOf($category, 2, sprintf('2026-11-01 12:%02d:00', $minute));

            self::assertSame(0, Artisan::call('audit-log:seal'), Artisan::output());
        }

        self::assertCount(3, $this->seals());

        CarbonImmutable::setTestNow(self::PRUNED_AT);
    }

    /**
     * Put the clock back, remove the anchor's disk, and remove what the
     * children shared once the migrations have rolled back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        if ($this->anchorRoot !== null) {
            (new Filesystem)->deleteDirectory($this->anchorRoot);
        }

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * Rows of `[boundary]`: every boundary of a run's start before its
     * transaction commits.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUncommittedStarts(): iterable
    {
        foreach (array_keys(self::START_BOUNDARIES) as $boundary) {
            yield $boundary => [$boundary];
        }
    }

    /**
     * A prune killed before its start commits journals and deletes nothing, and
     * the next run prunes the segment.
     *
     * @param  string  $boundary
     * @return void
     */
    #[DataProvider('provideUncommittedStarts')]
    public function testACrashBeforeThePruneCommitsLeavesTheSegmentValid(string $boundary): void
    {
        $this->retainForADay('security');

        $this->assertKilled($this->runChild(function () use ($boundary): void {
            $this->killAt(...self::START_BOUNDARIES[$boundary]);

            app(Pruner::class)->run();
        }));

        self::assertSame([2, []], [$this->entriesLeftOf(2), $this->kinds()]);

        $this->assertSegments(['valid', 'valid', 'valid']);

        self::assertSame(2, $this->prune()->deleted);
        self::assertSame(['policy', 'prune_run', 'prune', 'prune_run'], $this->kinds());

        $this->assertSegments(['valid', 'pruned', 'valid']);
    }

    /**
     * A prune killed after its finish row commits has journalled the whole run,
     * and the next run starts again from the first seal.
     *
     * @return void
     */
    public function testACommittedPruneIsPruned(): void
    {
        $this->retainForADay('security');

        $this->assertKilled($this->runChild(function (): void {
            $this->killAt('committed', self::FINISH_COMMIT, false);

            app(Pruner::class)->run();
        }));

        self::assertSame([0, ['policy', 'prune_run', 'prune', 'prune_run']], [$this->entriesLeftOf(2), $this->kinds()]);
        self::assertNull(app(IntegrityProgress::class)->get(IntegrityProgress::RETENTION_LAST_RUN));

        $this->assertSegments(['valid', 'pruned', 'valid']);

        CarbonImmutable::setTestNow('2026-11-03 10:10:00');

        $next = $this->prune();

        self::assertSame([0, 3], [$next->deleted, $next->cursor]);
        self::assertSame(0, $this->runStarts()[1]['resume_from'] ?? null);
    }

    /**
     * A segment pruned by two runs around a hold is `pruned` after each, with
     * disjoint records.
     *
     * @return void
     */
    public function testTwoPrunesOfOneSegmentArePruned(): void
    {
        $this->retainForADay('security');

        $members = self::sorted($this->membersOf($this->sealIdOf(2)));
        $window  = HoldScope::all()->occurredBetween(new CarbonImmutable('2026-11-01 12:01:00.000001', 'UTC'), null);
        $hold    = app(HoldKeeper::class)->place(self::OPERATION, $window, self::authority(), HoldBasis::LEGAL_CLAIM, null);

        self::assertSame([1, 1], [$this->prune()->deleted, $this->entriesLeftOf(2)]);

        $this->assertSegments(['valid', 'pruned', 'valid']);

        app(HoldKeeper::class)->release(self::OPERATION, $hold->id, self::authority());

        self::assertSame(1, $this->prune()->deleted);

        $this->assertSegments(['valid', 'pruned', 'valid']);

        self::assertSame([0, 2], [$this->entriesLeftOf(2), $this->recordsOf(2)]);
        self::assertSame($members, self::sorted($this->membersOf($this->sealIdOf(2))));
    }

    /**
     * Rows of `[boundary]`: every boundary of a chunk before its transaction
     * commits.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUncommittedBoundaries(): iterable
    {
        foreach (array_keys(self::BOUNDARIES) as $boundary) {
            yield $boundary => [$boundary];
        }
    }

    /**
     * A prune killed before its chunk commits leaves the segment `valid`, and
     * the next run passes over the killed start and prunes it.
     *
     * @param  string  $boundary
     * @return void
     */
    #[DataProvider('provideUncommittedBoundaries')]
    public function testACrashBeforeAChunkCommitsLeavesTheSegmentValid(string $boundary): void
    {
        $this->retainForADay('security');

        $this->assertKilled($this->runChild(function () use ($boundary): void {
            $this->killAt(...self::BOUNDARIES[$boundary]);

            app(Pruner::class)->run();
        }));

        self::assertSame([2, 0], [$this->entriesLeftOf(2), $this->pruneRows()]);
        self::assertSame(['policy', 'prune_run'], $this->kinds());

        $this->assertSegments(['valid', 'valid', 'valid']);

        self::assertSame(2, $this->prune()->deleted);

        $this->assertSegments(['valid', 'pruned', 'valid']);
    }

    /**
     * A prune killed after its chunk commits, before its finish row, leaves the
     * segment `pruned` and anchored, and the run passes.
     *
     * @return void
     */
    public function testACommittedChunkIsPruned(): void
    {
        $this->retainForADay('security');

        $members = $this->membersOf($this->sealIdOf(2));

        $this->assertKilled($this->runChild(function (): void {
            $this->killAt('committed', self::CHUNK_COMMIT, false);

            app(Pruner::class)->run();
        }));

        self::assertSame([0, 1], [$this->entriesLeftOf(2), $this->pruneRows()]);
        self::assertSame($members, $this->membersOf($this->sealIdOf(2)));
        self::assertSame(['policy', 'prune_run', 'prune'], $this->kinds());

        $this->assertSegments(['valid', 'pruned', 'valid']);
    }

    /**
     * The next run passes over a killed run's start, resumes after the last
     * finished run's cursor and prunes what is left.
     *
     * @return void
     */
    public function testACrashAfterTheStartRowIsResumedFromTheLastFinishedRunsCursor(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.after_days', 1);

        $this->moveClockOnTheFirstPruneRow('2026-11-03 10:01:01');

        $stopped = app(Pruner::class)->run(false, 60);

        self::assertSame([2, 1, 2], [$stopped->deleted, $stopped->cursor, $stopped->remaining]);

        // Each process runs at a time of its own, later than any before, so the
        // ids it draws never repeat those of a process it was forked from
        $this->assertKilled($this->runChild(function (): void {
            CarbonImmutable::setTestNow('2026-11-03 10:05:00');

            $this->killAt('committed', self::CHUNK_COMMIT, false);

            app(Pruner::class)->run();
        }));

        CarbonImmutable::setTestNow('2026-11-03 10:10:00');

        self::assertSame([0, 0, 2], [$this->entriesLeftOf(1), $this->entriesLeftOf(2), $this->entriesLeftOf(3)]);

        $resumed = $this->prune();

        self::assertSame([2, 3, 0], [$resumed->deleted, $resumed->cursor, $resumed->remaining]);
        self::assertSame([1, 1, 1], [$this->recordsOf(1), $this->recordsOf(2), $this->recordsOf(3)]);
        self::assertSame(1, $this->runStarts()[2]['resume_from'] ?? null);

        $this->assertSegments(['pruned', 'pruned', 'pruned']);
    }

    /**
     * A segment whose pruned entries were put back is `resurrected`, and a
     * later change to one is `tampered`, the worse finding.
     *
     * @return void
     */
    public function testARecordWithoutItsDeletionIsResurrected(): void
    {
        $this->retainForADay('security');

        $rows = $this->rowsOf(2);

        self::assertSame(2, $this->prune()->deleted);

        DB::connection(StorageConnection::name())->table(EntrySettings::table())->insert($rows);

        $first   = self::sorted($this->membersOf($this->sealIdOf(2)))[0];
        $summary = $this->assertSegments(['valid', 'incomplete', 'valid'], false);

        self::assertSame(['resurrected', $first], [$summary->firstFinding?->value, $summary->firstBadId]);

        $changed = $this->membersOf($this->sealIdOf(2))[1];

        DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $changed)->update(['event' => 'invoice.forged']);

        $summary = $this->assertSegments(['valid', 'tampered', 'valid'], false);

        self::assertSame(['entry_hmac', $changed], [$summary->firstFinding?->value, $summary->firstBadId]);
    }

    /**
     * A prune of the last seal keeps its checkpoint, so the next seal still
     * chains onto it.
     *
     * @return void
     */
    public function testAPrunedHeadIsStillExtendedAndAnchored(): void
    {
        $this->retainForADay('audit');

        $this->assertKilled($this->runChild(function (): void {
            $this->killAt('committed', self::CHUNK_COMMIT, false);

            app(Pruner::class)->run();
        }));

        self::assertSame(['policy', 'prune_run', 'prune'], $this->kinds());

        $this->storeOf('finance', 2, '2026-11-03 09:00:00');

        $this->assertSegments(['valid', 'valid', 'pruned', 'valid']);

        $seals = $this->seals();

        self::assertSame($seals[2]['seal_digest'], $seals[3]['previous_digest']);
    }

    /**
     * Entries deleted without a record are `incomplete` yet still anchored, and
     * the run fails.
     *
     * @return void
     */
    public function testADeletionWithoutItsRecordIsIncomplete(): void
    {
        $first = self::sorted($this->membersOf($this->sealIdOf(2)))[0];

        $this->assertKilled($this->runChild(function (): void {
            DB::connection(StorageConnection::forMaintenance())->table(EntrySettings::table())->whereIn('id', $this->membersOf($this->sealIdOf(2)))->delete();
        }));

        self::assertSame([0, 0], [$this->entriesLeftOf(2), $this->pruneRows()]);

        $summary = $this->assertSegments(['valid', 'incomplete', 'valid'], false);

        self::assertSame(['missing_entry', $first], [$summary->firstFinding?->value, $summary->firstBadId]);
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
     * Kill this process before or after the given occurrence of the matching
     * statement; `prune row`, `committing` and `committed` name a chunk's prune
     * row insert and its commit.
     *
     * @param  string  $pattern
     * @param  int  $occurrence
     * @param  bool  $before
     * @return void
     */
    private function killAt(string $pattern, int $occurrence, bool $before): void
    {
        if ($before) {
            self::killBefore($pattern, $occurrence);

            return;
        }

        if ($pattern === 'committing' || $pattern === 'committed') {
            self::killAtTheCommit($pattern === 'committing', $occurrence);

            return;
        }

        $seen = 0;

        DB::listen(static function (QueryExecuted $query) use ($pattern, $occurrence, &$seen): void {
            $matches = $pattern === 'prune row' ? self::isPruneRowInsert($query) : preg_match($pattern, $query->sql) === 1;

            if (!$matches || ++$seen !== $occurrence) {
                return;
            }

            self::killThisProcess();
        });
    }

    /**
     * Kill this process just before the occurrence given of the statement the
     * pattern matches runs on the maintenance connection.
     *
     * @param  string  $pattern
     * @param  int  $occurrence
     * @return void
     */
    private static function killBefore(string $pattern, int $occurrence): void
    {
        $seen = 0;

        DB::connection(StorageConnection::forMaintenance())->beforeExecuting(static function (string $query) use ($pattern, $occurrence, &$seen): void {
            if (preg_match($pattern, $query) !== 1 || ++$seen !== $occurrence) {
                return;
            }

            self::killThisProcess();
        });
    }

    /**
     * Kill this process as the given top-level transaction commits, or once it
     * has: the start first, then each chunk, then the finish.
     *
     * @param  bool  $committing
     * @param  int  $occurrence
     * @return void
     */
    private static function killAtTheCommit(bool $committing, int $occurrence): void
    {
        $seen  = 0;
        $event = $committing ? TransactionCommitting::class : TransactionCommitted::class;
        $level = $committing ? 1 : 0;

        // The outermost transaction is still open as it commits, and closed
        // once it has
        Event::listen($event, static function (TransactionCommitted|TransactionCommitting $event) use ($level, $occurrence, &$seen): void {
            if ($event->connection->transactionLevel() !== $level || ++$seen !== $occurrence) {
                return;
            }

            self::killThisProcess();
        });
    }

    /**
     * Whether the statement is the insert of a chunk's prune row.
     *
     * @param  \Illuminate\Database\Events\QueryExecuted  $query
     * @return bool
     */
    private static function isPruneRowInsert(QueryExecuted $query): bool
    {
        return str_starts_with($query->sql, 'insert') && str_contains($query->sql, LifecycleTables::journalTable()) && in_array(JournalKind::PRUNE->value, $query->bindings, true);
    }

    /**
     * Move the clock to the instant once the first chunk has written its prune
     * row.
     *
     * @param  string  $instant
     * @return void
     */
    private function moveClockOnTheFirstPruneRow(string $instant): void
    {
        $moved = false;

        DB::listen(static function (QueryExecuted $query) use ($instant, &$moved): void {
            if ($moved || !self::isPruneRowInsert($query)) {
                return;
            }

            $moved = true;

            CarbonImmutable::setTestNow($instant);
        });
    }

    /**
     * How many prune rows the journal holds for the seal at the sequence.
     *
     * @param  int  $sequence
     * @return int
     */
    private function recordsOf(int $sequence): int
    {
        $sealId = $this->sealIdOf($sequence);

        return count(array_filter($this->journalRows(), static fn (array $row): bool => $row['kind'] === JournalKind::PRUNE->value && $row['seal_id'] === $sealId));
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
     * Keep the category's entries a day, and every other forever.
     *
     * @param  string  $category
     * @return void
     */
    private function retainForADay(string $category): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.categories', [$category => 1]);
    }

    /**
     * Run a prune.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\PruneResult
     */
    private function prune(): PruneResult
    {
        return app(Pruner::class)->run();
    }

    /**
     * Seal, verify, and assert each segment's integrity in order, every seal
     * anchored, and whether the strict run passes.
     *
     * @param  list<string>  $integrity
     * @param  bool  $passes
     * @return \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary
     */
    private function assertSegments(array $integrity, bool $passes = true): VerificationSummary
    {
        self::assertSame(0, Artisan::call('audit-log:seal'), Artisan::output());

        $now = CarbonImmutable::now();

        CarbonImmutable::setTestNow(self::VERIFIED_AT);

        /** @var \ArrayObject<int, array{0: string, 1: string}> $segments */
        $segments = new \ArrayObject;

        try {
            $summary = app(Verifier::class)->verify(VerificationRange::whole(), static function (SegmentReport $report) use ($segments): void {
                $segments->append([$report->integrity->value, $report->anchoring->value]);
            });
        } finally {
            CarbonImmutable::setTestNow($now);
        }

        $count = count($integrity);

        self::assertSame(array_map(static fn (string $status): array => [$status, 'anchored'], $integrity), $segments->getArrayCopy());
        self::assertSame($count, $summary->remoteHead);
        self::assertSame(range(1, $count), array_map(static fn (array $seal): int => (int) $seal['sequence'], $this->seals()));
        self::assertSame(!$passes, $summary->fails(true));

        return $summary;
    }

    /**
     * Store the number of captured records of the category from the given UTC
     * time, a microsecond apart.
     *
     * @param  string  $category
     * @param  int  $count
     * @param  string  $at
     * @return void
     */
    private function storeOf(string $category, int $count, string $at): void
    {
        $first = new CarbonImmutable($at, 'UTC');

        for ($index = 0; $index < $count; $index++) {
            $instant   = $first->addMicroseconds($index);
            $record    = RecordFactory::withFields(['category' => $category, 'occurred_at' => $instant->format('Y-m-d\TH:i:s.u\Z')]);
            $finalised = (new RecordFinaliser(FrozenClock::at($instant->format('Y-m-d H:i:s.u')), app(RecordSigner::class)))->finalise($record);

            app(DatabaseAuditStore::class)->store($finalised);
        }
    }

    /**
     * The stored rows of the entries the seal at the sequence holds, as raw
     * rows, so a test can put them back.
     *
     * @param  int  $sequence
     * @return list<array<string, scalar|null>>
     */
    private function rowsOf(int $sequence): array
    {
        $rows = DB::connection(StorageConnection::name())->table(EntrySettings::table())->whereIn('id', $this->membersOf($this->sealIdOf($sequence)))->get()->all();

        /** @var list<array<string, scalar|null>> $raw */
        $raw = array_map(static fn (object $row): array => (array) $row, $rows);

        return $raw;
    }

    /**
     * The ids sorted bytewise, as the members are.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private static function sorted(array $ids): array
    {
        usort($ids, strcmp(...));

        return $ids;
    }

    /**
     * How many of the entries the seal at the sequence holds are still stored.
     *
     * @param  int  $sequence
     * @return int
     */
    private function entriesLeftOf(int $sequence): int
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table())->whereIn('id', $this->membersOf($this->sealIdOf($sequence)))->count();
    }

    /**
     * How many prune rows the journal holds.
     *
     * @return int
     */
    private function pruneRows(): int
    {
        return count(array_filter($this->kinds(), static fn (string $kind): bool => $kind === JournalKind::PRUNE->value));
    }

    /**
     * The kinds of the journal's rows, in order.
     *
     * @return list<string>
     */
    private function kinds(): array
    {
        return array_map(static fn (array $row): string => (string) $row['kind'], $this->journalRows());
    }

    /**
     * The payloads of the run rows of phase `start`, in order.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return list<array<array-key, mixed>>
     */
    private function runStarts(): array
    {
        $payloads = array_map(
            static fn (array $row): array => JournalRow::fromRow($row, true)->payloadMap() ?? [],
            array_values(array_filter($this->journalRows(), static fn (array $row): bool => $row['kind'] === JournalKind::PRUNE_RUN->value)),
        );

        return array_values(array_filter($payloads, static fn (array $payload): bool => ($payload['phase'] ?? null) === 'start'));
    }

    /**
     * The id of the stored seal at the sequence.
     *
     * @param  int  $sequence
     * @return string
     */
    private function sealIdOf(int $sequence): string
    {
        return (string) $this->seals()[$sequence - 1]['id'];
    }
}
