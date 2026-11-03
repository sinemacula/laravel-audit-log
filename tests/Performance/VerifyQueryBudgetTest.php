<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Integrity\Anchorer;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorSettings;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\CheckpointWriter;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\RunFinding;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\VerificationSummary;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;

/**
 * Statement-budget and memory contract for verification: a run of an empty log
 * reads the head and the five whole-log counts and writes its completion; each
 * segment adds one read of its members and their entries, and each page of
 * seals one more; a ranged run reads its range, its boundary and the head, and
 * writes nothing; the null prune ledger and the null anchor cost no statement,
 * and an anchor that answers costs one read of the local seal at its head; every
 * report is let go as the run goes; and the peak memory of a run follows its
 * largest segment, never the number of segments.
 *
 * Memory is measured as the growth of the peak over what the process held
 * before the run, the peak reset first, always against another run in this
 * process.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Verifier::class)]
#[CoversClass(SegmentVerifier::class)]
final class VerifyQueryBudgetTest extends PerformanceContractTestCase
{
    use SealsEntries;

    /** @var int The reads a run of the whole log makes whatever it holds: the head, the seals outside the chain, the orphaned members, and the overdue, the far-ahead and the pending entries. */
    private const int WHOLE_RUN_READS = 6;

    /** @var int How many entries a segment of the largest-segment measurement holds. */
    private const int SEGMENT_ENTRIES = 100;

    /** @var int Entries inserted by one statement, well under every engine's placeholder limit. */
    private const int INSERT_CHUNK = 20;

    /** @var string The disk a disk anchor writes to, faked for each test that anchors. */
    private const string ANCHOR_DISK = 'anchors';

    /** @var string A digest no seal has. */
    private const string OTHER_DIGEST = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /** @var string An id no seal has. */
    private const string OTHER_ID = '01932b4e-9000-7000-8000-00000000ffff';

    /** @var int How many entries the test has stored, so each next one is recorded a microsecond later. */
    private int $stored = 0;

    /** @var list<\SineMacula\Laravel\AuditLog\Integrity\SegmentReport> The reports the last run streamed, in order. */
    private array $streamed = [];

    /**
     * A run of a log with no seal and no entry reads the head and the five
     * whole-log counts, and writes its completion.
     *
     * @return void
     */
    public function testAnEmptyLogIsPinned(): void
    {
        $summary = $this->assertStatementBudget(self::WHOLE_RUN_READS, 1, 0, 0, fn (): VerificationSummary => $this->verifyLog());

        self::assertNull($summary->head);
        self::assertSame([], $this->streamed);
    }

    /**
     * Rows of `[segments]`: one, ten, and a hundred, a whole page of seals,
     * which costs a second page read to find there is no more.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideSegmentCounts(): iterable
    {
        yield from [
            'one segment'        => [1],
            'ten segments'       => [10],
            'a hundred segments' => [100],
        ];
    }

    /**
     * Each segment costs exactly one read, of its members and their entries
     * together, and each page of seals one more, on top of what an empty log
     * costs.
     *
     * @param  int  $segments
     * @return void
     */
    #[DataProvider('provideSegmentCounts')]
    public function testEachSegmentIsOneRead(int $segments): void
    {
        $this->storeSeals($segments, 1);

        $members = $this->recordMemberReads();
        $pages   = intdiv($segments, Verifier::SEAL_PAGE) + 1;
        $summary = $this->assertStatementBudget(self::WHOLE_RUN_READS + $segments + $pages, 1, 0, 0, fn (): VerificationSummary => $this->verifyLog());

        self::assertSame($segments, $summary->integrity['valid']);
        self::assertCount($segments, $members);
    }

    /**
     * Rows of `[first, last, reads]`: a range from the first seal, which has no
     * boundary to read, and one from the middle, which reads its boundary.
     *
     * @return iterable<string, array{0: int, 1: int, 2: int}>
     */
    public static function provideRanges(): iterable
    {
        yield from [
            'from the first seal' => [1, 3, 1 + 1 + 3],
            'from the middle'     => [2, 4, 1 + 1 + 1 + 3],
        ];
    }

    /**
     * A ranged run reads the head, the seal before its first when there is one,
     * one page and each segment of its range, and nothing else: no member of a
     * seal outside it, no whole-log count, and no write.
     *
     * @param  int  $from
     * @param  int  $to
     * @param  int  $reads
     * @return void
     */
    #[DataProvider('provideRanges')]
    public function testARangedRunReadsOnlyItsRangeAndBoundary(int $from, int $to, int $reads): void
    {
        $this->storeSeals(5, 1);

        $ids     = array_column($this->seals(), 'id', 'sequence');
        $members = $this->recordMemberReads();
        $summary = $this->assertStatementBudget($reads, 0, 0, 0, fn (): VerificationSummary => $this->verifyLog(new VerificationRange($from, $to)));

        self::assertFalse($summary->complete);
        self::assertSame(array_values(array_intersect_key($ids, array_flip(range($from, $to)))), $members->getArrayCopy());
    }

    /**
     * A run of the whole log writes one row, its completion in the state table,
     * and nothing else.
     *
     * @return void
     */
    public function testAFullRunWritesOnlyItsCompletion(): void
    {
        $this->storeSeals(3, 2);

        $this->assertStatementBudget(self::WHOLE_RUN_READS + 3 + 1, 1, 0, 0, fn (): VerificationSummary => $this->verifyLog());

        $writes = $this->capturedWrites();

        self::assertStringContainsString(IntegrityTables::stateTable(), $writes[0]);
        self::assertNotNull(app(IntegrityProgress::class)->get(IntegrityProgress::VERIFY_LAST_FULL));
    }

    /**
     * The null prune ledger, asked for a seal whose entry is missing, and the
     * null anchor, asked for nothing, cost no statement: the run costs what one
     * of an intact log does.
     *
     * @return void
     */
    public function testTheNullLedgerAndNullAnchorCostNothing(): void
    {
        $this->storeSeals(3, 2);

        $sealId = (string) $this->seals()[1]['id'];

        DB::connection()->table(EntrySettings::table())->where('id', $this->membersOf($sealId)[0])->delete();

        $this->assertStatementBudget(self::WHOLE_RUN_READS + 3 + 1, 1, 0, 0, fn (): VerificationSummary => $this->verifyLog());

        self::assertSame(Finding::MISSING_ENTRY, $this->streamed[1]->finding);
    }

    /**
     * An anchor that holds every seal is asked for its head alone, and the
     * local seal at that head is read once to compare it: a run under it costs
     * one read more than one under no anchor does, whatever the number of
     * seals.
     *
     * @return void
     */
    public function testAnAnchorThatAnswersCostsOneRead(): void
    {
        $this->storeSeals(3, 2);

        $anchor = $this->anchorAll();

        $summary = $this->assertStatementBudget(self::WHOLE_RUN_READS + 3 + 1 + 1, 1, 0, 0, fn (): VerificationSummary => $this->verifyLog(null, $anchor));

        self::assertSame(3, $summary->anchoring['anchored']);
    }

    /**
     * A ranged run whose range leaves out the anchor's head reads the local
     * seal at that head once, to compare it.
     *
     * @return void
     */
    public function testARemoteHeadOutsideTheRangeIsOneMoreRead(): void
    {
        $this->storeSeals(3, 2);

        $anchor = $this->anchorAll();

        $this->assertStatementBudget(1 + 1 + 2 + 1, 0, 0, 0, fn (): VerificationSummary => $this->verifyLog(new VerificationRange(1, 2), $anchor));
    }

    /**
     * An orphaned member and an overdue entry each cost one read more than a
     * log with neither, of the first of them.
     *
     * @return void
     */
    public function testEachWholeLogFindingCostsOneMoreRead(): void
    {
        $this->storeSeals(2, 2);

        $this->storeEntryAt('2026-10-30 00:00:00');

        DB::connection()->table(IntegrityTables::membersTable())->insert(['checkpoint_id' => self::OTHER_ID, 'entry_id' => self::OTHER_ID, 'hmac' => self::OTHER_DIGEST]);

        $summary = $this->assertStatementBudget(self::WHOLE_RUN_READS + 2 + 1 + 2, 1, 0, 0, fn (): VerificationSummary => $this->verifyLog());

        self::assertSame(1, $summary->overdue);
        self::assertSame([Finding::ORPHAN_MEMBER, Finding::OVERDUE_UNSEALED], array_map(static fn (RunFinding $finding): Finding => $finding->finding, $summary->findings));
    }

    /**
     * Every report is let go as the run goes: by the time a report is given to
     * the callback, none but the one before it is still held anywhere, and once
     * the run ends none is, so neither the verifier nor its summary keeps them,
     * however many segments there are.
     *
     * @return void
     */
    public function testEveryReportIsLetGoAsTheRunGoes(): void
    {
        $this->storeSeals(30, 2);

        /** @var list<\WeakReference<\SineMacula\Laravel\AuditLog\Integrity\SegmentReport>> $reports */
        $reports = [];
        $held    = [];

        $this->verifier()->verify(VerificationRange::whole(), static function (SegmentReport $report) use (&$reports, &$held): void {
            $reports[] = \WeakReference::create($report);

            foreach (array_slice($reports, 0, -2) as $index => $earlier) {
                $held[$index] = ($held[$index] ?? false) || $earlier->get() !== null;
            }
        });

        gc_collect_cycles();

        self::assertCount(30, $reports);
        self::assertSame([], array_keys(array_filter($held)), 'A report was still held two segments later.');
        self::assertSame([], array_keys(array_filter($reports, static fn (\WeakReference $report): bool => $report->get() !== null)), 'A report was held once the run ended.');
    }

    /**
     * The peak follows the largest segment alone: eight more segments as large
     * as the one there was leave it where that one put it, though the log holds
     * nine times the entries, and one segment six times as large raises it at
     * least twofold.
     *
     * @return void
     */
    public function testPeakMemoryGrowsWithTheLargestSegmentOnly(): void
    {
        $this->storeSeals(1, self::SEGMENT_ENTRIES);

        [$one] = $this->peakGrowthOfARun();

        $this->storeSeals(8, self::SEGMENT_ENTRIES);

        [$nine] = $this->peakGrowthOfARun();

        $this->storeSeals(1, 6 * self::SEGMENT_ENTRIES);

        [$larger, $segments] = $this->peakGrowthOfARun();

        self::assertSame(10, $segments);
        self::assertLessThanOrEqual(intdiv(3 * $one, 2), $nine, sprintf('Nine segments grew the peak by %d bytes, and one by %d.', $nine, $one));
        self::assertGreaterThanOrEqual(2 * $one, $larger, sprintf('A segment six times as large grew the peak by %d bytes, and one by %d.', $larger, $one));
    }

    /**
     * Run a verification of the range, the whole log by default, under the
     * anchor given or none, keeping every report it streams.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\VerificationRange  $range
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @return \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary
     */
    private function verifyLog(?VerificationRange $range = null, ?CheckpointAnchor $anchor = null): VerificationSummary
    {
        $this->streamed = [];

        return $this->verifier($anchor)->verify($range ?? VerificationRange::whole(), function (SegmentReport $report): void {
            $this->streamed[] = $report;
        });
    }

    /**
     * How much a run of the whole log grows the peak by, in bytes, and how many
     * segments it reported, holding no report: only their number is kept.
     *
     * @return array{0: int, 1: int}
     */
    private function peakGrowthOfARun(): array
    {
        $verifier = $this->verifier();
        $range    = VerificationRange::whole();
        $count    = 0;

        gc_collect_cycles();
        memory_reset_peak_usage();

        $before = memory_get_usage();

        $verifier->verify($range, static function () use (&$count): void {
            $count++;
        });

        return [memory_get_peak_usage() - $before, $count];
    }

    /**
     * A verifier from the container's collaborators, under the anchor given or
     * none, with nothing pruned.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @return \SineMacula\Laravel\AuditLog\Integrity\Verifier
     */
    private function verifier(?CheckpointAnchor $anchor = null): Verifier
    {
        $anchor ??= new NullAnchor;
        $database = app(DatabaseManager::class);
        $settings = app(SealSettings::class);
        $segments = new SegmentVerifier(app(SealSigner::class), app(RecordSigner::class), app(RowCodec::class), $settings, new NullPruneLedger, $anchor, $database);

        return new Verifier($segments, $anchor, $settings, app(IntegrityProgress::class), app(Clock::class), $database);
    }

    /**
     * Store and seal the number of seals, each of the number of entries, the
     * entries signed as the package signs them and inserted a chunk at a time,
     * each recorded a microsecond after the one before.
     *
     * @param  int  $seals
     * @param  int  $entries
     * @return void
     */
    private function storeSeals(int $seals, int $entries): void
    {
        $writer = new CheckpointWriter(app(DatabaseManager::class), app(SealSigner::class), app(SealSettings::class), app(Clock::class));
        $until  = StoredTime::format(CarbonImmutable::now());

        for ($seal = 0; $seal < $seals; $seal++) {
            $this->insertEntries($entries);

            $writer->write(null, $until, $entries);
        }
    }

    /**
     * Insert the number of finalised records as entries, a chunk at a time.
     *
     * @param  int  $count
     * @return void
     */
    private function insertEntries(int $count): void
    {
        $first = new CarbonImmutable(self::ENTRIES_RECORDED_AT, 'UTC');
        $codec = app(RowCodec::class);
        $rows  = [];

        for ($index = 0; $index < $count; $index++) {
            $instant   = StoredTime::format($first->addMicroseconds($this->stored++));
            $finaliser = new RecordFinaliser(FrozenClock::at($instant), app(RecordSigner::class));
            $rows[]    = $codec->encode($finaliser->finalise(RecordFactory::captured(occurredAt: $instant)));
        }

        foreach (array_chunk($rows, self::INSERT_CHUNK) as $chunk) {
            DB::connection()->table(EntrySettings::table())->insert($chunk);
        }
    }

    /**
     * Anchor every seal in a disk anchor on a faked disk, which reports its
     * head and reads no table, as anchoring does, and return the anchor.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor
     */
    private function anchorAll(): DiskAnchor
    {
        $anchor = new DiskAnchor(Storage::fake(self::ANCHOR_DISK), self::ANCHOR_DISK, 'audit-log-anchors', app(SealSettings::class)->logId());

        (new Anchorer($anchor, app(SealSigner::class), app(AnchorSettings::class), app(IntegrityProgress::class), app(Clock::class), app(DatabaseManager::class)))->anchorPending();

        return $anchor;
    }

    /**
     * Record the seal id of every read of a seal's members from now on, in
     * order.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordMemberReads(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $reads */
        $reads   = new \ArrayObject;
        $pattern = '/^select .* from \S*' . preg_quote(IntegrityTables::membersTable(), '/') . '\S* as m left join \S*' . preg_quote(EntrySettings::table(), '/') . '\S* as e\b/';

        DB::connection()->beforeExecuting(static function (string $query, array $bindings) use ($reads, $pattern): void {
            if (preg_match($pattern, str_replace(['"', '`'], '', $query)) !== 1) {
                return;
            }

            $reads->append((string) ($bindings[0] ?? ''));
        });

        return $reads;
    }
}
