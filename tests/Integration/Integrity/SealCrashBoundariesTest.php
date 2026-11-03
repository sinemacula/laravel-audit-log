<?php

declare(strict_types = 1);

namespace Tests\Integration\Integrity;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\SealCommand;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor;
use SineMacula\Laravel\AuditLog\Integrity\CheckpointWriter;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\Sealer;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SealsEntries;
use Tests\TestCase;

/**
 * Integration tests for a sealer killed by `SIGKILL` at every boundary of a
 * seal, on whichever engine the suite runs against: before the head is read,
 * after the selection, before and after the checkpoint's insert, between two
 * chunks of its members, before and after the commit, before its progress is
 * written, in a later batch of a run and in the middle of a sweep. A kill
 * before the commit leaves nothing of the seal, since the engine rolls the
 * attempt back whole; a kill after it keeps the seal, its progress stale until
 * the next run overwrites it. After every kill a run of `audit-log:seal` leaves
 * every entry a member of exactly one seal, the sequences contiguous from 1,
 * every segment `valid` and every seal anchored.
 *
 * Every test starts from one anchored seal, so each kill falls on a seal that
 * extends the chain.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Sealer::class)]
#[CoversClass(CheckpointWriter::class)]
#[CoversClass(SealCommand::class)]
final class SealCrashBoundariesTest extends TestCase
{
    use RunsKilledChildren, SealsEntries;

    /** @var string When every seal of a test is made. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When every verification runs: past the anchoring grace of every seal, and within the allowed age of every entry. */
    private const string VERIFIED_AT = '2026-11-01T14:00:00.000000Z';

    /** @var string When the first of the entries the killed run seals is recorded, after those of the first seal. */
    private const string LATER = '2026-11-01 12:10:00.000000';

    /** @var string When the entries stored after a kill are recorded, after every other. */
    private const string LATEST = '2026-11-01 12:20:00.000000';

    /** @var int The entries a seal holds at most in the tests of several batches. */
    private const int BATCH = 100;

    /** @var string The disk the anchor writes to. */
    private const string DISK = 'anchors';

    /** @var string The namespace on the disk the anchor writes under. */
    private const string PATH = 'audit-log-anchors';

    /** @var string The read of the head inside the attempt's transaction. */
    private const string HEAD = '/^select \* from \S*audit_log_checkpoints\S* where \S*sequence\S* >= 1 order by/';

    /** @var string The selection of the recent pass's candidates. */
    private const string SELECTION = '/^select .* from \S*audit_log_entries\S* as \S*e\S* left join/';

    /** @var string The insert of a checkpoint. */
    private const string CHECKPOINT = '/^insert into \S*audit_log_checkpoints\S* /';

    /** @var string The insert of the checkpoint's fourth seal. */
    private const string FOURTH_CHECKPOINT = '/^insert into \S*audit_log_checkpoints\S* .* values \(\'[0-9a-f-]{36}\', 4, /';

    /** @var string The insert of a chunk of members. */
    private const string MEMBERS = '/^insert into \S*audit_log_checkpoint_members/';

    /** @var string The commit of the attempt's transaction, the first of the run. */
    private const string COMMIT = '/^commit$/';

    /** @var string The write of the last seal's progress. */
    private const string SEAL_PROGRESS = '/^insert into \S*audit_log_integrity_state\S* .*\'seal\.last\'/';

    /** @var string A sweep's window: entries read through a derived table. */
    private const string WINDOW = '/^select .* from \(select /';

    /** @var string The sweep's third window: the one after the 197th entry the killed run seals. */
    private const string THIRD_WINDOW = '/^select .* from \(select .*12:10:00\.000196/';

    /** @var string The write of the sweep's cursor after its second window. */
    private const string SECOND_CURSOR = '/^insert into \S*audit_log_integrity_state\S* .*\'sweep\.cursor\'.*12:10:00\.000196/';

    /** @var ?string The directory the anchor's disk is rooted at, once a test made one. */
    private ?string $anchorRoot = null;

    /**
     * Register the command, stop the clock, bind a disk anchor every process
     * shares and no prune ledger, and make the first seal and anchor it.
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

        app()->instance(PruneLedger::class, new NullPruneLedger);

        $this->bindADiskAnchor();
        $this->storeEntries(3);

        self::assertSame(0, Artisan::call('audit-log:seal'), Artisan::output());
        self::assertSame(['1'], $this->anchoredSequences());
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
     * A sealer killed before its transaction reads the head leaves nothing, and
     * the next run seals every entry.
     *
     * @return void
     */
    public function testACrashBeforeTheHeadReadLeavesNothing(): void
    {
        $this->storeEntries(5, self::LATER);

        $this->assertKilled($this->runChild(fn () => $this->sealer()->seal(), killBefore: self::HEAD));

        $this->assertLeavesNothing();
        $this->assertRecovers();
    }

    /**
     * A sealer killed once it has selected its candidates, before it writes,
     * leaves nothing, and the next run seals every entry.
     *
     * @return void
     */
    public function testACrashAfterTheSelectionLeavesNothing(): void
    {
        $this->storeEntries(5, self::LATER);

        $this->assertKilled($this->runChild(fn () => $this->sealer()->seal(), killAfter: self::SELECTION));

        $this->assertLeavesNothing();
        $this->assertRecovers();
    }

    /**
     * A sealer killed just before it inserts the checkpoint leaves nothing, and
     * the next run seals every entry.
     *
     * @return void
     */
    public function testACrashBeforeTheCheckpointInsertLeavesNothing(): void
    {
        $this->storeEntries(5, self::LATER);

        $this->assertKilled($this->runChild(fn () => $this->sealer()->seal(), killBefore: self::CHECKPOINT));

        $this->assertLeavesNothing();
        $this->assertRecovers();
    }

    /**
     * A sealer killed once the checkpoint is inserted, before any of its
     * members, leaves no checkpoint, since the insert never committed, and the
     * next run seals every entry under the sequence the lost one had.
     *
     * @return void
     */
    public function testACrashBetweenTheCheckpointAndItsMembersLeavesNothing(): void
    {
        $this->storeEntries(5, self::LATER);

        $this->assertKilled($this->runChild(fn () => $this->sealer()->seal(), killAfter: self::CHECKPOINT));

        $this->assertLeavesNothing();
        $this->assertRecovers();

        self::assertCount(2, $this->seals());
    }

    /**
     * A sealer of 601 entries in one seal, killed after the first of its three
     * chunks of members, leaves neither the checkpoint nor that chunk, and the
     * next run seals all 601 in one seal.
     *
     * @return void
     */
    public function testACrashBetweenMemberChunksLeavesNothing(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.seal.batch', 601);

        $this->storeEntries(601, self::LATER);

        $this->assertKilled($this->runChild(fn () => $this->sealer()->seal(), killAfter: self::MEMBERS));

        $this->assertLeavesNothing();
        $this->assertRecovers();

        self::assertSame(601, (int) $this->seals()[1]['member_count']);
    }

    /**
     * A sealer killed as it commits, every statement of its seal written,
     * leaves nothing, and the next run seals every entry.
     *
     * @return void
     */
    public function testACrashBeforeTheCommitLeavesNothing(): void
    {
        $this->storeEntries(5, self::LATER);

        $this->assertKilled($this->runChild(function (): void {
            Event::listen(TransactionCommitting::class, static function (): void {
                self::killThisProcess();
            });

            $this->sealer()->seal();
        }));

        $this->assertLeavesNothing();
        $this->assertRecovers();
    }

    /**
     * A sealer killed straight after its commit keeps the seal, chained onto
     * the first, with every member, though its progress still names the first
     * seal and nothing anchored it; the next run anchors it and seals nothing
     * more.
     *
     * @return void
     */
    public function testACrashAfterTheCommitKeepsTheSeal(): void
    {
        $ids = $this->storeEntries(5, self::LATER);

        $this->assertKilled($this->runChild(fn () => $this->sealer()->seal(), killAfter: self::COMMIT));

        $seals = $this->seals();

        self::assertCount(2, $seals);
        self::assertSame($seals[0]['seal_digest'], $seals[1]['previous_digest']);
        self::assertSame(self::sorted($ids), $this->membersOf((string) $seals[1]['id']));
        self::assertSame(1, $this->lastSealProgress());
        self::assertSame(['1'], $this->anchoredSequences());

        $this->assertRecovers();

        self::assertCount(2, $this->seals());
    }

    /**
     * A sealer killed after its commit, before it records the seal in progress,
     * leaves that progress naming the seal before; progress is never evidence,
     * so the log verifies, and the next run's seal overwrites it.
     *
     * @return void
     */
    public function testACrashBeforeTheProgressWriteIsCaughtUpByTheNextRun(): void
    {
        $this->storeEntries(5, self::LATER);

        $this->assertKilled($this->runChild(fn () => $this->sealer()->seal(), killBefore: self::SEAL_PROGRESS));

        self::assertCount(2, $this->seals());
        self::assertSame(1, $this->lastSealProgress());

        $this->storeEntries(2, self::LATEST);
        $this->assertRecovers();

        self::assertCount(3, $this->seals());
        self::assertSame(3, $this->lastSealProgress());
    }

    /**
     * A sweep killed before its third window, two windows sealed and its cursor
     * saved after the second, keeps both seals, and the next sweep resumes from
     * that cursor, never from the beginning, and completes.
     *
     * @return void
     */
    public function testACrashMidSweepResumesFromTheSavedCursor(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.seal.batch', self::BATCH);

        $ids = $this->storeEntries(250, self::LATER);

        $this->assertKilled($this->runChild(fn () => $this->sealer()->sweep(), killBefore: self::THIRD_WINDOW));

        self::assertCount(3, $this->seals());
        self::assertSame($ids[196], $this->sweepCursor()['id'] ?? null);

        $windows = $this->windowsOf(fn () => $this->assertRecovers(['--sweep' => true]));

        self::assertMatchesRegularExpression('/12:10:00\.000196/', $windows[0]);
        self::assertCount(4, $this->seals());
        self::assertNull($this->sweepCursor());
        self::assertNotNull(app(IntegrityProgress::class)->get(IntegrityProgress::SWEEP_COMPLETED));
    }

    /**
     * A sweep killed after its second window committed, before it saved its
     * cursor past that window, resumes from the cursor before it: it reads the
     * window again, finds it sealed, seals nothing of it twice, and completes.
     *
     * @return void
     */
    public function testACrashBeforeTheSweepSavesItsCursorReadsTheWindowAgain(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.seal.batch', self::BATCH);

        $ids = $this->storeEntries(250, self::LATER);

        $this->assertKilled($this->runChild(fn () => $this->sealer()->sweep(), killBefore: self::SECOND_CURSOR));

        self::assertCount(3, $this->seals());
        self::assertSame($ids[96], $this->sweepCursor()['id'] ?? null);

        $windows = $this->windowsOf(fn () => $this->assertRecovers(['--sweep' => true]));

        self::assertMatchesRegularExpression('/12:10:00\.000096/', $windows[0]);
        self::assertCount(4, $this->seals());
        self::assertNull($this->sweepCursor());
    }

    /**
     * A run killed in its third batch, before that batch's checkpoint, keeps
     * the two seals its earlier batches committed and their progress, and the
     * next run seals what is left onto them.
     *
     * @return void
     */
    public function testACrashInALaterBatchKeepsTheSealsBeforeIt(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.seal.batch', self::BATCH);

        $this->storeEntries(250, self::LATER);

        $this->assertKilled($this->runChild(fn () => $this->sealer()->seal(), killBefore: self::FOURTH_CHECKPOINT));

        self::assertSame(['100', '100'], array_map(static fn (array $seal): string => (string) $seal['member_count'], array_slice($this->seals(), 1)));
        self::assertSame(3, $this->lastSealProgress());

        $this->assertRecovers();

        self::assertSame('50', (string) $this->seals()[3]['member_count']);
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
     * Assert the kill left nothing of the seal it was making: the first seal
     * alone, its members alone, and its progress.
     *
     * @return void
     */
    private function assertLeavesNothing(): void
    {
        $seals = $this->seals();

        self::assertCount(1, $seals, 'A seal the kill interrupted was kept.');
        self::assertCount(3, $this->memberIds(), 'A member the kill interrupted was kept.');
        self::assertSame(1, $this->lastSealProgress());
    }

    /**
     * Run `audit-log:seal` with the options and assert it succeeds and leaves
     * the log whole: every entry a member of exactly one seal, the sequences
     * contiguous from 1, and on verification, strict, every segment `valid` and
     * anchored, the anchor's head the last seal.
     *
     * @param  array<string, bool>  $options
     * @return void
     */
    private function assertRecovers(array $options = []): void
    {
        self::assertSame(0, Artisan::call('audit-log:seal', $options), Artisan::output());

        $entries = DB::connection(StorageConnection::name())->table(EntrySettings::table())->pluck('id')->all();
        $seals   = $this->seals();
        $count   = count($seals);

        self::assertSame(self::sorted($entries), $this->memberIds(), 'An entry is not a member of exactly one seal.');
        self::assertSame(range(1, $count), array_map(static fn (array $seal): int => (int) $seal['sequence'], $seals));

        CarbonImmutable::setTestNow(self::VERIFIED_AT);

        $reports = new \ArrayObject;
        $summary = app(Verifier::class)->verify(VerificationRange::whole(), static function (SegmentReport $report) use ($reports): void {
            $reports->append([$report->integrity->value, $report->anchoring->value]);
        });

        CarbonImmutable::setTestNow(self::SEALED_AT);

        self::assertSame(array_fill(0, $count, ['valid', 'anchored']), $reports->getArrayCopy());
        self::assertSame([AnchorStatus::ANCHORED, $count], [$summary->remote, $summary->remoteHead]);
        self::assertFalse($summary->fails(true));
    }

    /**
     * Run the work and return every sweep window it read, in order.
     *
     * @param  \Closure(): void  $work
     * @return list<string>
     */
    private function windowsOf(\Closure $work): array
    {
        $windows = new \ArrayObject;

        DB::listen(static function (QueryExecuted $event) use ($windows): void {
            $statement = $event->toRawSql();

            if (preg_match(self::WINDOW, $statement) !== 1) {
                return;
            }

            $windows->append($statement);
        });

        $work();

        /** @var list<string> */
        return $windows->getArrayCopy();
    }

    /**
     * Bind a disk anchor on a local disk of this test's own, beside the files
     * its processes share, which a child writes to and this process reads.
     *
     * @return void
     */
    private function bindADiskAnchor(): void
    {
        $this->anchorRoot = rtrim($this->childFile(''), '/') . '-anchors';

        $disk = Storage::build(['driver' => 'local', 'root' => $this->anchorRoot]);

        app()->instance(CheckpointAnchor::class, new DiskAnchor($disk, self::DISK, self::PATH, app(SealSettings::class)->logId()));
    }

    /**
     * The sequences of the anchored seals, in order, as the engine returns
     * them, as text.
     *
     * @return list<string>
     */
    private function anchoredSequences(): array
    {
        $anchored = array_filter($this->seals(), static fn (array $seal): bool => $seal['anchored_at'] !== null);

        return array_values(array_map(static fn (array $seal): string => (string) $seal['sequence'], $anchored));
    }

    /**
     * The sequence the last seal's progress names, or `null` when there is
     * none.
     *
     * @return ?int
     */
    private function lastSealProgress(): ?int
    {
        $sequence = app(IntegrityProgress::class)->get(IntegrityProgress::SEAL_LAST)['sequence'] ?? null;

        return $sequence === null ? null : (int) $sequence;
    }

    /**
     * The sweep's saved cursor, or `null` when none is saved.
     *
     * @return ?array<string, scalar|null>
     */
    private function sweepCursor(): ?array
    {
        return app(IntegrityProgress::class)->get(IntegrityProgress::SWEEP_CURSOR);
    }

    /**
     * The entry id of every member row, in byte order.
     *
     * @return list<string>
     */
    private function memberIds(): array
    {
        /** @var list<string> $ids */
        $ids = DB::connection(StorageConnection::name())->table(IntegrityTables::membersTable())->pluck('entry_id')->all();

        return self::sorted($ids);
    }

    /**
     * The ids in byte order.
     *
     * @param  array<array-key, string>  $ids
     * @return list<string>
     */
    private static function sorted(array $ids): array
    {
        $sorted = array_values(array_map(strval(...), $ids));

        sort($sorted, SORT_STRING);

        return $sorted;
    }
}
