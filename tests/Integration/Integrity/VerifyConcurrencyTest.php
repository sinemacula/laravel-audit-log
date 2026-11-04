<?php

declare(strict_types = 1);

namespace Tests\Integration\Integrity;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;
use SineMacula\Laravel\AuditLog\Integrity\Anchorer;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\PruneBitmap;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\VerificationSummary;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Integrity\RecordingAnchor;
use Tests\Fixtures\Integrity\TableBackedPruneLedger;
use Tests\TestCase;

/**
 * Integration tests for verification racing the work that changes the log in
 * another process, on whichever engine the suite runs against: a seal committed
 * once the run has read the head is never read; a prune that deletes a
 * segment's entries and writes its signed record in one transaction is seen
 * whole or not at all, and one that commits after the members are read is found
 * by the ledger and the reread that follow, so the segment is `valid` or
 * `pruned` and never `incomplete`, neither `missing_entry` nor `resurrected`;
 * anchoring meanwhile never fails a run; and a strict run beside a seal run
 * that has sealed and not yet anchored passes, its new seal awaiting its first
 * anchoring.
 *
 * Each run streams its reports and keeps none; these tests keep them to
 * compare. SQLite runs in WAL mode, as the operations guidance advises, so a
 * reader never blocks another process's commit. The processes meet on file
 * gates rather than on timing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Verifier::class)]
#[CoversClass(SegmentVerifier::class)]
final class VerifyConcurrencyTest extends TestCase
{
    use RunsKilledChildren, SealsEntries;

    /** @var string When every sealer of a test runs, unless a test says otherwise. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When a run begins, unless a test says otherwise: past the anchoring grace of every seal, and within the allowed age of every entry. */
    private const string VERIFIED_AT = '2026-11-01T14:00:00.000000Z';

    /** @var string The id of the prune operation every prune record names. */
    private const string OPERATION_ID = '01932b4e-a000-7000-8000-000000000001';

    /** @var string When every prune runs. */
    private const string PRUNED_AT = '2026-11-01T13:30:00.000000Z';

    /** @var string The disk a disk anchor writes to. */
    private const string DISK = 'anchors';

    /** @var string The gate a process opens once it has reached where it is held. */
    private const string ARRIVED = 'arrived';

    /** @var string The gate that lets a held process go on. */
    private const string RELEASE = 'release';

    /** @var string The gate a child opens once its work has committed. */
    private const string DONE = 'done';

    /** @var string The file the seal run's child leaves what its anchor holds in. */
    private const string HELD = 'held';

    /** @var list<\SineMacula\Laravel\AuditLog\Integrity\SegmentReport> The reports the last run streamed, in order. */
    private array $streamed = [];

    /** @var ?string The directory a disk anchor's disk is rooted at, once a test made one. */
    private ?string $anchorRoot = null;

    /**
     * Seal on a fixed clock, and bind no anchor and no prune ledger unless a
     * test binds its own.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->sealAt(self::SEALED_AT);

        CarbonImmutable::setTestNow(self::VERIFIED_AT);

        app()->instance(CheckpointAnchor::class, new NullAnchor);
        app()->instance(PruneLedger::class, new NullPruneLedger);
    }

    /**
     * Put the clock back, drop the prune ledger's table and the anchor's disk,
     * and remove what the children shared once the migrations have rolled back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        app(TableBackedPruneLedger::class)->dropTable();

        if ($this->anchorRoot !== null) {
            (new Filesystem)->deleteDirectory($this->anchorRoot);
        }

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * A seal committed by another process once the run has read the head is
     * never read: the run checks the seals up to the head it read, all of them
     * `valid`, and the next run checks the new seal too.
     *
     * @return void
     */
    public function testSealsCreatedDuringVerificationAreSkipped(): void
    {
        $this->storeSeals(2);
        $this->storeEntries(2, '2026-11-01 12:30:00.000000');

        $child = $this->startChild(function (): void {
            $this->awaitGate(self::ARRIVED);
            $this->sealer()->seal();
            $this->openGate(self::DONE);
        });

        $this->holdAfter(static fn (QueryExecuted $event): bool => str_contains($event->sql, 'max(') && str_contains($event->sql, IntegrityTables::checkpointsTable()));

        $during = $this->verify();

        $this->assertKilled($this->waitForChild($child));

        self::assertCount(3, $this->seals());
        self::assertSame([2, 1, 2], [$during->head, $during->from, $during->to]);
        self::assertSame(['valid', 'valid'], $this->integrityOf());
        self::assertFalse($during->fails(false));

        $after = $this->verify();

        self::assertSame([3, 3], [$after->head, $after->to]);
        self::assertSame(['valid', 'valid', 'valid'], $this->integrityOf());
    }

    /**
     * Rows of `[whether the run is held after the segment's members and
     * entries are read rather than before, the segment's integrity]`: the
     * prune commits on either side of the one statement that reads them.
     *
     * @return iterable<string, array{0: bool, 1: \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus}>
     */
    public static function providePruneCommits(): iterable
    {
        yield from [
            'committed before the segment is read'             => [false, IntegrityStatus::PRUNED],
            'committed after its members and entries are read' => [true, IntegrityStatus::PRUNED],
        ];
    }

    /**
     * A prune in another process deletes a segment's entries and writes its
     * signed record in one transaction, committing while the run is held at the
     * segment: committed before its members and entries are read, the segment
     * is `pruned`; committed after, its members were read present, the ledger
     * asked after them gives the record, and the members it covers, read again,
     * are gone, so it is `pruned` too. It is never `incomplete`, and every
     * other segment stays `valid`.
     *
     * @param  bool  $afterTheRead
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus  $expected
     * @return void
     */
    #[DataProvider('providePruneCommits')]
    public function testAPruneCommittingDuringVerificationIsNeverHalfSeen(bool $afterTheRead, IntegrityStatus $expected): void
    {
        $this->storeSeals(3);

        $seal   = $this->seals()[1];
        $ledger = $this->bindTheTableBackedLedger();

        $child = $this->startChild(function () use ($seal, $ledger): void {
            $this->awaitGate(self::ARRIVED);
            $this->prune($seal, $ledger);
            $this->openGate(self::DONE);
        });

        $sealId = (string) $seal['id'];

        if ($afterTheRead) {
            $this->holdAfter(static fn (QueryExecuted $event): bool => str_contains($event->sql, IntegrityTables::membersTable()) && in_array($sealId, $event->bindings, true));
        } else {
            $this->holdBeforeTheMembersOf($sealId);
        }

        $summary = $this->verify();

        $this->assertKilled($this->waitForChild($child));

        self::assertSame(['valid', $expected->value, 'valid'], $this->integrityOf());
        self::assertFalse($summary->fails(false));

        $this->verify();

        self::assertSame(['valid', 'pruned', 'valid'], $this->integrityOf());
    }

    /**
     * A prune held open in another process, its entries deleted and its record
     * not yet written, is invisible to a run over every seal, which finds the
     * segment `valid`; once it commits, the next run finds it `pruned`. On
     * MySQL and PostgreSQL that run is a whole one. SQLite has one writer, and
     * a whole run records its completion, which would wait for the prune's, so
     * there the run is the range of every seal, which writes nothing.
     *
     * @return void
     */
    public function testAnOpenPruneIsNeverSeenByVerification(): void
    {
        $this->storeSeals(3);

        $seal   = $this->seals()[1];
        $ledger = $this->bindTheTableBackedLedger();

        $child = $this->startChild(function () use ($seal, $ledger): void {
            $this->prune($seal, $ledger, function (): void {
                $this->openGate(self::ARRIVED);
                $this->awaitGate(self::RELEASE);
            });
        });

        $this->awaitGate(self::ARRIVED);

        $sqlite = DB::connection(StorageConnection::name())->getDriverName() === 'sqlite';
        $open   = $this->verify($sqlite ? new VerificationRange(1, 3) : null);

        self::assertSame(['valid', 'valid', 'valid'], $this->integrityOf());
        self::assertFalse($open->fails(false));

        $this->openGate(self::RELEASE);

        $this->assertKilled($this->waitForChild($child));

        $this->verify();

        self::assertSame(['valid', 'pruned', 'valid'], $this->integrityOf());
    }

    /**
     * Runs made one after another while a prune in another process commits
     * whenever it does each find the segment `valid` or `pruned`, never
     * `incomplete`, and the run made once it has committed finds it `pruned`.
     * The prune is released from inside the first run, once it has read the
     * head, so at least that run is in flight when the prune starts, and the
     * loop makes more than one run.
     *
     * @return void
     */
    public function testAPruneRacingRepeatedVerificationsIsNeverHalfSeen(): void
    {
        $this->storeSeals(3);

        $seal   = $this->seals()[1];
        $ledger = $this->bindTheTableBackedLedger();

        $child = $this->startChild(function () use ($seal, $ledger): void {
            $this->awaitGate(self::ARRIVED);
            $this->prune($seal, $ledger);
            $this->openGate(self::DONE);
        });

        $released = false;

        DB::connection(StorageConnection::name())->listen(function (QueryExecuted $event) use (&$released): void {
            if ($released || !str_contains($event->sql, 'max(') || !str_contains($event->sql, IntegrityTables::checkpointsTable())) {
                return;
            }

            $released = true;

            $this->openGate(self::ARRIVED);
        });

        $seen = [];

        do {
            $done = is_file($this->childFile('gate-' . self::DONE));

            $this->verify();

            $seen[] = $this->integrityOf()[1];
        } while (!$done);

        $this->assertKilled($this->waitForChild($child));

        self::assertTrue($released);
        self::assertGreaterThan(1, count($seen));
        self::assertSame([], array_diff($seen, ['valid', 'pruned']));
        self::assertSame('pruned', $seen[array_key_last($seen)]);
    }

    /**
     * Rows of `[whether the run is held once its first segment is verified
     * rather than once it has read the head, the anchoring of each segment]`:
     * anchoring in another process records each receipt before the run reads
     * the seals, or after.
     *
     * @return iterable<string, array{0: bool, 1: list<string>}>
     */
    public static function provideAnchorings(): iterable
    {
        yield from [
            'anchored before the seals are read'           => [false, ['anchored', 'unanchored', 'unanchored']],
            'anchored after the first segment is verified' => [true, ['anchored', 'unanchored', 'unanchored']],
        ];
    }

    /**
     * A disk anchor, which every process shares, anchors the seals another
     * process left unanchored while the run is held. The anchor's head, asked
     * for first, settles the run's anchoring as it was then, so the seals
     * anchored meanwhile are `unanchored` in this run, wherever it is held; the
     * head still matches the local seal at its sequence; no segment is
     * contradicted, unavailable or short of `valid`; the run passes, and a
     * strict one would fail; and the next run, strict, finds every seal
     * anchored.
     *
     * @param  bool  $afterTheFirst
     * @param  list<string>  $expected
     * @return void
     */
    #[DataProvider('provideAnchorings')]
    public function testAnchoringDuringVerificationNeverFails(bool $afterTheFirst, array $expected): void
    {
        $this->bindADiskAnchor();
        $this->storeSeals(1);

        app(Anchorer::class)->anchorPending();

        $this->storeSeals(2);

        $child = $this->startChild(function (): void {
            $this->awaitGate(self::ARRIVED);

            app(Anchorer::class)->anchorPending();

            $this->openGate(self::DONE);
        });

        $second = (string) $this->seals()[1]['id'];

        if ($afterTheFirst) {
            $this->holdBeforeTheMembersOf($second);
        } else {
            $this->holdAfter(static fn (QueryExecuted $event): bool => str_contains($event->sql, 'max(') && str_contains($event->sql, IntegrityTables::checkpointsTable()));
        }

        $during = $this->verify();

        $this->assertKilled($this->waitForChild($child));

        self::assertSame(['valid', 'valid', 'valid'], $this->integrityOf());
        self::assertSame($expected, $this->anchoringOf());
        self::assertSame(AnchorStatus::ANCHORED, $during->remote);
        self::assertFalse($during->fails(false));
        self::assertTrue($during->fails(true));

        $after = $this->verify();

        self::assertSame(['anchored', 'anchored', 'anchored'], $this->anchoringOf());
        self::assertFalse($after->fails(true));
    }

    /**
     * A seal run in another process seals and is held before it anchors while a
     * strict run, under an anchor whose holdings the processes share through a
     * file, reads the head: the new seal is `unanchored`, awaiting its first
     * anchoring within the grace, so the strict run passes. Once the seal run
     * has anchored it, the strict run finds every seal anchored.
     *
     * @return void
     */
    public function testAStrictVerificationBesideASealRunPasses(): void
    {
        $anchor = new RecordingAnchor;

        app()->instance(CheckpointAnchor::class, self::inIssuedOrder($anchor));

        $this->sealAt('2026-11-01 12:30:00');
        $this->storeEntries(2);
        $this->sealer()->seal();

        app(Anchorer::class)->anchorPending();

        $this->storeEntries(2, '2026-11-01 12:40:00.000000');

        $child = $this->startChild(function () use ($anchor): void {
            $this->sealAt(self::SEALED_AT);
            $this->sealer()->seal();
            $this->openGate(self::ARRIVED);
            $this->awaitGate(self::RELEASE);

            app(Anchorer::class)->anchorPending();

            file_put_contents($this->childFile(self::HELD), json_encode($anchor->held(), JSON_THROW_ON_ERROR));
        });

        $this->awaitGate(self::ARRIVED);

        CarbonImmutable::setTestNow('2026-11-01T13:05:00.000000Z');

        $beside = $this->verify();

        self::assertSame([2, 1], [$beside->head, $beside->awaiting]);
        self::assertSame(['anchored', 'unanchored'], $this->anchoringOf());
        self::assertTrue($this->streamed[1]->awaitingAnchor);
        self::assertSame(AnchorStatus::ANCHORED, $beside->remote);
        self::assertFalse($beside->fails(true));

        $this->openGate(self::RELEASE);

        $this->assertKilled($this->waitForChild($child));

        /** @var array<int, string> $held */
        $held = json_decode((string) file_get_contents($this->childFile(self::HELD)), true, flags: JSON_THROW_ON_ERROR);

        foreach ($held as $sequence => $digest) {
            $anchor->holdInstead($sequence, $digest);
        }

        $after = $this->verify();

        self::assertSame(['anchored', 'anchored'], $this->anchoringOf());
        self::assertSame([2, 0], [$after->remoteHead, $after->awaiting]);
        self::assertFalse($after->fails(true));
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
     * In another process's prune: delete every entry of the seal and write the
     * signed prune record of all of them in one transaction on the maintenance
     * connection, running the hold, when given, between the two.
     *
     * @param  array<string, scalar|null>  $seal
     * @param  \Tests\Fixtures\Integrity\TableBackedPruneLedger  $ledger
     * @param  ?\Closure(): void  $hold
     * @return void
     */
    private function prune(array $seal, TableBackedPruneLedger $ledger, ?\Closure $hold = null): void
    {
        $id      = (string) $seal['id'];
        $members = $this->membersOf($id);
        $digest  = (string) $seal['seal_digest'];
        $count   = (int) $seal['member_count'];
        $record  = app(SealSigner::class)->signPrune(
            (string) $seal['log_id'],
            $id,
            $digest,
            $count,
            PruneBitmap::encode(range(0, $count - 1), $count),
            $count,
            self::OPERATION_ID,
            self::PRUNED_AT,
        );

        DB::connection(StorageConnection::forMaintenance())->transaction(static function ($connection) use ($members, $record, $ledger, $hold): void {
            $connection->table(EntrySettings::table())->whereIn('id', $members)->delete();

            if ($hold !== null) {
                $hold();
            }

            $ledger->record($record);
        });
    }

    /**
     * Hold this process just before the statement that reads the seal's members
     * and their entries, until the child is done, having let it start.
     *
     * @param  string  $sealId
     * @return void
     */
    private function holdBeforeTheMembersOf(string $sealId): void
    {
        $held = false;

        DB::connection(StorageConnection::name())->beforeExecuting(function (string $query, array $bindings) use (&$held, $sealId): void {
            if ($held || !str_contains($query, IntegrityTables::membersTable()) || !in_array($sealId, $bindings, true)) {
                return;
            }

            $held = true;

            $this->openGate(self::ARRIVED);
            $this->awaitGate(self::DONE);
        });
    }

    /**
     * Hold this process just after the first statement the match accepts has
     * run, until the child is done, having let it start.
     *
     * @param  \Closure(\Illuminate\Database\Events\QueryExecuted): bool  $matches
     * @return void
     */
    private function holdAfter(\Closure $matches): void
    {
        $held = false;

        DB::listen(function (QueryExecuted $event) use (&$held, $matches): void {
            if ($held || !$matches($event)) {
                return;
            }

            $held = true;

            $this->openGate(self::ARRIVED);
            $this->awaitGate(self::DONE);
        });
    }

    /**
     * Create the table-backed prune ledger's table and bind the ledger, so
     * verification reads the records a prune writes.
     *
     * @return \Tests\Fixtures\Integrity\TableBackedPruneLedger
     */
    private function bindTheTableBackedLedger(): TableBackedPruneLedger
    {
        $ledger = app(TableBackedPruneLedger::class);

        $ledger->createTable();

        app()->instance(PruneLedger::class, $ledger);

        return $ledger;
    }

    /**
     * Bind a disk anchor on a local disk of this test's own, beside the files
     * its processes share, which a child writes to and this process reads, as
     * every server reads one bucket.
     *
     * @return void
     */
    private function bindADiskAnchor(): void
    {
        $this->anchorRoot = rtrim($this->childFile(''), '/') . '-anchors';

        $disk = Storage::build(['driver' => 'local', 'root' => $this->anchorRoot]);

        app()->instance(CheckpointAnchor::class, new DiskAnchor($disk, self::DISK, 'audit-log-anchors', app(SealSettings::class)->logId()));
    }

    /**
     * Store and seal the number of seals, two entries each, recorded a minute
     * apart after the last.
     *
     * @param  int  $count
     * @return void
     */
    private function storeSeals(int $count): void
    {
        $first = new CarbonImmutable(self::ENTRIES_RECORDED_AT, 'UTC');
        $after = count($this->seals());

        for ($seal = 0; $seal < $count; $seal++) {
            $this->storeEntries(2, $first->addMinutes($after + $seal)->format('Y-m-d H:i:s.u'));
            $this->sealAll();
        }
    }

    /**
     * Verify the range, the whole log by default, by the verifier the container
     * builds, keeping every report the run streams.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\VerificationRange  $range
     * @return \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary
     */
    private function verify(?VerificationRange $range = null): VerificationSummary
    {
        $this->streamed = [];

        return app(Verifier::class)->verify($range ?? VerificationRange::whole(), function (SegmentReport $report): void {
            $this->streamed[] = $report;
        });
    }

    /**
     * The integrity of each segment the last run streamed, in order.
     *
     * @return list<string>
     */
    private function integrityOf(): array
    {
        return array_map(static fn (SegmentReport $report): string => $report->integrity->value, $this->streamed);
    }

    /**
     * The anchoring of each segment the last run streamed, in order.
     *
     * @return list<string>
     */
    private function anchoringOf(): array
    {
        return array_map(static fn (SegmentReport $report): string => $report->anchoring->value, $this->streamed);
    }

    /**
     * The recording anchor, handed each receipt with its keys in the order it
     * gave them and any other key after: MySQL keeps a JSON document with its
     * keys reordered, and the recording anchor compares a receipt whole, its
     * order included.
     *
     * @param  \Tests\Fixtures\Integrity\RecordingAnchor  $anchor
     * @return \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor
     */
    private static function inIssuedOrder(RecordingAnchor $anchor): CheckpointAnchor
    {
        return new readonly class ($anchor) implements CheckpointAnchor {
            /**
             * Constructor.
             *
             * @param  \Tests\Fixtures\Integrity\RecordingAnchor  $anchor
             */
            public function __construct(

                /** The anchor every call is handed to. */
                private RecordingAnchor $anchor,
            ) {}

            /**
             * The recording anchor's name.
             *
             * @return string
             */
            #[\Override]
            public function name(): string
            {
                return $this->anchor->name();
            }

            /**
             * Anchor the summary in the recording anchor.
             *
             * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
             * @return array<string, scalar|null>
             *
             * @throws \Throwable
             */
            #[\Override]
            public function anchor(SealSummary $seal): array
            {
                return $this->anchor->anchor($seal);
            }

            /**
             * Whether the recording anchor confirms the receipt, its sequence
             * and digest put first in the order they were given.
             *
             * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
             * @param  array<string, scalar|null>  $receipt
             * @return bool
             *
             * @throws \Throwable
             */
            #[\Override]
            public function confirms(SealSummary $seal, array $receipt): bool
            {
                return $this->anchor->confirms($seal, array_merge(array_intersect_key(['sequence' => null, 'digest' => null], $receipt), $receipt));
            }

            /**
             * Whether the recording anchor can report its head.
             *
             * @return bool
             */
            #[\Override]
            public function supportsDiscovery(): bool
            {
                return $this->anchor->supportsDiscovery();
            }

            /**
             * The recording anchor's head.
             *
             * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
             *
             * @throws \Throwable
             */
            #[\Override]
            public function latest(): ?AnchoredHead
            {
                return $this->anchor->latest();
            }
        };
    }
}
