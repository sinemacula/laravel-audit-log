<?php

declare(strict_types = 1);

namespace Tests\Integration\Integrity;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\CheckpointWriter;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\RunFinding;
use SineMacula\Laravel\AuditLog\Integrity\Sealer;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\VerificationSummary;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SealsEntries;
use Tests\TestCase;

/**
 * Integration tests for entries that reach the table after a later entry has
 * been sealed, on whichever engine the suite runs against, each written by
 * another process as another server would: a row that commits after a seal with
 * an earlier time joins the next seal; a row older than the lookback is left by
 * the recent pass, pending and then overdue to verification, until a sweep
 * seals it, and a sweep that already passed its place finds it on its next
 * pass; a record queued in the outbox and drained late joins a later seal; and
 * an id that sorts before every sealed id is still sealed, at the head's very
 * instant included.
 *
 * SQLite runs in WAL mode, as the operations guidance advises.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Sealer::class)]
#[CoversClass(CheckpointWriter::class)]
#[CoversClass(Verifier::class)]
final class LateArrivalsTest extends TestCase
{
    use RunsKilledChildren, SealsEntries;

    /** @var string When every sealer of a test runs. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When a verification runs, unless a test says otherwise: within the allowed age of every entry. */
    private const string VERIFIED_AT = '2026-11-01T14:00:00.000000Z';

    /** @var string When the latest entry of the first seal is recorded. */
    private const string HEAD_LAST = '2026-11-01 12:10:00.000000';

    /** @var string When a row older than the lookback before the first seal's latest entry is recorded. */
    private const string BEYOND_THE_LOOKBACK = '2026-11-01 11:00:00.000000';

    /** @var string The last instant at which that row is still pending: the allowed age after it. */
    private const string LAST_PENDING = '2026-11-02T12:00:00.000000Z';

    /** @var string The first instant at which that row is overdue. */
    private const string FIRST_OVERDUE = '2026-11-02T12:00:00.000001Z';

    /** @var string An id that sorts before every id the package generates. */
    private const string FIRST_ID = '00000000-0000-7000-8000-000000000001';

    /** @var string The gate a child opens once it has reached where it is held. */
    private const string ARRIVED = 'arrived';

    /** @var string The gate that lets a held child go on. */
    private const string RELEASE = 'release';

    /** @var string The file a child names the entry it stored in. */
    private const string IDS = 'ids';

    /** @var list<\SineMacula\Laravel\AuditLog\Integrity\SegmentReport> The reports the last verification streamed, in order. */
    private array $streamed = [];

    /**
     * Seal on a fixed clock and bind no anchor and no prune ledger, so
     * verification checks the seals alone.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->sealAt(self::SEALED_AT);

        app()->instance(CheckpointAnchor::class, new NullAnchor);
        app()->instance(PruneLedger::class, new NullPruneLedger);
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
     * A row recorded before the first seal's latest entry whose transaction, in
     * another process, commits only after that seal is not in it, and joins the
     * next one. On MySQL and PostgreSQL the transaction is open while the seal
     * is written; SQLite has one writer, so there the row is inserted once the
     * seal has committed.
     *
     * @return void
     */
    public function testARowCommittedAfterALaterSealJoinsTheNextSeal(): void
    {
        $sealed = [$this->storeEntryAt(self::ENTRIES_RECORDED_AT), $this->storeEntryAt(self::HEAD_LAST)];
        $open   = DB::connection(StorageConnection::name())->getDriverName() !== 'sqlite';

        $child = $this->startChild(function () use ($open): void {
            if (!$open) {
                $this->awaitGate(self::RELEASE);
            }

            DB::connection(StorageConnection::name())->transaction(function () use ($open): void {
                $this->appendToChildFile(self::IDS, $this->storeEntryAt('2026-11-01 12:05:00'));

                if (!$open) {
                    return;
                }

                $this->openGate(self::ARRIVED);
                $this->awaitGate(self::RELEASE);
            });
        });

        if ($open) {
            $this->awaitGate(self::ARRIVED);
        }

        $first = $this->sealer()->seal();

        $this->openGate(self::RELEASE);

        $this->assertKilled($this->waitForChild($child));

        self::assertSame(2, $first->entries());
        self::assertSame(self::sorted($sealed), $this->membersOf((string) $this->seals()[0]['id']));
        self::assertSame(1, $this->sealer()->seal()->seals());
        self::assertSame($this->childFileLines(self::IDS), $this->membersOf((string) $this->seals()[1]['id']));

        $this->assertPasses($this->verifyAt(self::VERIFIED_AT), 2);
    }

    /**
     * A row recorded further before the first seal's latest entry than the
     * lookback is never read by the recent pass. Verification calls it pending
     * up to the allowed age after it, the run still passing, and overdue a
     * microsecond later, naming it, so the run fails; the sweep seals it, and
     * verification passes again.
     *
     * @return void
     */
    public function testARowOlderThanTheLookbackWaitsForTheSweep(): void
    {
        $this->storeEntryAt(self::ENTRIES_RECORDED_AT);
        $this->storeEntryAt(self::HEAD_LAST);
        $this->sealer()->seal();

        $late = $this->storeInAnotherProcess(self::BEYOND_THE_LOOKBACK);

        self::assertSame(0, $this->sealer()->seal()->seals());

        $pending = $this->verifyAt(self::LAST_PENDING);

        self::assertSame([1, 0], [$pending->pending, $pending->overdue]);
        self::assertSame([], $pending->findings);
        self::assertFalse($pending->fails(true));

        $overdue = $this->verifyAt(self::FIRST_OVERDUE);

        self::assertSame([0, 1], [$overdue->pending, $overdue->overdue]);
        self::assertSame([Finding::OVERDUE_UNSEALED], array_map(static fn (RunFinding $finding): Finding => $finding->finding, $overdue->findings));
        self::assertSame($late, $overdue->firstBadId);
        self::assertTrue($overdue->fails(false));

        $swept = $this->sealer()->sweep();

        self::assertSame(1, $swept->seals());
        self::assertTrue($swept->isSweepComplete());
        self::assertSame([$late], $this->membersOf((string) $this->seals()[1]['id']));

        $this->assertPasses($this->verifyAt(self::FIRST_OVERDUE), 2);
    }

    /**
     * A sweep resumes from its saved cursor, so a row that arrives behind the
     * cursor, older than everything it has read, is left by the rest of that
     * pass, which still completes; the next pass starts again at the beginning
     * of the table and seals it.
     *
     * @return void
     */
    public function testARowBehindTheSweepsCursorIsSealedByItsNextPass(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.integrity.seal.batch', 100);
        $config->set('audit-log.integrity.seal.max_batches', 1);

        $this->storeEntries(250);

        self::assertFalse($this->sealer()->sweep()->isSweepComplete());

        $late = $this->storeInAnotherProcess(self::BEYOND_THE_LOOKBACK);

        self::assertFalse($this->sealer()->sweep()->isSweepComplete());

        $completed = $this->sealer()->sweep();

        self::assertTrue($completed->isSweepComplete());
        self::assertSame(3, $completed->lastSequence());
        self::assertFalse($this->isSealed($late));

        $next = $this->sealer()->sweep();

        self::assertSame(1, $next->seals());
        self::assertSame([$late], $this->membersOf((string) $this->seals()[3]['id']));

        $this->assertPasses($this->verifyAt(self::VERIFIED_AT), 4);
    }

    /**
     * A record queued in the outbox reaches the table only when a worker in
     * another process drains it, after a later entry has been sealed, with the
     * time it was recorded at, before that entry's; the next seal holds it.
     *
     * @return void
     */
    public function testAQueuedRecordDrainedLateJoinsALaterSeal(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::OUTBOX->value);

        CarbonImmutable::setTestNow('2026-11-01T12:00:00.000000Z');

        $queued = AuditLog::event('invoice.approved')->record()->id;
        $stored = $this->storeEntryAt(self::HEAD_LAST);

        self::assertSame(1, $this->sealer()->seal()->seals());
        self::assertSame([$stored], $this->membersOf((string) $this->seals()[0]['id']));
        self::assertFalse($this->entries()->where('id', $queued)->exists());

        $this->assertKilled($this->runChild(static function (): void {
            app(OutboxDrainer::class)->drain(100, false);
        }));

        $recordedAt = $this->entries()->where('id', $queued)->value('recorded_at');

        self::assertIsString($recordedAt);
        self::assertSame('2026-11-01T12:00:00.000000Z', StoredTime::fromStorage($recordedAt));
        self::assertSame(1, $this->sealer()->seal()->seals());
        self::assertSame([$queued], $this->membersOf((string) $this->seals()[1]['id']));

        $this->assertPasses($this->verifyAt(self::VERIFIED_AT), 2);
    }

    /**
     * A row stored by another process after a seal, recorded later than every
     * sealed entry, under an id that sorts before every sealed id, is still
     * sealed: the id order is never a high-water mark.
     *
     * @return void
     */
    public function testAnIdThatSortsFirstIsStillSealed(): void
    {
        $this->storeEntries(3);
        $this->sealer()->seal();

        $this->storeInAnotherProcess('2026-11-01 12:30:00.000000', self::FIRST_ID);

        self::assertSame(1, $this->sealer()->seal()->seals());
        self::assertSame([self::FIRST_ID], $this->membersOf((string) $this->seals()[1]['id']));

        $this->assertPasses($this->verifyAt(self::VERIFIED_AT), 2);
    }

    /**
     * With no lookback at all, the recent pass starts at the very instant of
     * the last seal's latest entry, so a row stored late at that instant, under
     * an id that sorts before the sealed one, is still read and sealed.
     *
     * @return void
     */
    public function testAnIdThatSortsFirstAtTheHeadsLastInstantIsStillSealed(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.seal.lookback_seconds', 0);

        $this->storeEntryAt(self::HEAD_LAST);
        $this->sealer()->seal();

        $this->storeInAnotherProcess(self::HEAD_LAST, self::FIRST_ID);

        self::assertSame(1, $this->sealer()->seal()->seals());
        self::assertSame([self::FIRST_ID], $this->membersOf((string) $this->seals()[1]['id']));

        $this->assertPasses($this->verifyAt(self::VERIFIED_AT), 2);
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
     * Store one entry recorded at the time given, under the id given or a fresh
     * one, from another process, and return its id.
     *
     * @param  string  $recordedAt
     * @param  ?string  $id
     * @return string
     */
    private function storeInAnotherProcess(string $recordedAt, ?string $id = null): string
    {
        $this->assertKilled($this->runChild(function () use ($recordedAt, $id): void {
            $this->appendToChildFile(self::IDS, $this->storeEntryAt($recordedAt, $id));
        }));

        $ids = $this->childFileLines(self::IDS);
        $id  = array_pop($ids);

        self::assertIsString($id);

        return $id;
    }

    /**
     * Verify the whole log at the instant given, by the verifier the container
     * builds, keeping every report it streams.
     *
     * @param  string  $at
     * @return \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary
     */
    private function verifyAt(string $at): VerificationSummary
    {
        CarbonImmutable::setTestNow($at);

        $this->streamed = [];

        return app(Verifier::class)->verify(VerificationRange::whole(), function (SegmentReport $report): void {
            $this->streamed[] = $report;
        });
    }

    /**
     * Assert the verification passed over the number of seals, each `valid`,
     * with no entry left unsealed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary  $summary
     * @param  int  $seals
     * @return void
     */
    private function assertPasses(VerificationSummary $summary, int $seals): void
    {
        $statuses = array_map(static fn (SegmentReport $report): IntegrityStatus => $report->integrity, $this->streamed);

        self::assertFalse($summary->fails(true));
        self::assertSame($seals, $summary->head);
        self::assertSame(array_fill(0, $seals, IntegrityStatus::VALID), $statuses);
        self::assertSame([0, 0], [$summary->pending, $summary->overdue]);
    }

    /**
     * Whether a seal holds the entry.
     *
     * @param  string  $id
     * @return bool
     */
    private function isSealed(string $id): bool
    {
        return in_array($id, array_merge(...array_map(fn (array $seal): array => $this->membersOf((string) $seal['id']), $this->seals())), true);
    }

    /**
     * A query of the entries table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function entries(): Builder
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table());
    }

    /**
     * The ids in byte order, as the members are read back.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private static function sorted(array $ids): array
    {
        usort($ids, strcmp(...));

        return $ids;
    }
}
