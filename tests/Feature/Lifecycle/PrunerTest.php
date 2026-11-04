<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Sleep;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalPruneLedger;
use SineMacula\Laravel\AuditLog\Lifecycle\Pruner;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneResult;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneTally;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Querying\ClosurePolicy;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for the pruner, on whichever engine the suite runs against:
 * what it deletes and keeps (the cut-off, categories apart, holds, unsealed,
 * protected and undelivered entries, artifacts and receipts with their
 * entries), what it journals (a policy row per version, the run's start and
 * bounded finish rows, one signed prune row per chunk), where a run resumes,
 * how it stops (its time budget, a seal or candidate that fails authentication,
 * a mismatch, a policy, a broken journal), what a dry run counts and writes,
 * and its progress.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Pruner::class)]
#[CoversClass(PruneTally::class)]
#[CoversClass(PruneResult::class)]
final class PrunerTest extends TestCase
{
    use InteractsWithOutbox, SealsEntries, WritesTheJournal;

    /** @var string When every run starts, unless a test moves the clock. */
    private const string NOW = '2026-12-15 15:00:00';

    /** @var string The cut-off of a pair kept thirty days. */
    private const string CUTOFF = '2026-11-15T00:00:00.000000Z';

    /** @var string When every entry is recorded. */
    private const string RECORDED_AT = '2026-12-02 12:00:00';

    /** @var string When every seal is made. */
    private const string SEALED_AT = '2026-12-02 13:00:00';

    /** @var string When an entry past thirty days happened. */
    private const string OLD = '2026-11-01T10:00:00.000000Z';

    /** @var string When an entry within thirty days happened. */
    private const string RECENT = '2026-12-01T10:00:00.000000Z';

    /** @var string The operation every hold and release is placed under. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string The pattern of a run id: a lower-case UUID v7. */
    private const string RUN_ID = '/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/';

    /** @var ?\Tests\Fixtures\Privacy\RecordingExceptionHandler What every failure is reported to. */
    private ?RecordingExceptionHandler $reporter = null;

    /**
     * Stop the clock, keep every category thirty days, bind the configured
     * policy, the journal's ledger and a recording reporter, and seal at the
     * test's time.
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

        $this->reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $this->reporter);

        $this->sealAt(self::SEALED_AT);
    }

    /**
     * Roll back any transaction a test left open, and put the clock and the
     * sleeper back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (array_unique([StorageConnection::forMaintenance(), StorageConnection::name()]) as $name) {
            $connection = DB::connection($name);

            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }

        CarbonImmutable::setTestNow();
        Sleep::fake(false);

        parent::tearDown();
    }

    /**
     * By default every entry is kept forever: a run deletes nothing, writes no
     * prune row, and ends complete.
     *
     * @return void
     */
    public function testNothingIsPrunedByDefault(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.after_days', 0);

        $ids = [$this->storeEntry(self::OLD), $this->storeEntry('2000-01-01T00:00:00.000000Z')];

        $this->sealAll();

        $result = $this->prune();

        self::assertSame([PruneStatus::COMPLETE, 0, 0], [$result->status, $result->deleted, $result->seals]);
        self::assertSame($ids, $this->present($ids));
        self::assertSame(['policy', 'prune_run', 'prune_run'], $this->kinds());
    }

    /**
     * The cut-off is the run's midnight less thirty days, to the microsecond:
     * an entry one microsecond before it is pruned, one at it and one after it
     * are kept.
     *
     * @return void
     */
    public function testTheFrozenClockBoundary(): void
    {
        $before = $this->storeEntry('2026-11-14T23:59:59.999999Z');
        $at     = $this->storeEntry(self::CUTOFF);
        $after  = $this->storeEntry('2026-11-15T00:00:00.000001Z');

        $this->sealAll();

        $result = $this->prune();

        self::assertSame(1, $result->deleted);
        self::assertSame([], $this->present([$before]));
        self::assertEqualsCanonicalizing([$at, $after], $this->present([$at, $after]));
    }

    /**
     * Two categories of one seal are pruned each by its own retention: a day
     * for `security` prunes it, thirty for `finance` keeps it; the seal is then
     * `pruned` and verifies.
     *
     * @return void
     */
    public function testTwoCategoriesPruneIndependentlyInsideOneSeal(): void
    {
        $this->retain(['security' => 1, 'finance' => 30]);

        $security = $this->storeEntry(self::RECENT, ['category' => 'security']);
        $finance  = $this->storeEntry(self::RECENT);

        $this->sealAll();

        $result = $this->prune();

        self::assertSame([1, ['security' => 1]], [$result->deleted, $result->categories]);
        self::assertSame([], $this->present([$security]));
        self::assertSame([$finance], $this->present([$finance]));
        self::assertSame(['pruned'], $this->verifiedSegments());
    }

    /**
     * An entry an active hold keeps survives and is counted held, and the run
     * ends partial; its neighbours go.
     *
     * @return void
     */
    public function testAHeldRowSurvives(): void
    {
        $held  = $this->storeEntry(self::OLD, ['tenant_id' => 'org_held']);
        $other = $this->storeEntry(self::OLD);

        $this->sealAll();
        $this->hold(HoldScope::tenants(Reference::of('organisation', 'org_held')));

        $result = $this->prune();

        self::assertSame([PruneStatus::PARTIAL, 1, 1], [$result->status, $result->deleted, $result->held]);
        self::assertSame([$held], $this->present([$held, $other]));
    }

    /**
     * Overlapping holds each count: an entry either keeps is kept, an entry
     * both keep is counted once, and releasing one leaves the other keeping its
     * entries.
     *
     * @return void
     */
    public function testOverlappingHoldsEachCount(): void
    {
        $tenantOnly = $this->storeEntry(self::OLD, ['tenant_id' => 'org_held']);
        $both       = $this->storeEntry(self::OLD, ['tenant_id' => 'org_held', 'actor_id' => '99']);
        $actorOnly  = $this->storeEntry(self::OLD, ['actor_id' => '99']);
        $free       = $this->storeEntry(self::OLD);

        $this->sealAll();

        $tenant = $this->hold(HoldScope::tenants(Reference::of('organisation', 'org_held')));

        $this->hold(HoldScope::all()->about(Reference::of('user', '99')));

        $result = $this->prune();

        self::assertSame([1, 3], [$result->deleted, $result->held]);
        self::assertEqualsCanonicalizing([$tenantOnly, $both, $actorOnly], $this->present([$tenantOnly, $both, $actorOnly, $free]));

        $this->release($tenant);

        $result = $this->prune();

        self::assertSame([1, 2], [$result->deleted, $result->held]);
        self::assertEqualsCanonicalizing([$both, $actorOnly], $this->present([$tenantOnly, $both, $actorOnly]));
    }

    /**
     * An entry no seal holds is never pruned, however old.
     *
     * @return void
     */
    public function testAnUnsealedRowSurvives(): void
    {
        $sealed = $this->storeEntry(self::OLD);

        $this->sealAll();

        $unsealed = $this->storeEntry(self::OLD);

        $result = $this->prune();

        self::assertSame(1, $result->deleted);
        self::assertSame([$unsealed], $this->present([$sealed, $unsealed]));
    }

    /**
     * An export's journal entry is protected: it survives a prune that takes
     * everything around it, its artifact with it, and its export still
     * verifies.
     *
     * @return void
     */
    public function testAProtectedExportSurvivesAndStillVerifies(): void
    {
        $directory = uniqid(sys_get_temp_dir() . '/audit-log-prune-export-', true);

        mkdir($directory, 0700);

        try {
            $target = $directory . '/trail.ndjson';

            CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:00:00', 'UTC'));
            $this->usePolicyThatAllowsEverything();

            $exported = [$this->storeEntry(self::OLD), $this->storeEntry(self::OLD)];

            $viewer = ['file' => $target, '--viewer-type' => 'App\Models\User', '--viewer-id' => '7'];

            self::assertSame(0, Artisan::call('audit-log:export', $viewer), Artisan::output());

            $this->sealAll();

            CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

            $result  = $this->prune();
            $journal = $this->maintenance()->table(EntrySettings::table())->where('event', 'audit_log.trail_exported')->pluck('id')->all();

            self::assertSame(2, $result->deleted);
            self::assertSame([], $this->present($exported));
            self::assertCount(1, $journal);
            self::assertSame(1, $this->maintenance()->table(EntrySettings::artifactsTable())->whereIn('entry_id', $journal)->count());
            self::assertSame(0, Artisan::call('audit-log:export', [...$viewer, '--verify' => true]), Artisan::output());
        } finally {
            array_map(unlink(...), glob($directory . '/*') ?: []);
            rmdir($directory);
        }
    }

    /**
     * An entry with an outbox row survives, counted as pending, and the run
     * ends partial.
     *
     * @return void
     */
    public function testAPendingDeliverySurvivesAndIsCounted(): void
    {
        $pending = $this->storeEntry(self::OLD);
        $other   = $this->storeEntry(self::OLD);

        $this->sealAll();
        $this->seedOutboxRow($pending, 'payload');

        $result = $this->prune();

        self::assertSame([PruneStatus::PARTIAL, 1, 1], [$result->status, $result->deleted, $result->pendingDelivery]);
        self::assertSame([$pending], $this->present([$pending, $other]));
    }

    /**
     * A pruned entry's artifact and its delivered receipts go with it.
     *
     * @return void
     */
    public function testArtifactsAndReceiptsGoWithTheirEntries(): void
    {
        $bundle = RecordFactory::finalisedBundle();

        app(DatabaseAuditStore::class)->store($bundle);

        $id = $bundle->record->id;

        $this->receipt($id, 'siem', '2026-12-02 12:00:01.000000');
        $this->sealAll();

        self::assertSame(1, $this->maintenance()->table(EntrySettings::artifactsTable())->where('entry_id', $id)->count());

        $result = $this->prune();

        self::assertSame(1, $result->deleted);
        self::assertSame([], $this->present([$id]));
        self::assertSame(0, $this->maintenance()->table(EntrySettings::artifactsTable())->where('entry_id', $id)->count());
        self::assertSame(0, $this->maintenance()->table(DeliveryTables::deliveriesTable())->where('entry_id', $id)->count());
        self::assertSame(['pruned'], $this->verifiedSegments());
    }

    /**
     * Each chunk of a seal writes one prune row of its own, its record signed
     * and disjoint from the other's, between the run's start and finish.
     *
     * @return void
     */
    public function testEachChunkWritesOneSignedPruneRow(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.batch', 100);

        $this->bulk(150, self::OLD);
        $this->sealAll();

        $result  = $this->prune();
        $records = $this->records();

        self::assertSame([150, 1], [$result->deleted, $result->seals]);
        self::assertSame(['policy', 'prune_run', 'prune', 'prune', 'prune_run'], $this->kinds());
        self::assertCount(2, $records);
        self::assertSame([100, 50], [$records[0]->prunedCount, $records[1]->prunedCount]);
        self::assertSame([], array_intersect($records[0]->positions(), $records[1]->positions()));
        self::assertTrue(app(SealSigner::class)->verifiesPrune($records[0]));
        self::assertTrue(app(SealSigner::class)->verifiesPrune($records[1]));
        self::assertSame($result->operationId, $records[0]->operationId);
        self::assertSame(['pruned'], $this->verifiedSegments());
    }

    /**
     * The policy's row is written by the first run under its version alone,
     * with the bound class and its settings.
     *
     * @return void
     */
    public function testThePolicyRowIsWrittenOncePerVersion(): void
    {
        $first  = $this->prune();
        $second = $this->prune();

        self::assertSame($first->policyVersion, $second->policyVersion);
        self::assertSame(['policy', 'prune_run', 'prune_run', 'prune_run', 'prune_run'], $this->kinds());

        $policy = $this->payloadsOf(JournalKind::POLICY)[0];

        self::assertSame([
            'policy'   => ConfiguredRetentionPolicy::class,
            'settings' => ['after_days' => 30, 'categories' => [], 'preserve' => []],
            'version'  => $first->policyVersion,
        ], $policy);
        self::assertMatchesRegularExpression('/\Aconfig:[0-9a-f]{16}\z/', (string) $first->policyVersion);
    }

    /**
     * A changed setting is a new version, journalled by the next run.
     *
     * @return void
     */
    public function testAChangedSettingJournalsANewVersion(): void
    {
        $first = $this->prune();

        $this->retain(['security' => 7]);

        $second   = $this->prune();
        $policies = $this->payloadsOf(JournalKind::POLICY);

        self::assertNotSame($first->policyVersion, $second->policyVersion);
        self::assertSame([$first->policyVersion, $second->policyVersion], array_column($policies, 'version'));
        self::assertSame(['after_days' => 30, 'categories' => ['security' => 7], 'preserve' => []], $policies[1]['settings']);
    }

    /**
     * The start row carries the run, its policy version, its boundary, its
     * midnight and where it resumes; the finish row its status, counts, cursor,
     * what it left, its deletions per category and its decisions.
     *
     * @return void
     */
    public function testTheRunRowsCarryStatusCountsCursorAndCutoffs(): void
    {
        $this->storeEntry(self::OLD);
        $this->storeEntry(self::RECENT, ['category' => 'security']);
        $this->sealAll();

        $result = $this->prune();

        [$start, $finish] = $this->payloadsOf(JournalKind::PRUNE_RUN);

        self::assertMatchesRegularExpression(self::RUN_ID, $result->operationId);
        self::assertSame([
            'boundary_sequence' => 1,
            'cutoff_midnight'   => '2026-12-15T00:00:00.000000Z',
            'phase'             => 'start',
            'policy_version'    => $result->policyVersion,
            'resume_from'       => 0,
            'run_id'            => $result->operationId,
        ], $start);

        $decisions = [
            ['finance', 'organisation', 'org_01', 30, null, self::CUTOFF],
            ['security', 'organisation', 'org_01', 30, null, self::CUTOFF],
        ];

        self::assertSame([
            'categories'        => ['finance' => 1],
            'cursor'            => 1,
            'decisions'         => [['finance', 30, null, self::CUTOFF, 1], ['security', 30, null, self::CUTOFF, 1]],
            'decisions_digest'  => hash('sha256', CanonicalEncoder::encode($decisions)),
            'decisions_omitted' => 0,
            'deleted'           => 1,
            'failure'           => null,
            'held'              => 0,
            'pairs'             => 2,
            'pending_delivery'  => 0,
            'phase'             => 'finish',
            'remaining'         => 0,
            'run_id'            => $result->operationId,
            'seals'             => 1,
            'skipped_seals'     => 0,
            'status'            => 'complete',
            'tenants_affected'  => 1,
        ], $finish);
        self::assertSame([1, 0, true, false], [$result->cursor, $result->remaining, $result->committed, $result->recorded]);
    }

    /**
     * The finish row is bounded whatever the tenants: a thousand tenants of one
     * category give one decision, the thousand pairs it was made for, and the
     * digest of every pair's decision.
     *
     * @return void
     */
    public function testTheFinishRowIsBoundedWhateverTheTenants(): void
    {
        $this->bulk(1000, self::OLD, static fn (int $index): array => ['tenant_id' => 'org_' . $index]);
        $this->sealAll();

        $result = $this->prune();
        $finish = $this->payloadsOf(JournalKind::PRUNE_RUN)[1];

        self::assertSame([1000, 1000], [$result->deleted, $result->tenantsAffected]);
        self::assertSame([['finance', 30, null, self::CUTOFF, 1000]], $finish['decisions']);
        self::assertSame([1000, 0], [$finish['pairs'], $finish['decisions_omitted']]);
        $payload = $this->maintenance()->table(LifecycleTables::journalTable())->where('sequence', 4)->value('payload');

        self::assertIsString($finish['decisions_digest']);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $finish['decisions_digest']);
        self::assertIsString($payload);
        self::assertLessThan(2048, strlen($payload));
    }

    /**
     * The time budget is read from the clock between chunks: a run past it
     * after its first chunk stops before the second, partial, with the seal it
     * was in left to the next run.
     *
     * @return void
     */
    public function testTheTimeBudgetStopsBetweenChunks(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.batch', 100);

        $this->bulk(150, self::OLD);
        $this->sealAll();
        $this->moveClockOnTheFirstPruneRow('2026-12-15 15:01:01');

        $result = app(Pruner::class)->run(false, 60);

        self::assertSame([PruneStatus::PARTIAL, 100, 0, 1], [$result->status, $result->deleted, $result->cursor, $result->remaining]);
        self::assertSame(['policy', 'prune_run', 'prune', 'prune_run'], $this->kinds());
    }

    /**
     * A run stopped on its budget is resumed after its cursor: the next run
     * starts after the last seal it walked, and never reads the seals before.
     *
     * @return void
     */
    public function testAPartialRunResumesWhereItStopped(): void
    {
        $first = $this->storeEntry(self::OLD);
        $this->sealAll();
        $second = $this->storeEntry(self::OLD);
        $this->sealAll();

        $this->moveClockOnTheFirstPruneRow('2026-12-15 15:01:01');

        $stopped = app(Pruner::class)->run(false, 60);

        self::assertSame([PruneStatus::PARTIAL, 1, 1], [$stopped->status, $stopped->cursor, $stopped->remaining]);
        self::assertSame([$second], $this->present([$first, $second]));

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $loads   = $this->sealLoads();
        $resumed = $this->prune();

        self::assertSame([PruneStatus::COMPLETE, 1, 2, 0], [$resumed->status, $resumed->deleted, $resumed->cursor, $resumed->remaining]);
        self::assertSame([2], $loads->getArrayCopy());
        self::assertSame(1, $this->payloadsOf(JournalKind::PRUNE_RUN)[2]['resume_from']);
    }

    /**
     * After a complete run the next starts again from the first seal.
     *
     * @return void
     */
    public function testACompleteRunStartsAgainFromTheFirstSeal(): void
    {
        $this->storeEntry(self::OLD);
        $this->sealAll();

        self::assertSame(PruneStatus::COMPLETE, $this->prune()->status);

        $loads = $this->sealLoads();

        $this->prune();

        self::assertSame([1], $loads->getArrayCopy());
        self::assertSame(0, $this->payloadsOf(JournalKind::PRUNE_RUN)[2]['resume_from']);
    }

    /**
     * A run that failed before its boundary is never resumed from its cursor:
     * the next run starts again from the first seal.
     *
     * @return void
     */
    public function testAFailedRunIsNotResumedFromItsCursor(): void
    {
        $this->storeEntry(self::OLD);
        $this->sealAll();
        $this->storeEntry(self::OLD, ['category' => 'security']);
        $this->sealAll();

        $this->usePolicy(self::thirtyDaysButSecurity(...));

        $failed = $this->prune();

        self::assertSame([PruneStatus::FAILED, 1, 1], [$failed->status, $failed->cursor, $failed->remaining]);

        app()->bind(RetentionPolicy::class, ConfiguredRetentionPolicy::class);

        $loads = $this->sealLoads();
        $next  = $this->prune();

        self::assertSame([PruneStatus::COMPLETE, 1, 2], [$next->status, $next->deleted, $next->cursor]);
        self::assertSame([1, 2], $loads->getArrayCopy());
        self::assertSame(0, $this->payloadsOf(JournalKind::PRUNE_RUN)[2]['resume_from']);
    }

    /**
     * A partial run that walked every seal to its boundary, leaving a held
     * entry, has nothing remaining, so the next run starts again from the first
     * seal.
     *
     * @return void
     */
    public function testAPartialRunThatReachedItsBoundaryStartsAgainFromTheFirstSeal(): void
    {
        $this->storeEntry(self::OLD);
        $this->sealAll();
        $this->hold(HoldScope::all());

        $partial = $this->prune();

        self::assertSame([PruneStatus::PARTIAL, 1, 0], [$partial->status, $partial->cursor, $partial->remaining]);

        $loads = $this->sealLoads();

        $this->prune();

        self::assertSame([1], $loads->getArrayCopy());
        self::assertSame(0, $this->payloadsOf(JournalKind::PRUNE_RUN)[2]['resume_from']);
    }

    /**
     * An entry a hold kept through a partial run is pruned by the next run once
     * the hold is released, never stranded behind a cursor.
     *
     * @return void
     */
    public function testARowReleasedAfterAPartialRunIsPrunedByTheNext(): void
    {
        $id = $this->storeEntry(self::OLD);

        $this->sealAll();

        $hold = $this->hold(HoldScope::all());

        self::assertSame([0, 1], [$this->prune()->deleted, count($this->present([$id]))]);

        $this->release($hold);

        $result = $this->prune();

        self::assertSame([PruneStatus::COMPLETE, 1], [$result->status, $result->deleted]);
        self::assertSame([], $this->present([$id]));
    }

    /**
     * The cursor is the verified chain's, read after the start's lock: the
     * progress a monitor reads is never consulted, and a finish row whose
     * payload was changed refuses the run.
     *
     * @return void
     */
    public function testTheCursorIsReadFromTheVerifiedChainAfterTheLock(): void
    {
        $this->storeEntry(self::OLD);
        $this->sealAll();
        $this->storeEntry(self::OLD);
        $this->sealAll();

        $this->moveClockOnTheFirstPruneRow('2026-12-15 15:01:01');
        app(Pruner::class)->run(false, 60);
        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $forged = ['at' => 'x', 'run_id' => 'x', 'status' => 'partial', 'deleted' => 0, 'cursor' => 99];

        app(IntegrityProgress::class)->put(IntegrityProgress::RETENTION_LAST_RUN, $forged, CarbonImmutable::now());

        /** @var \ArrayObject<int, string> $order */
        $order = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($order): void {
            $order->append(match (true) {
                str_starts_with($query->sql, 'update') && str_contains($query->sql, LifecycleTables::lockTable()) => 'lock',
                str_contains($query->sql, LifecycleTables::journalTable())                                        => 'journal',
                default                                                                                           => 'other',
            });
        });

        $this->prune();

        $events = $order->getArrayCopy();

        self::assertSame(1, $this->payloadsOf(JournalKind::PRUNE_RUN)[2]['resume_from']);
        self::assertSame('lock', array_values(array_filter($events, static fn (string $event): bool => $event !== 'other'))[0]);

        $finish = $this->journalRows()[6];

        self::assertSame('prune_run', $finish['kind']);

        $this->tamperJournal((int) $finish['sequence'], ['payload' => str_replace('"remaining":0', '"remaining":5', (string) $finish['payload'])]);

        $refused = $this->prune();

        self::assertSame([PruneStatus::FAILED, 'journal_broken', false], [$refused->status, $refused->failure, $refused->committed]);
    }

    /**
     * A seal that fails authentication is skipped, named and counted, and the
     * run prunes the seals after it and ends partial.
     *
     * @return void
     */
    public function testASealThatFailsAuthenticationIsSkippedAndReported(): void
    {
        $first = $this->storeEntry(self::OLD);
        $this->sealAll();
        $second = $this->storeEntry(self::OLD);
        $this->sealAll();

        $sealId = (string) $this->seals()[0]['id'];

        $this->maintenance()->table(IntegrityTables::checkpointsTable())->where('sequence', 1)->update(['seal_digest' => str_repeat('e', 64)]);

        $result = $this->prune();

        self::assertSame([PruneStatus::PARTIAL, 1, 1, [$sealId], 2], [$result->status, $result->deleted, $result->skippedSeals, $result->skippedSealIds, $result->cursor]);
        self::assertSame([$first], $this->present([$first, $second]));
    }

    /**
     * A candidate changed after it was sealed skips its seal: nothing of that
     * seal is deleted or recorded, and the next seal is still pruned.
     *
     * @return void
     */
    public function testATamperedCandidateSkipsItsSealAndDeletesNothing(): void
    {
        $tampered  = $this->storeEntry(self::OLD);
        $neighbour = $this->storeEntry(self::OLD);
        $this->sealAll();
        $next = $this->storeEntry(self::OLD);
        $this->sealAll();

        $this->maintenance()->table(EntrySettings::table())->where('id', $tampered)->update(['event' => 'invoice.forged']);

        $result = $this->prune();

        self::assertSame([PruneStatus::PARTIAL, 1, 1], [$result->status, $result->deleted, $result->skippedSeals]);
        self::assertEqualsCanonicalizing([$tampered, $neighbour], $this->present([$tampered, $neighbour, $next]));
        self::assertCount(1, $this->records());
        self::assertSame((string) $this->seals()[1]['id'], $this->records()[0]->sealId);
    }

    /**
     * An entry stored again after it was pruned skips its seal on the next run:
     * it is never deleted again, no second record sets its member, and
     * verification still finds it `resurrected` rather than an overlap of the
     * package's own records.
     *
     * @return void
     */
    public function testAResurrectedEntryIsNeverPrunedAgain(): void
    {
        $id = $this->storeEntry(self::OLD);
        $this->sealAll();

        $stored = (array) $this->maintenance()->table(EntrySettings::table())->where('id', $id)->first();

        self::assertSame(1, $this->prune()->deleted);

        $this->maintenance()->table(EntrySettings::table())->insert($stored);

        $sealId = (string) $this->seals()[0]['id'];
        $result = $this->prune();

        self::assertSame([PruneStatus::PARTIAL, 0, 1, [$sealId]], [$result->status, $result->deleted, $result->skippedSeals, $result->skippedSealIds]);
        self::assertSame([$id], $this->present([$id]));
        self::assertCount(1, $this->records());

        /** @var \ArrayObject<int, array{0: string, 1: ?string}> $findings */
        $findings = new \ArrayObject;

        app(Verifier::class)->verify(VerificationRange::whole(), static function (SegmentReport $report) use ($findings): void {
            $findings->append([$report->integrity->value, $report->finding?->value]);
        });

        self::assertSame([['incomplete', 'resurrected']], $findings->getArrayCopy());
    }

    /**
     * A policy that throws stops the run: the chunks it committed before stand,
     * its finish row is written failed, and the failure is reported by its
     * class alone.
     *
     * @return void
     */
    public function testAPolicyExceptionStopsTheRunAndCommittedChunksStand(): void
    {
        $finance = $this->storeEntry(self::OLD);
        $this->sealAll();
        $security = $this->storeEntry(self::OLD, ['category' => 'security']);
        $this->sealAll();

        $this->usePolicy(self::thirtyDaysButSecurity(...));

        $result = $this->prune();

        self::assertSame([PruneStatus::FAILED, 'policy_failed', true, 1], [$result->status, $result->failure, $result->committed, $result->deleted]);
        self::assertSame([$security], $this->present([$finance, $security]));
        self::assertSame('failed', $this->payloadsOf(JournalKind::PRUNE_RUN)[1]['status']);
        self::assertSame([sprintf('The prune run `%s` stopped with RuntimeException; the chunks it committed stand.', $result->operationId)], $this->reported());
    }

    /**
     * A custom policy that keeps a pair for less than it must be preserved
     * stops the run when the pair is first evaluated, as refused configuration.
     *
     * @return void
     */
    public function testACustomPolicysConflictStopsTheRun(): void
    {
        $id = $this->storeEntry(self::OLD);

        $this->sealAll();
        $this->usePolicy(static fn (): int => 10, 20);

        $result = $this->prune();

        self::assertSame([PruneStatus::FAILED, 'configuration_refused', 0], [$result->status, $result->failure, $result->deleted]);
        self::assertSame([$id], $this->present([$id]));
    }

    /**
     * A malformed retention setting refuses the run before it starts, as
     * refused configuration, and nothing is journalled.
     *
     * @return void
     */
    public function testAMalformedSettingRefusesTheRunBeforeItStarts(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.after_days', 'forever');

        $result = $this->prune();

        self::assertSame([PruneStatus::FAILED, 'configuration_refused', false, null], [$result->status, $result->failure, $result->committed, $result->policyVersion]);
        self::assertSame([], $this->kinds());
    }

    /**
     * A journal that fails verification refuses the run: nothing is deleted or
     * journalled, and the run is not committed.
     *
     * @return void
     */
    public function testABrokenJournalRefusesTheRun(): void
    {
        $id = $this->storeEntry(self::OLD);

        $this->sealAll();
        $this->journalHold('01932b4e-d000-7000-8000-000000000001');
        $this->tamperJournal(1, ['reason' => 'forged']);

        $result = $this->prune();

        self::assertSame([PruneStatus::FAILED, 'journal_broken', false, 0], [$result->status, $result->failure, $result->committed, $result->deleted]);
        self::assertSame([$id], $this->present([$id]));
        self::assertSame(['hold'], $this->kinds());
    }

    /**
     * A hold whose projection row was deleted still keeps its entries: the
     * pruner reads holds from the verified chain alone.
     *
     * @return void
     */
    public function testADeletedProjectionRowStillHolds(): void
    {
        $id = $this->storeEntry(self::OLD);

        $this->sealAll();
        $this->hold(HoldScope::all());

        $this->maintenance()->table(LifecycleTables::holdsTable())->delete();

        $result = $this->prune();

        self::assertSame([0, 1], [$result->deleted, $result->held]);
        self::assertSame([$id], $this->present([$id]));
    }

    /**
     * A dry run counts per pair and per seal what a run would delete, takes no
     * lock, runs no statement but `select`, and journals nothing, not even the
     * policy's row.
     *
     * @return void
     */
    public function testTheDryRunCountsPerPairAndPerSealAndWritesNothing(): void
    {
        $this->storeEntry(self::OLD);
        $this->storeEntry(self::OLD, ['tenant_id' => 'org_02']);
        $this->storeEntry(self::RECENT);
        $this->sealAll();
        $this->storeEntry(self::OLD, ['category' => 'security', 'tenant_type' => null, 'tenant_id' => null]);
        $this->sealAll();

        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append(strtolower(ltrim($query->sql)));
        });

        $result = app(Pruner::class)->run(true);

        self::assertSame([], array_values(array_filter($statements->getArrayCopy(), static fn (string $sql): bool => !str_starts_with($sql, 'select'))));
        self::assertSame([true, false, PruneStatus::COMPLETE, 0], [$result->dryRun, $result->committed, $result->status, $result->deleted]);
        self::assertSame([2, 0], [$result->cursor, $result->remaining]);
        self::assertSame([
            'pairs' => [
                ['category' => 'finance', 'tenant_type' => 'organisation', 'tenant_id' => 'org_01', 'cutoff' => self::CUTOFF, 'eligible' => 1],
                ['category' => 'finance', 'tenant_type' => 'organisation', 'tenant_id' => 'org_02', 'cutoff' => self::CUTOFF, 'eligible' => 1],
                ['category' => 'security', 'tenant_type' => null, 'tenant_id' => null, 'cutoff' => self::CUTOFF, 'eligible' => 1],
            ],
            'seals' => [1 => 2, 2 => 1],
        ], $result->plan);
        self::assertSame([], $this->kinds());
        self::assertNull(app(IntegrityProgress::class)->get(IntegrityProgress::RETENTION_LAST_RUN));
    }

    /**
     * A dry run counts as held exactly the entries the run keeps for a hold.
     *
     * @return void
     */
    public function testTheDryRunCountsHeldRowsAsTheRunWould(): void
    {
        $this->storeEntry(self::OLD, ['tenant_id' => 'org_held']);
        $this->storeEntry(self::OLD, ['tenant_id' => 'org_held', 'occurred_at' => '2026-10-01T00:00:00.000000Z']);
        $this->storeEntry(self::OLD, ['actor_id' => '99']);
        $this->storeEntry(self::OLD);
        $this->sealAll();

        $this->hold(HoldScope::tenants(Reference::of('organisation', 'org_held'))->occurredBetween(new CarbonImmutable('2026-10-15', 'UTC'), null));
        $this->hold(HoldScope::all()->about(Reference::of('user', '99')));

        $planned = app(Pruner::class)->run(true);
        $run     = $this->prune();

        self::assertSame(2, $planned->held);
        self::assertSame($run->held, $planned->held);
        self::assertSame($run->deleted, array_sum($planned->plan['seals'] ?? []));
    }

    /**
     * A dry run on a journal that fails verification refuses, and writes
     * nothing.
     *
     * @return void
     */
    public function testADryRunOnABrokenChainRefuses(): void
    {
        $this->journalHold('01932b4e-d000-7000-8000-000000000001');
        $this->tamperJournal(1, ['reason' => 'forged']);

        $result = app(Pruner::class)->run(true);

        self::assertSame([PruneStatus::FAILED, 'journal_broken', false, true], [$result->status, $result->failure, $result->committed, $result->dryRun]);
        self::assertSame(['hold'], $this->kinds());
    }

    /**
     * Every run that is not a dry run writes `retention.last_run`: when it
     * ended, the run, its status, what it deleted and its cursor.
     *
     * @return void
     */
    public function testTheRunWritesItsProgress(): void
    {
        $this->storeEntry(self::OLD);
        $this->sealAll();

        $result = $this->prune();

        self::assertSame(
            ['at' => '2026-12-15T15:00:00.000000Z', 'run_id' => $result->operationId, 'status' => 'complete', 'deleted' => 1, 'cursor' => 1],
            app(IntegrityProgress::class)->get(IntegrityProgress::RETENTION_LAST_RUN),
        );
    }

    /**
     * A run refuses inside a transaction on the storage connection, a dry run
     * too, before it reads or writes anything; a budget under a second is
     * refused as well.
     *
     * @return void
     */
    public function testItRefusesInsideATransaction(): void
    {
        $connection = DB::connection(StorageConnection::name());

        $connection->beginTransaction();

        foreach ([false, true] as $dryRun) {
            try {
                app(Pruner::class)->run($dryRun);

                self::fail('Expected a prune inside a transaction to be refused.');
            } catch (\LogicException $exception) {
                self::assertSame('A prune runs in transactions of its own on the maintenance connection, and refuses to run inside one.', $exception->getMessage());
            }
        }

        $connection->rollBack();

        self::assertSame([], $this->kinds());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A prune\'s time budget must be at least a second.');

        app(Pruner::class)->run(false, 0);
    }

    /**
     * Ten thousand unsealed entries past the threshold are never deleted: a run
     * walks seals alone.
     *
     * @return void
     */
    public function testTenThousandUnsealedRowsPastTheThresholdDeleteNothing(): void
    {
        $this->bulk(10000, self::OLD);

        $result = $this->prune();

        self::assertSame([PruneStatus::COMPLETE, 0, 0], [$result->status, $result->deleted, $result->cursor]);
        self::assertSame(10000, $this->maintenance()->table(EntrySettings::table())->count());
    }

    /**
     * A chunk whose deletes mismatch is made once more from a fresh read; one
     * that mismatches again skips its seal, deleting and journalling nothing.
     *
     * @return void
     */
    public function testAMismatchIsRetriedOnceThenTheSealIsSkipped(): void
    {
        $ids = [$this->storeEntry(self::OLD), $this->storeEntry(self::OLD)];

        $this->sealAll();

        $locks  = $this->deleteBeforeEachEntriesDelete($ids[0], 2);
        $result = $this->prune();

        self::assertSame([PruneStatus::PARTIAL, 0, 1], [$result->status, $result->deleted, $result->skippedSeals]);
        self::assertCount(4, $locks);
        self::assertCount(2, $this->present($ids));
        self::assertSame(['policy', 'prune_run', 'prune_run'], $this->kinds());
    }

    /**
     * A chunk whose deletes mismatch once is pruned by its retry.
     *
     * @return void
     */
    public function testAMismatchRetriedSuccessfullyPrunes(): void
    {
        $ids = [$this->storeEntry(self::OLD), $this->storeEntry(self::OLD)];

        $this->sealAll();
        $this->deleteBeforeEachEntriesDelete($ids[0], 1);

        $result = $this->prune();

        self::assertSame([PruneStatus::COMPLETE, 2, 0], [$result->status, $result->deleted, $result->skippedSeals]);
        self::assertSame([], $this->present($ids));
    }

    /**
     * A chunk lost to a deadlock after it wrote its prune row is made again
     * from the replay the last commit returned, so its retry appends its row at
     * the same sequence.
     *
     * @return void
     */
    public function testARetriedChunkStartsFromTheCommittedReplay(): void
    {
        Sleep::fake();

        $this->storeEntry(self::OLD);
        $this->sealAll();

        $failed = false;

        DB::listen(static function (QueryExecuted $query) use (&$failed): void {
            if ($failed || !self::isPruneRowInsert($query)) {
                return;
            }

            $failed = true;

            throw new DeadlockException('The chunk deadlocked.');
        });

        $result = $this->prune();
        $prune  = JournalRow::fromRow($this->journalRows()[2], true);

        self::assertTrue($failed);
        self::assertSame([PruneStatus::COMPLETE, 1], [$result->status, $result->deleted]);
        self::assertSame([JournalKind::PRUNE, 3], [$prune->kind, $prune->sequence]);
        self::assertSame(['policy', 'prune_run', 'prune', 'prune_run'], $this->kinds());

        Sleep::assertSleptTimes(1);
    }

    /**
     * A seal made during the run is past the boundary the run read at its
     * start, and is left to the next run.
     *
     * @return void
     */
    public function testASealMadeDuringTheRunIsNotPruned(): void
    {
        $before = $this->storeEntry(self::OLD);

        $this->sealAll();

        /** @var \ArrayObject<int, string> $during */
        $during = new \ArrayObject;
        $sealed = false;

        DB::listen(function (QueryExecuted $query) use ($during, &$sealed): void {
            if ($sealed || !str_contains($query->sql, IntegrityTables::membersTable()) || !str_contains($query->sql, 'join')) {
                return;
            }

            $sealed = true;

            $during->append($this->storeEntry(self::OLD));
            $this->sealAll();
        });

        $result = $this->prune();

        self::assertTrue($sealed);
        self::assertSame([1, 1, 0], [$result->deleted, $result->cursor, $result->remaining]);
        self::assertCount(2, $this->seals());
        self::assertSame($during->getArrayCopy(), $this->present([$before, ...$during->getArrayCopy()]));
        self::assertSame(1, $this->payloadsOf(JournalKind::PRUNE_RUN)[0]['boundary_sequence']);
    }

    /**
     * The cut-off is fixed for the run: a clock that passes midnight during the
     * run moves no pair's cut-off, so an entry the next day's cut-off would
     * admit is kept.
     *
     * @return void
     */
    public function testTheCutoffIsFixedForTheRun(): void
    {
        $first = $this->storeEntry('2026-11-14T12:00:00.000000Z');
        $this->sealAll();
        $second = $this->storeEntry('2026-11-15T12:00:00.000000Z');
        $this->sealAll();

        $this->moveClockOnTheFirstPruneRow('2026-12-16 00:30:00');

        $result = app(Pruner::class)->run(false, 86400);

        self::assertSame([PruneStatus::COMPLETE, 1], [$result->status, $result->deleted]);
        self::assertSame([$second], $this->present([$first, $second]));
        self::assertSame([['finance', 30, null, self::CUTOFF, 1]], $this->payloadsOf(JournalKind::PRUNE_RUN)[1]['decisions']);
    }

    /**
     * A run that fails after its start row still writes its finish row, failed,
     * and reports the failure by its class alone.
     *
     * @return void
     */
    public function testAFailedRunAfterItsStartStillWritesItsFinishRow(): void
    {
        $id = $this->storeEntry(self::OLD);

        $this->sealAll();

        DB::listen(static function (QueryExecuted $query): void {
            if (!self::isPruneRowInsert($query)) {
                return;
            }

            throw new \RuntimeException('The disk is full of org_01.');
        });

        $result = $this->prune();

        self::assertSame([PruneStatus::FAILED, 'prune_failed', true, 0], [$result->status, $result->failure, $result->committed, $result->deleted]);
        self::assertSame([$id], $this->present([$id]));
        self::assertSame(['policy', 'prune_run', 'prune_run'], $this->kinds());
        self::assertSame('failed', $this->payloadsOf(JournalKind::PRUNE_RUN)[1]['status']);
        self::assertSame([sprintf('The prune run `%s` stopped with RuntimeException; the chunks it committed stand.', $result->operationId)], $this->reported());
        self::assertSame('failed', app(IntegrityProgress::class)->get(IntegrityProgress::RETENTION_LAST_RUN)['status'] ?? null);
    }

    /**
     * A failed delivery keeps its entry until it is replayed: the run ends
     * partial with the entry pending, and once its receipt is delivered the
     * next run prunes the entry and the receipt.
     *
     * @return void
     */
    public function testAFailedDeliveryKeepsItsEntryUntilReplayed(): void
    {
        $id = $this->storeEntry(self::OLD);

        $this->receipt($id, 'siem', null);
        $this->sealAll();

        $kept = $this->prune();

        self::assertSame([PruneStatus::PARTIAL, 0, 1], [$kept->status, $kept->deleted, $kept->pendingDelivery]);
        self::assertSame([$id], $this->present([$id]));

        $this->maintenance()->table(DeliveryTables::deliveriesTable())->where('entry_id', $id)->update(['delivered_at' => '2026-12-15 15:00:00.000000']);

        $pruned = $this->prune();

        self::assertSame([PruneStatus::COMPLETE, 1], [$pruned->status, $pruned->deleted]);
        self::assertSame(0, $this->maintenance()->table(DeliveryTables::deliveriesTable())->where('entry_id', $id)->count());
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
     * Thirty days for every category but `security`, for which the policy
     * throws, naming a tenant a report must never show.
     *
     * @param  string  $category
     * @return int
     *
     * @throws \RuntimeException
     */
    private static function thirtyDaysButSecurity(string $category): int
    {
        if ($category === 'security') {
            throw new \RuntimeException('org_01 is under review');
        }

        return 30;
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
     * Keep the categories given for their days.
     *
     * @param  array<string, int>  $categories
     * @return void
     */
    private function retain(array $categories): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.categories', $categories);
    }

    /**
     * Bind a policy of version `custom:1` whose retention the closure gives, by
     * category, preserving each pair for the days given or nothing.
     *
     * @param  \Closure(string): ?int  $retain
     * @param  ?int  $preserve
     * @return void
     */
    private function usePolicy(\Closure $retain, ?int $preserve = null): void
    {
        app()->instance(RetentionPolicy::class, new class ($retain, $preserve) implements RetentionPolicy {
            /**
             * Constructor.
             *
             * @param  \Closure(string): ?int  $retain
             * @param  ?int  $preserve
             */
            public function __construct(

                /** The retention of each category. */
                private readonly \Closure $retain,

                /** The preservation of every pair. */
                private readonly ?int $preserve,
            ) {}

            /**
             * The policy's version.
             *
             * @return string
             */
            #[\Override]
            public function version(): string
            {
                return 'custom:1';
            }

            /**
             * The closure's retention of the category.
             *
             * @param  string  $category
             * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
             * @return ?int
             */
            #[\Override]
            public function retainFor(string $category, ?Reference $tenant): ?int
            {
                return ($this->retain)($category);
            }

            /**
             * The preservation given.
             *
             * @param  string  $category
             * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
             * @return ?int
             */
            #[\Override]
            public function preserveFor(string $category, ?Reference $tenant): ?int
            {
                return $this->preserve;
            }
        });
    }

    /**
     * Bind an access policy that lets every viewer read and export every entry.
     *
     * @return void
     */
    private function usePolicyThatAllowsEverything(): void
    {
        app()->instance(AuditAccessPolicy::class, new ClosurePolicy(static fn (): AccessScope => AccessScope::all()));
    }

    /**
     * Place a hold of the scope, and return it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $scope
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Hold
     */
    private function hold(HoldScope $scope): Hold
    {
        return app(HoldKeeper::class)->place(self::OPERATION, $scope, self::authority(), HoldBasis::LEGAL_CLAIM, null);
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
     * Store a captured record with the fields given over its own, happening at
     * the instant given unless the fields say otherwise, recorded at the test's
     * time, and return its id.
     *
     * @param  string  $occurredAt
     * @param  array<string, ?string>  $fields
     * @return string
     */
    private function storeEntry(string $occurredAt, array $fields = []): string
    {
        $record    = RecordFactory::withFields(['occurred_at' => $occurredAt, ...$fields]);
        $finalised = (new RecordFinaliser(FrozenClock::at(self::RECORDED_AT), app(RecordSigner::class)))->finalise($record);

        app(DatabaseAuditStore::class)->store($finalised);

        return $finalised->record->id;
    }

    /**
     * Insert the number of captured records happening at the instant given,
     * each with the fields the closure gives it by its index, as the store
     * writes them, twenty rows to a statement, and return their ids.
     *
     * @param  int  $count
     * @param  string  $occurredAt
     * @param  ?\Closure(int): array<string, string>  $fields
     * @return list<string>
     */
    private function bulk(int $count, string $occurredAt, ?\Closure $fields = null): array
    {
        $finaliser = new RecordFinaliser(FrozenClock::at(self::RECORDED_AT), app(RecordSigner::class));
        $codec     = app(RowCodec::class);
        $base      = RecordFactory::captured(occurredAt: $occurredAt);
        $rows      = [];
        $ids       = [];

        for ($index = 0; $index < $count; $index++) {
            $record = RecordFactory::withFields(['id' => Str::uuid7()->toString(), ...($fields === null ? [] : $fields($index))], $base);
            $rows[] = $codec->encode($finaliser->finalise($record));
            $ids[]  = $record->id;
        }

        foreach (array_chunk($rows, 20) as $chunk) {
            DB::connection(StorageConnection::name())->table(EntrySettings::table())->insert($chunk);
        }

        return $ids;
    }

    /**
     * Seed a receipt of the entry for the destination, delivered at the time
     * given, as the engine stores it, or not yet.
     *
     * @param  string  $entryId
     * @param  string  $destination
     * @param  ?string  $deliveredAt
     * @return void
     */
    private function receipt(string $entryId, string $destination, ?string $deliveredAt): void
    {
        $this->maintenance()->table(DeliveryTables::deliveriesTable())->insert([
            'entry_id'           => $entryId,
            'destination'        => $destination,
            'attempts'           => 1,
            'first_attempted_at' => '2026-12-02 12:00:00.500000',
            'delivered_at'       => $deliveredAt,
            'last_error_class'   => $deliveredAt === null ? \RuntimeException::class : null,
        ]);
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

            CarbonImmutable::setTestNow(new CarbonImmutable($instant, 'UTC'));
        });
    }

    /**
     * Delete the entry, through the chunk's own connection, as each of the
     * chunk's deletes of receipts runs, for the number of times given, so its
     * delete of entries affects one row fewer than it names; and count each
     * lock taken from now.
     *
     * @param  string  $id
     * @param  int  $times
     * @return \ArrayObject<int, string>
     */
    private function deleteBeforeEachEntriesDelete(string $id, int $times): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $locks */
        $locks = new \ArrayObject;
        $done  = 0;

        DB::listen(static function (QueryExecuted $query) use ($id, $times, $locks, &$done): void {
            if (str_starts_with($query->sql, 'update') && str_contains($query->sql, LifecycleTables::lockTable())) {
                $locks->append($query->sql);
            }

            if ($done >= $times || !str_starts_with($query->sql, 'delete') || !str_contains($query->sql, DeliveryTables::deliveriesTable())) {
                return;
            }

            $done++;

            $query->connection->table(EntrySettings::table())->where('id', $id)->delete();
        });

        return $locks;
    }

    /**
     * The sequence of every seal a run loads from now, in order.
     *
     * @return \ArrayObject<int, int>
     */
    private function sealLoads(): \ArrayObject
    {
        /** @var \ArrayObject<int, int> $loads */
        $loads = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($loads): void {
            $loadsASeal = str_starts_with($query->sql, 'select') && str_contains($query->sql, IntegrityTables::checkpointsTable());

            if (!$loadsASeal || preg_match('/[`"]?sequence[`"]?\s*=\s*\?/', $query->sql) !== 1) {
                return;
            }

            $loads->append((int) $query->bindings[0]);
        });

        return $loads;
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
     * The payloads of the journal's rows of the kind, in order.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @return list<array<array-key, mixed>>
     */
    private function payloadsOf(JournalKind $kind): array
    {
        $rows = array_values(array_filter($this->journalRows(), static fn (array $row): bool => $row['kind'] === $kind->value));

        return array_map(static fn (array $row): array => JournalRow::fromRow($row, true)->payloadMap() ?? [], $rows);
    }

    /**
     * Every prune record the journal holds, in order.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>
     */
    private function records(): array
    {
        return array_map(static function (array $payload): PruneRecord {
            self::assertIsArray($payload['record'] ?? null);

            return PruneRecord::fromArray($payload['record']);
        }, $this->payloadsOf(JournalKind::PRUNE));
    }

    /**
     * Verify the whole log through the journal's ledger, and return each
     * segment's integrity, in order.
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
     * The messages of every exception reported, in order.
     *
     * @return list<string>
     */
    private function reported(): array
    {
        return array_map(static fn (\Throwable $exception): string => $exception->getMessage(), $this->reporter?->reports() ?? []);
    }

    /**
     * The ids among those given whose entries are still stored, sorted.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private function present(array $ids): array
    {
        $present = array_map(strval(...), $this->maintenance()->table(EntrySettings::table())->whereIn('id', $ids)->pluck('id')->all());

        sort($present);

        $given = $ids;

        sort($given);

        return array_values(array_intersect($given, $present));
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
