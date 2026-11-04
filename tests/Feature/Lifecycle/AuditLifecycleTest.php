<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalPruneLedger;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecordFailedException;
use SineMacula\Laravel\AuditLog\Lifecycle\Pruner;
use SineMacula\Laravel\AuditLog\Lifecycle\Reconciler;
use SineMacula\Laravel\AuditLog\Lifecycle\UnknownHoldException;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for the lifecycle's way in: each operation commits first and is
 * recorded after, by its operator, or by no one for a prune; a record that
 * cannot be written leaves the operation standing and the result
 * `recorded: false`; a release of a hold that is not active is recorded
 * `denied` and rethrown; a prune is recorded under its run id, a failed one as
 * a failure and a dry run not at all; an import is recorded with its batch, its
 * hold as held, and a failure after its start as a failure before it is
 * rethrown; the active holds are read from the verified journal; and every
 * service is resolved again on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLifecycle::class)]
final class AuditLifecycleTest extends TestCase
{
    use ReadsTheTrail, SealsEntries, WritesTheJournal;

    /** @var string When every operation runs. */
    private const string NOW = '2026-12-15 15:00:00';

    /** @var string This installation's own source. */
    private const string OWN = 'app-eu-1';

    /** @var string The source every import is of. */
    private const string SOURCE = 'crm-eu';

    /** @var string A hold id no hold was ever placed under. */
    private const string UNKNOWN = '01932b4e-d000-7000-8000-00000000ffff';

    /** @var ?\Tests\Fixtures\Privacy\RecordingExceptionHandler What every failure is reported to. */
    private ?RecordingExceptionHandler $reporter = null;

    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Freeze the clock, keep entries thirty days, bind the configured policy
     * and the journal's prune ledger, name this installation's source and
     * report to a recording handler.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $config = app(ConfigRepository::class);

        $config->set('audit-log.retention.after_days', 30);
        $config->set('audit-log.source.id', self::OWN);

        app()->bind(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
        app()->bind(PruneLedger::class, JournalPruneLedger::class);

        $this->reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $this->reporter);
    }

    /**
     * Roll back any transaction a test left open, put the clock back and remove
     * the files this test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (DB::getConnections() as $connection) {
            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }

        CarbonImmutable::setTestNow();

        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        parent::tearDown();
    }

    /**
     * A hold is journalled and committed first, and its `audit_log.held`
     * record, by its operator, keeping exactly its evidence, is written only
     * after that commit.
     *
     * @return void
     */
    public function testAHoldIsRecordedAfterItCommits(): void
    {
        $order = $this->watchCommitsAndRecords();
        $scope = HoldScope::all()->categories('security');

        $result = $this->lifecycle()->hold($scope, self::authority(), HoldBasis::LEGAL_CLAIM, new CarbonImmutable('2027-05-01', 'UTC'));

        self::assertTrue($result->committed);
        self::assertTrue($result->recorded);
        self::assertSame($result->operationId, $result->hold->operationId);
        self::assertSame(['commit', 'record'], array_slice(array_values(array_unique($order->getArrayCopy())), 0, 2));
        self::assertSame([JournalKind::HOLD->value], array_column($this->journalRows(), 'kind'));

        $records = $this->readRecords('audit_log.held');

        self::assertCount(1, $records);
        self::assertSame(['App\Models\User', '7'], [$records[0]['actor_type'], $records[0]['actor_id']]);
        self::assertSame('success', $records[0]['outcome']);
        self::assertSameProperties([
            'operation_id'     => $result->operationId,
            'hold_id'          => $result->hold->id,
            'basis'            => 'legal_claim',
            'scope_digest'     => $scope->digest(),
            'review_by'        => '2027-05-01T00:00:00.000000Z',
            'authority_reason' => 'case.review',
            'outcome'          => 'success',
        ], self::propertiesOf($records[0]));
    }

    /**
     * A record that cannot be written never undoes the hold: the hold stays
     * placed and active, the failure is reported once, and the result says it
     * committed and was not recorded.
     *
     * @return void
     */
    public function testARecordingFailureLeavesTheHoldCommittedAndRecordedFalse(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['basis']);

        $result = $this->lifecycle()->hold(HoldScope::all(), self::authority(), HoldBasis::REGULATORY);

        self::assertTrue($result->committed);
        self::assertFalse($result->recorded);
        self::assertSame([], $this->readRecords('audit_log.held'));
        self::assertSame([$result->hold->id], array_map(static fn (Hold $hold): string => $hold->id, $this->lifecycle()->holds()));

        $reports = $this->reporter?->reports() ?? [];

        self::assertCount(1, $reports);
        self::assertInstanceOf(LifecycleRecordFailedException::class, $reports[0]);
    }

    /**
     * A release of a hold the verified journal does not hold active is recorded
     * `denied`, with `unknown_hold`, by the operator who asked, and the refusal
     * is rethrown; nothing is journalled.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnknownReleaseIsRecordedDeniedAndRethrown(): void
    {
        try {
            $this->lifecycle()->release(self::UNKNOWN, self::authority());

            self::fail('Expected the release to be refused.');
        } catch (UnknownHoldException $refusal) {
            self::assertStringContainsString(self::UNKNOWN, $refusal->getMessage());
        }

        $records = $this->readRecords('audit_log.released');

        self::assertCount(1, $records);
        self::assertSame(['denied', 'unknown_hold'], [$records[0]['outcome'], $records[0]['reason']]);
        self::assertSame(['App\Models\User', '7'], [$records[0]['actor_type'], $records[0]['actor_id']]);

        $properties = self::propertiesOf($records[0]);

        self::assertSamePropertyKeys(['operation_id', 'hold_id', 'authority_reason', 'outcome'], $properties);
        self::assertSame([self::UNKNOWN, 'case.review', 'denied'], [$properties['hold_id'], $properties['authority_reason'], $properties['outcome']]);
        self::assertSame([], $this->journalRows());
    }

    /**
     * A release refused for any other reason than an inactive hold, here on a
     * journal that fails verification, is rethrown and not recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReleaseRefusedOtherwiseIsNotRecorded(): void
    {
        $held = $this->lifecycle()->hold(HoldScope::all(), self::authority(), HoldBasis::INVESTIGATION);

        $this->tamperJournal(1, ['reason' => 'case.edited']);

        try {
            $this->lifecycle()->release($held->hold->id, self::authority());

            self::fail('Expected the release to be refused.');
        } catch (JournalBrokenException) {
            self::assertSame([], $this->readRecords('audit_log.released'));
        }
    }

    /**
     * A release of an active hold is journalled, then recorded a success under
     * its own operation, and returns the hold as it was.
     *
     * @return void
     */
    public function testAReleaseIsRecordedUnderItsOwnOperation(): void
    {
        $held     = $this->lifecycle()->hold(HoldScope::all(), self::authority(), HoldBasis::INVESTIGATION);
        $released = $this->lifecycle()->release($held->hold->id, new Authority(Reference::of('App\Models\User', '9'), 'case.closed'));

        self::assertTrue($released->committed);
        self::assertTrue($released->recorded);
        self::assertNotSame($held->operationId, $released->operationId);
        self::assertSame($held->hold->id, $released->hold->id);
        self::assertSame([], $this->lifecycle()->holds());

        $records = $this->readRecords('audit_log.released');

        self::assertCount(1, $records);
        self::assertSame(['App\Models\User', '9', 'success', null], [$records[0]['actor_type'], $records[0]['actor_id'], $records[0]['outcome'], $records[0]['reason']]);
        self::assertSameProperties([
            'operation_id'     => $released->operationId,
            'hold_id'          => $held->hold->id,
            'authority_reason' => 'case.closed',
            'outcome'          => 'success',
        ], self::propertiesOf($records[0]));
    }

    /**
     * A prune is recorded once it has finished, by no one, under the run id
     * every one of its journal rows names, with its counts.
     *
     * @return void
     */
    public function testAPruneIsRecordedWithItsRunId(): void
    {
        $this->storeEntries(3);
        $this->sealAll();

        $result = $this->lifecycle()->prune();

        self::assertSame([PruneStatus::COMPLETE, 3, 1], [$result->status, $result->deleted, $result->seals]);
        self::assertTrue($result->recorded);

        $runs = array_values(array_filter($this->journalRows(), static fn (array $row): bool => $row['kind'] !== JournalKind::POLICY->value));

        self::assertSame([$result->operationId], array_values(array_unique(array_column($runs, 'operation_id'))));

        $records = $this->readRecords('audit_log.pruned');

        self::assertCount(1, $records);
        self::assertSame([null, null, 'success'], [$records[0]['actor_type'], $records[0]['actor_id'], $records[0]['outcome']]);
        self::assertSameProperties([
            'operation_id'     => $result->operationId,
            'status'           => 'complete',
            'policy_version'   => $result->policyVersion,
            'deleted'          => 3,
            'seals'            => 1,
            'held'             => 0,
            'pending_delivery' => 0,
            'skipped_seals'    => 0,
            'categories'       => $result->categories,
            'tenants_affected' => $result->tenantsAffected,
            'outcome'          => 'success',
        ], self::propertiesOf($records[0]));
    }

    /**
     * A prune that fails, here on a journal that fails verification, is
     * recorded as a failure with the reason the run gives.
     *
     * @return void
     */
    public function testAFailedPruneIsRecordedAsAFailure(): void
    {
        $this->journalHold('01932b4e-d000-7000-8000-000000000001');
        $this->tamperJournal(1, ['reason' => 'case.edited']);

        $result = $this->lifecycle()->prune();

        self::assertSame([PruneStatus::FAILED, 'journal_broken'], [$result->status, $result->failure]);
        self::assertTrue($result->recorded);

        $records = $this->readRecords('audit_log.pruned');

        self::assertCount(1, $records);
        self::assertSame(['failure', 'journal_broken'], [$records[0]['outcome'], $records[0]['reason']]);
        self::assertSame(['failed', 'failure'], [self::propertiesOf($records[0])['status'] ?? null, self::propertiesOf($records[0])['outcome'] ?? null]);
    }

    /**
     * A dry run writes nothing, so it is not recorded: no record, and the
     * result says so.
     *
     * @return void
     */
    public function testADryRunPruneIsNotRecorded(): void
    {
        $this->storeEntries(2);
        $this->sealAll();

        $result = $this->lifecycle()->prune(true);

        self::assertTrue($result->dryRun);
        self::assertFalse($result->recorded);
        self::assertSame(0, $result->deleted);
        self::assertSame(2, array_sum(array_column($result->plan['pairs'] ?? [], 'eligible')));
        self::assertSame([], $this->readRecords('audit_log.pruned'));
        self::assertSame([], $this->journalRows());
    }

    /**
     * An import is recorded once it ends, by its operator, with its batch, its
     * source, its format, its status and its counts.
     *
     * @return void
     */
    public function testAnImportIsRecordedWithItsBatch(): void
    {
        $result = $this->lifecycle()->import(ImportSource::fromFile($this->file([self::line('rec-1'), self::line('rec-2'), '{']), self::SOURCE), self::authority());

        self::assertSame(ImportStatus::PARTIAL, $result->status);
        self::assertTrue($result->committed);
        self::assertTrue($result->recorded);
        self::assertNull($result->holdId);
        self::assertSame([], $this->readRecords('audit_log.held'));

        $records = $this->readRecords('audit_log.imported');

        self::assertCount(1, $records);
        self::assertSame(['App\Models\User', '7', 'success'], [$records[0]['actor_type'], $records[0]['actor_id'], $records[0]['outcome']]);
        self::assertSameProperties([
            'operation_id'     => $result->operationId,
            'batch_id'         => $result->batchId,
            'source_id'        => self::SOURCE,
            'format'           => 'audit-log-import/v1',
            'status'           => 'partial',
            'lines_read'       => 3,
            'imported'         => 2,
            'duplicates'       => 0,
            'conflicts'        => 0,
            'rejected'         => 1,
            'hold_id'          => null,
            'authority_reason' => 'case.review',
            'outcome'          => 'success',
        ], self::propertiesOf($records[0]));
    }

    /**
     * A dry run of an import writes nothing, so it is not recorded.
     *
     * @return void
     */
    public function testADryRunImportIsNotRecorded(): void
    {
        $result = $this->lifecycle()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority(), true, true);

        self::assertTrue($result->dryRun);
        self::assertFalse($result->recorded);
        self::assertSame(1, $result->imported);
        self::assertSame([], $this->readRecords());
        self::assertSame([], $this->journalRows());
    }

    /**
     * The hold an import places with its start is recorded as held, under the
     * import's operation, as the import is recorded with it, so a
     * reconciliation never finds it missing.
     *
     * @return void
     */
    public function testAnImportsHoldIsRecordedHeld(): void
    {
        $source = ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE);
        $result = $this->lifecycle()->import($source, self::authority(), hold: true, basis: HoldBasis::LEGAL_CLAIM);

        self::assertNotNull($result->batchId);
        self::assertNotNull($result->holdId);
        self::assertTrue($result->recorded);
        self::assertEqualsCanonicalizing(['audit_log.held', 'audit_log.imported'], array_column($this->readRecords(), 'event'));

        $held = $this->readRecords('audit_log.held')[0];

        self::assertSameProperties([
            'operation_id'     => $result->operationId,
            'hold_id'          => $result->holdId,
            'basis'            => 'legal_claim',
            'scope_digest'     => HoldScope::all()->importBatch($result->batchId)->digest(),
            'review_by'        => null,
            'authority_reason' => 'case.review',
            'outcome'          => 'success',
        ], self::propertiesOf($held));

        self::assertSame($result->holdId, self::propertiesOf($this->readRecords('audit_log.imported')[0])['hold_id'] ?? null);
    }

    /**
     * An import whose hold could not be recorded says so on its result, though
     * the import itself is recorded and the hold placed.
     *
     * @return void
     */
    public function testAnImportWhoseHoldWentUnrecordedSaysSo(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['basis']);

        $result = $this->lifecycle()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority(), hold: true);

        self::assertFalse($result->recorded);
        self::assertSame(['audit_log.imported'], array_column($this->readRecords(), 'event'));
        self::assertCount(1, $this->lifecycle()->holds());
    }

    /**
     * An import that fails once its start committed is recorded as a failure,
     * `import_failed`, with the counts its batch holds, after the hold it
     * placed is recorded as held, and the failure is rethrown; the hold stays.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedImportIsRecordedAndRethrown(): void
    {
        DB::listen(static function (QueryExecuted $query): void {
            $imported = in_array('invoice.approved', $query->bindings, true);

            if ($imported && str_starts_with(strtolower($query->sql), 'insert') && str_contains($query->sql, EntrySettings::table())) {
                throw new \RuntimeException('The entries could not be written.');
            }
        });

        try {
            $this->lifecycle()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::SOURCE), self::authority(), hold: true);

            self::fail('Expected the import to fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The entries could not be written.', $exception->getMessage());
        }

        self::assertEqualsCanonicalizing(['audit_log.held', 'audit_log.imported'], array_column($this->readRecords(), 'event'));

        $record = $this->readRecords('audit_log.imported')[0];
        $batch  = (array) DB::connection(StorageConnection::name())->table(LifecycleTables::importBatchesTable())->first();

        self::assertSame(['failure', 'import_failed'], [$record['outcome'], $record['reason']]);
        self::assertSame(1, (int) $batch['lines_read']);
        self::assertSameProperties([
            'operation_id'     => self::propertiesOf($this->readRecords('audit_log.held')[0])['operation_id'] ?? null,
            'batch_id'         => $batch['id'],
            'source_id'        => self::SOURCE,
            'format'           => 'audit-log-import/v1',
            'status'           => 'failed',
            'lines_read'       => (int) $batch['lines_read'],
            'imported'         => (int) $batch['imported'],
            'duplicates'       => (int) $batch['duplicates'],
            'conflicts'        => (int) $batch['conflicts'],
            'rejected'         => (int) $batch['rejected'],
            'hold_id'          => $batch['hold_id'],
            'authority_reason' => 'case.review',
            'outcome'          => 'failure',
        ], self::propertiesOf($record));
        self::assertCount(1, $this->lifecycle()->holds());
    }

    /**
     * An import refused before its start, here because its source is this
     * installation, records nothing and is rethrown.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnImportRefusedBeforeItsStartIsNotRecorded(): void
    {
        try {
            $this->lifecycle()->import(ImportSource::fromFile($this->file([self::line('rec-1')]), self::OWN), self::authority());

            self::fail('Expected the import to be refused.');
        } catch (\InvalidArgumentException) {
            self::assertSame([], $this->readRecords());
        }
    }

    /**
     * Closing a running batch whose import stopped records the import as a
     * failure, `interrupted`, under the close's own operation, with the source
     * and format its batch row holds.
     *
     * @return void
     */
    public function testAClosedImportIsRecordedInterrupted(): void
    {
        $batchId = '01932b4e-a000-7000-8000-0000000000e1';

        $this->runningBatch($batchId);

        $result = $this->lifecycle()->closeImport($batchId, self::authority());

        self::assertSame(ImportStatus::INTERRUPTED, $result->status);
        self::assertTrue($result->recorded);

        $record = $this->readRecords('audit_log.imported')[0];

        self::assertSame(['failure', 'interrupted'], [$record['outcome'], $record['reason']]);
        self::assertSameProperties([
            'operation_id'     => $result->operationId,
            'batch_id'         => $batchId,
            'source_id'        => 'crm-killed',
            'format'           => 'audit-log-import/v1',
            'status'           => 'interrupted',
            'lines_read'       => 0,
            'imported'         => 0,
            'duplicates'       => 0,
            'conflicts'        => 0,
            'rejected'         => 0,
            'hold_id'          => null,
            'authority_reason' => 'case.review',
            'outcome'          => 'failure',
        ], self::propertiesOf($record));
    }

    /**
     * The active holds are replayed from the verified journal, never read from
     * the projection: a projection row deleted changes nothing, and a journal
     * that fails verification is refused.
     *
     * @return void
     */
    public function testHoldsAreReadFromTheVerifiedChain(): void
    {
        $first  = $this->lifecycle()->hold(HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM);
        $second = $this->lifecycle()->hold(HoldScope::tenantless(), self::authority(), HoldBasis::OTHER);

        DB::connection(StorageConnection::name())->table(LifecycleTables::holdsTable())->delete();

        self::assertSame([$first->hold->id, $second->hold->id], array_map(static fn (Hold $hold): string => $hold->id, $this->lifecycle()->holds()));

        $this->tamperJournal(2, ['reason' => 'case.edited']);

        $this->expectException(JournalBrokenException::class);

        $this->lifecycle()->holds();
    }

    /**
     * Rebuilding the projection puts back what the journal holds, and says how
     * many holds it holds.
     *
     * @return void
     */
    public function testRebuildingTheProjectionPutsBackWhatTheJournalHolds(): void
    {
        $this->lifecycle()->hold(HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM);

        $holds = DB::connection(StorageConnection::name())->table(LifecycleTables::holdsTable());

        $holds->delete();

        self::assertSame(1, $this->lifecycle()->rebuildHolds());
        self::assertSame(1, $holds->count());
    }

    /**
     * Reconciling writes the record the journal says is missing, once.
     *
     * @return void
     */
    public function testReconcilingWritesAMissingRecordOnce(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['basis']);

        $this->lifecycle()->hold(HoldScope::all(), self::authority(), HoldBasis::LEGAL_CLAIM);

        app(ConfigRepository::class)->set('audit-log.redaction.keys', []);

        self::assertSame(1, $this->lifecycle()->reconcile()->recorded);
        self::assertSame([0, 1], [$this->lifecycle()->reconcile(1)->recorded, $this->lifecycle()->reconcile(1)->alreadyRecorded]);
        self::assertCount(1, $this->readRecords('audit_log.held'));
    }

    /**
     * Every operation resolves its service from the container on every call, so
     * one way into the lifecycle outlives requests and follows rebinding.
     *
     * @return void
     */
    public function testItResolvesItsServicesOnEveryCall(): void
    {
        $resolved = [];

        foreach ([HoldKeeper::class, Pruner::class, Reconciler::class] as $service) {
            app()->resolving($service, static function () use (&$resolved, $service): void {
                $resolved[] = $service;
            });
        }

        $lifecycle = $this->lifecycle();

        $lifecycle->holds();
        $lifecycle->holds();
        $lifecycle->prune(true);
        $lifecycle->prune(true);
        $lifecycle->reconcile();
        $lifecycle->reconcile();

        self::assertSame([HoldKeeper::class, HoldKeeper::class, Pruner::class, Pruner::class, Reconciler::class, Reconciler::class], $resolved);
    }

    /**
     * Record, in order, each commit of a transaction and each insert into the
     * entries table.
     *
     * @return \ArrayObject<int, string>
     */
    private function watchCommitsAndRecords(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $order */
        $order = new \ArrayObject;

        Event::listen(TransactionCommitted::class, static function () use ($order): void {
            $order[] = 'commit';
        });

        DB::listen(static function (QueryExecuted $query) use ($order): void {
            if (!str_starts_with(strtolower($query->sql), 'insert') || !str_contains($query->sql, EntrySettings::table())) {
                return;
            }

            $order[] = 'record';
        });

        return $order;
    }

    /**
     * Start a batch as an import whose process was then killed leaves it: its
     * row `running` and its journal's `import_started`, and nothing after.
     *
     * @param  string  $batchId
     * @return void
     */
    private function runningBatch(string $batchId): void
    {
        DB::connection(StorageConnection::name())->table(LifecycleTables::importBatchesTable())->insert([
            'id'                  => $batchId,
            'source_id'           => 'crm-killed',
            'source_region'       => null,
            'input_format'        => 'audit-log-import/v1',
            'importer_type'       => 'App\Models\User',
            'importer_id'         => '7',
            'reason'              => 'case.review',
            'external_reference'  => null,
            'file_sha256'         => str_repeat('f', 64),
            'externally_verified' => false,
            'hold_id'             => null,
            'status'              => 'running',
            'lines_read'          => 0,
            'imported'            => 0,
            'duplicates'          => 0,
            'conflicts'           => 0,
            'rejected'            => 0,
            'conflict_ids'        => null,
            'started_at'          => '2026-12-15 14:00:00.000000',
            'updated_at'          => '2026-12-15 14:00:00.000000',
            'finished_at'         => null,
        ]);

        $this->journalRow(JournalKind::IMPORT_STARTED, [
            'batch_id'            => $batchId,
            'source_id'           => 'crm-killed',
            'source_region'       => null,
            'format'              => 'audit-log-import/v1',
            'file_sha256'         => str_repeat('f', 64),
            'externally_verified' => false,
            'hold_id'             => null,
        ]);
    }

    /**
     * A line of the import format, of the record id given.
     *
     * @param  string  $recordId
     * @return string
     */
    private static function line(string $recordId): string
    {
        return (string) json_encode([
            'format'           => 'audit-log-import/v1',
            'source_record_id' => $recordId,
            'occurred_at'      => '2026-12-01T09:00:00.000001Z',
            'event'            => 'invoice.approved',
            'outcome'          => 'success',
            'actor'            => ['type' => 'user', 'id' => '42'],
            'category'         => 'finance',
            'properties'       => ['amount' => '1200.00'],
        ]);
    }

    /**
     * Write a file of the lines given, and return its path.
     *
     * @param  list<string>  $lines
     * @return string
     */
    private function file(array $lines): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'lifecycle-');

        file_put_contents($path, implode("\n", $lines) . "\n");

        $this->files[] = $path;

        return $path;
    }

    /**
     * The authority every operation is asked for on, unless a test gives
     * another.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review', 'app:ticket-123');
    }

    /**
     * The lifecycle the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle
     */
    private function lifecycle(): AuditLifecycle
    {
        return app(AuditLifecycle::class);
    }
}
