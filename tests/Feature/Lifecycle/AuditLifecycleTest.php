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
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint;
use SineMacula\Laravel\AuditLog\Keys\KeyUseRebuilder;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\RewrapStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Eraser;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureReapplier;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalPruneLedger;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecordFailedException;
use SineMacula\Laravel\AuditLog\Lifecycle\Pruner;
use SineMacula\Laravel\AuditLog\Lifecycle\Reconciler;
use SineMacula\Laravel\AuditLog\Lifecycle\ReinstatementRefusedException;
use SineMacula\Laravel\AuditLog\Lifecycle\Reinstater;
use SineMacula\Laravel\AuditLog\Lifecycle\Rewrapper;
use SineMacula\Laravel\AuditLog\Lifecycle\UnknownHoldException;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Capture\Models\Tag;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\TestCase;

/**
 * Feature tests for the lifecycle's way in: each operation commits first and is
 * recorded after, by its operator, or by no one for a prune; a record that
 * cannot be written leaves the operation standing and the result `recorded:
 * false`; a release of a hold that is not active is recorded `denied` and
 * rethrown; a prune is recorded under its run id, a failed one as a failure and
 * a dry run not at all; an import is recorded with its batch, its hold as held,
 * and a failure after its start as a failure before it is rethrown; an erasure,
 * a reinstatement and a rewrap are recorded after their commits, a refusal
 * `denied` and rethrown and a failure as a failure, and the erasure's record
 * reaches the destinations as any package record does; a reapply erases each
 * owner as `erase()` does; the active holds are read from the verified journal;
 * and every service is resolved again on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLifecycle::class)]
final class AuditLifecycleTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail, SealsEntries;

    /** @var string The type of the owner every privacy operation names. */
    private const string OWNER_TYPE = 'App\Models\Customer';

    /** @var string The id of the owner every privacy operation names: a sentinel no hex, base64url or UUID holds by chance. */
    private const string OWNER_ID = 'owner-sentinel';

    /** @var string When every operation runs. */
    private const string NOW = '2026-12-15 15:00:00';

    /** @var string This installation's own source. */
    private const string OWN = 'app-eu-1';

    /** @var string The source every import is of. */
    private const string SOURCE = 'crm-eu';

    /** @var string A hold id no hold was ever placed under. */
    private const string UNKNOWN = '01932b4e-d000-7000-8000-00000000ffff';

    /** @var string The code a card charge, encrypted under its actor's key, is captured under. */
    private const string CARD = 'billing.card_charged';

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
     * An erasure is journalled and committed first, and its
     * `audit_log.subject_erased` record, by the authority's operator, of no
     * subject and no tenant, naming the owner by its fingerprint alone and
     * keeping exactly its evidence, is written only after that commit.
     *
     * @return void
     */
    public function testAnErasureIsRecordedAfterItsCommit(): void
    {
        $this->makeSubjectKey(self::owner(), null, 'billing');

        $order  = $this->watchCommitsAndRecords();
        $result = $this->lifecycle()->erase(self::owner(), self::authority());

        self::assertTrue($result->committed);
        self::assertTrue($result->recorded);
        self::assertSame([ErasureStatus::COMPLETE, 1, 0], [$result->status, $result->keysDestroyed, $result->keysKept]);
        self::assertSame(['commit', 'record'], array_slice(array_values(array_unique($order->getArrayCopy())), 0, 2));
        self::assertSame([JournalKind::ERASURE->value], array_column($this->journalRows(), 'kind'));
        self::assertSame($result->erasureId, $this->journalRows()[0]['id']);

        $records = $this->readRecords('audit_log.subject_erased');

        self::assertCount(1, $records);
        self::assertSame(['App\Models\User', '7', null, null, null, null], [
            $records[0]['actor_type'], $records[0]['actor_id'], $records[0]['subject_type'], $records[0]['subject_id'], $records[0]['tenant_type'], $records[0]['tenant_id'],
        ]);
        self::assertSame(['success', null], [$records[0]['outcome'], $records[0]['reason']]);
        self::assertSameProperties(self::erasedProperties($result->operationId, $result->erasureId, 'complete', [1, 0, 0], [], 'success'), self::propertiesOf($records[0]));
        $properties = self::propertiesOf($records[0]);
        $encoded    = (string) json_encode($properties);

        self::assertStringNotContainsString(self::OWNER_ID, $encoded);
        self::assertStringNotContainsString(trim((string) json_encode(self::OWNER_TYPE), '"'), $encoded);
        self::assertSame([], array_intersect(['owner_type', 'owner_id'], array_keys($properties)));
    }

    /**
     * An erasure a hold blocks is refused, recorded `denied` with `blocked`,
     * naming the hold in its `blocked`, and rethrown; nothing is journalled but
     * the hold.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedErasureIsRecordedDeniedAndRethrown(): void
    {
        $this->captureCards();
        $this->chargeCard(self::owner());

        $hold = $this->lifecycle()->hold(HoldScope::all()->categories('billing'), self::authority(), HoldBasis::LEGAL_CLAIM)->hold;

        try {
            $this->lifecycle()->erase(self::owner(), self::authority());

            self::fail('Expected the erasure to be refused.');
        } catch (ErasureRefusedException $refusal) {
            self::assertSame(ErasureRefusal::BLOCKED, $refusal->refusal());
        }

        $records = $this->readRecords('audit_log.subject_erased');

        self::assertCount(1, $records);
        self::assertSame(['denied', 'blocked'], [$records[0]['outcome'], $records[0]['reason']]);
        $expected = self::erasedProperties(self::operationOf($records[0]), null, null, [0, 0, 0], ['held:' . $hold->id => 1], 'denied');

        self::assertSameProperties($expected, self::propertiesOf($records[0]));
        self::assertSame([JournalKind::HOLD->value], array_column($this->journalRows(), 'kind'));
    }

    /**
     * An erasure refused for anything but a block, here a custom encrypter, is
     * recorded `denied` with its refusal and blocked by nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalOtherThanABlockNamesNoBlock(): void
    {
        app()->bind(FieldEncrypter::class, RecordingFieldEncrypter::class);

        try {
            $this->lifecycle()->erase(self::owner(), self::authority());

            self::fail('Expected the erasure to be refused.');
        } catch (ErasureRefusedException $refusal) {
            self::assertSame(ErasureRefusal::UNSUPPORTED_ENCRYPTER, $refusal->refusal());
        }

        $records = $this->readRecords('audit_log.subject_erased');

        self::assertCount(1, $records);
        self::assertSame(['denied', 'unsupported_encrypter'], [$records[0]['outcome'], $records[0]['reason']]);
        self::assertSame([], self::propertiesOf($records[0])['blocked']);
        self::assertStringNotContainsString(RecordingFieldEncrypter::class, (string) json_encode(self::propertiesOf($records[0])));
    }

    /**
     * An erasure that fails, here on a journal that does not verify, is
     * recorded as a failure with `journal_broken` and rethrown; any other
     * failure is `erasure_failed`, named by a code and never its message.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedErasureIsRecordedAsAFailureAndRethrown(): void
    {
        $this->lifecycle()->hold(HoldScope::all(), self::authority(), HoldBasis::OTHER);
        $this->tamperJournal(1, ['reason' => 'case.edited']);

        try {
            $this->lifecycle()->erase(self::owner(), self::authority());

            self::fail('Expected the erasure to fail.');
        } catch (JournalBrokenException) {
            // The failure is rethrown as it was
        }

        $this->failing(Eraser::class, new \RuntimeException('SQLSTATE[HY000]: secret-42 bound'));

        try {
            $this->lifecycle()->erase(self::owner(), self::authority());

            self::fail('Expected the erasure to fail.');
        } catch (\RuntimeException $failure) {
            self::assertStringContainsString('secret-42', $failure->getMessage());
        }

        $records      = $this->readRecords('audit_log.subject_erased');
        $fingerprints = array_map(static fn (array $record): mixed => self::propertiesOf($record)['owner_fingerprint'], $records);

        self::assertSame(['failure:erasure_failed', 'failure:journal_broken'], self::endings($records));
        self::assertStringNotContainsString('secret-42', (string) json_encode($records));
        self::assertSame(array_fill(0, 2, app(OwnerFingerprint::class)->of(self::owner())[1]), $fingerprints);
    }

    /**
     * A record that cannot be written never undoes the erasure: its keys stay
     * destroyed, the failure is reported once, the result says it committed and
     * was not recorded, and a reconciliation writes the record later.
     *
     * @return void
     */
    public function testARecordingFailureLeavesTheErasureCommitted(): void
    {
        $this->makeSubjectKey(self::owner(), null, 'billing');

        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['entries_affected']);

        $result = $this->lifecycle()->erase(self::owner(), self::authority());

        self::assertTrue($result->committed);
        self::assertFalse($result->recorded);
        self::assertSame([], $this->readRecords('audit_log.subject_erased'));
        self::assertSame(['erased'], array_values(array_map(static fn ($key): string => $key->state->value, $this->storedSubjectKeys())));

        $reports = $this->reporter?->reports() ?? [];

        self::assertCount(1, $reports);
        self::assertInstanceOf(LifecycleRecordFailedException::class, $reports[0]);

        app(ConfigRepository::class)->set('audit-log.redaction.keys', []);

        self::assertSame(1, $this->lifecycle()->reconcile()->recorded);
        self::assertSameProperties(
            self::erasedProperties($result->operationId, $result->erasureId, 'complete', [1, 0, 0], [], 'success'),
            self::propertiesOf($this->readRecords('audit_log.subject_erased')[0]),
        );
    }

    /**
     * An owner already erased that holds no key is recorded `already_erased`,
     * naming no journal row, and nothing more is journalled.
     *
     * @return void
     */
    public function testAnAlreadyErasedOwnerIsRecordedAlreadyErased(): void
    {
        $this->lifecycle()->erase(self::owner(), self::authority());

        $result  = $this->lifecycle()->erase(self::owner(), self::authority());
        $records = $this->readRecords('audit_log.subject_erased');

        $statuses = array_map(static fn (array $record): mixed => self::propertiesOf($record)['status'], $records);

        sort($statuses);

        self::assertSame([ErasureStatus::ALREADY_ERASED, null, true], [$result->status, $result->erasureId, $result->recorded]);
        self::assertSame(['already_erased', 'complete'], $statuses);
        self::assertCount(1, $this->journalRows());
    }

    /**
     * A model is erased as the reference it makes, by its morph class and key.
     *
     * @return void
     */
    public function testAModelIsErasedByItsReference(): void
    {
        $tag = (new Tag)->forceFill(['id' => 42]);

        $result = $this->lifecycle()->erase($tag, self::authority());

        self::assertSame(app(OwnerFingerprint::class)->of(Reference::to($tag))[1], $result->fingerprint);
        self::assertSame(app(OwnerFingerprint::class)->of(Reference::to($tag))[1], $this->lifecycle()->reinstate($tag, self::authority())->fingerprint);
    }

    /**
     * A reinstatement is journalled and committed first, and its
     * `audit_log.keys_reinstated` record, keeping exactly its evidence, is
     * written after that commit by the authority's operator.
     *
     * @return void
     */
    public function testAReinstatementIsRecorded(): void
    {
        $this->makeSubjectKey(self::owner(), null, 'billing');
        $this->lifecycle()->erase(self::owner(), self::authority());

        $order  = $this->watchCommitsAndRecords();
        $result = $this->lifecycle()->reinstate(self::owner(), self::authority());

        self::assertTrue($result->committed);
        self::assertTrue($result->recorded);
        self::assertSame(1, $result->generationFloor);
        self::assertSame(['commit', 'record'], array_slice(array_values(array_unique($order->getArrayCopy())), 0, 2));

        [$fingerprintKey, $fingerprint] = app(OwnerFingerprint::class)->of(self::owner());

        $records = $this->readRecords('audit_log.keys_reinstated');

        self::assertCount(1, $records);
        self::assertSame(['success', 'App\Models\User', '7'], [$records[0]['outcome'], $records[0]['actor_type'], $records[0]['actor_id']]);
        self::assertSameProperties([
            'operation_id'      => $result->operationId,
            'reinstatement_id'  => $result->reinstatementId,
            'owner_fingerprint' => $fingerprint,
            'fingerprint_key'   => $fingerprintKey,
            'generation_floor'  => 1,
            'authority_reason'  => 'case.review',
            'outcome'           => 'success',
        ], self::propertiesOf($records[0]));
    }

    /**
     * A reinstatement of an owner who is not erased is recorded `denied` with
     * `not_erased` and rethrown, naming no row and no floor; nothing is
     * journalled.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedReinstatementIsRecordedDenied(): void
    {
        try {
            $this->lifecycle()->reinstate(self::owner(), self::authority());

            self::fail('Expected the reinstatement to be refused.');
        } catch (ReinstatementRefusedException $refusal) {
            self::assertSame('not_erased', $refusal->reason);
        }

        $records = $this->readRecords('audit_log.keys_reinstated');

        self::assertCount(1, $records);
        self::assertSame(['denied', 'not_erased'], [$records[0]['outcome'], $records[0]['reason']]);
        self::assertSame([null, null], [self::propertiesOf($records[0])['reinstatement_id'], self::propertiesOf($records[0])['generation_floor']]);
        self::assertSame([], $this->journalRows());
    }

    /**
     * A reinstatement that fails otherwise, here on a journal that does not
     * verify, is rethrown and not recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReinstatementFailingOtherwiseIsNotRecorded(): void
    {
        $this->lifecycle()->erase(self::owner(), self::authority());
        $this->tamperJournal(1, ['reason' => 'case.edited']);

        try {
            $this->lifecycle()->reinstate(self::owner(), self::authority());

            self::fail('Expected the reinstatement to fail.');
        } catch (JournalBrokenException) {
            // The failure is rethrown as it was
        }

        self::assertSame([], $this->readRecords('audit_log.keys_reinstated'));
    }

    /**
     * A rewrap is journalled a batch at a time, and its
     * `audit_log.keys_rewrapped` record, keeping exactly its counts, is written
     * after its commits by the authority's operator.
     *
     * @return void
     */
    public function testARewrapIsRecorded(): void
    {
        $this->makeSubjectKey(self::owner(), null, 'billing');

        $result = $this->lifecycle()->rewrap(self::authority(), true);

        self::assertTrue($result->committed);
        self::assertTrue($result->recorded);
        self::assertSame([RewrapStatus::COMPLETE, 0, 1, 1], [$result->status, $result->rewrapped, $result->rotated, $result->batches]);

        $records = $this->readRecords('audit_log.keys_rewrapped');

        self::assertCount(1, $records);
        self::assertSame(['success', null, 'App\Models\User'], [$records[0]['outcome'], $records[0]['reason'], $records[0]['actor_type']]);
        self::assertSameProperties([
            'operation_id'     => $result->operationId,
            'status'           => 'complete',
            'keys_rewrapped'   => 0,
            'keys_rotated'     => 1,
            'keys_skipped'     => 0,
            'wrap_key_id'      => $this->keyWrapper()->currentKeyId(),
            'batches'          => 1,
            'authority_reason' => 'case.review',
            'outcome'          => 'success',
        ], self::propertiesOf($records[0]));
    }

    /**
     * A dry run rewraps nothing and records nothing, and a dry run that fails
     * is rethrown unrecorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADryRunRewrapIsNotRecorded(): void
    {
        $this->makeSubjectKey(self::owner(), null, 'billing');

        $result = $this->lifecycle()->rewrap(self::authority(), true, true);

        self::assertSame([false, false, 1], [$result->committed, $result->recorded, $result->rotated]);

        $this->failing(Rewrapper::class, new \RuntimeException('The dry run failed.'));

        try {
            $this->lifecycle()->rewrap(self::authority(), false, true);

            self::fail('Expected the dry run to fail.');
        } catch (\RuntimeException) {
            // The failure is rethrown as it was
        }

        self::assertSame([], $this->readRecords('audit_log.keys_rewrapped'));
        self::assertSame([], $this->journalRows());
    }

    /**
     * A rewrap that fails is recorded as a failure, `journal_broken` for a
     * journal that does not verify and `rewrap_failed` otherwise, counting
     * nothing, and rethrown.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedRewrapIsRecordedAsAFailure(): void
    {
        $this->keyWrapper();
        $this->lifecycle()->hold(HoldScope::all(), self::authority(), HoldBasis::OTHER);
        $this->tamperJournal(1, ['reason' => 'case.edited']);

        try {
            $this->lifecycle()->rewrap(self::authority());

            self::fail('Expected the rewrap to fail.');
        } catch (JournalBrokenException) {
            // The failure is rethrown as it was
        }

        $this->failing(Rewrapper::class, new \RuntimeException('The wrapper is down.'));

        try {
            $this->lifecycle()->rewrap(self::authority());

            self::fail('Expected the rewrap to fail.');
        } catch (\RuntimeException) {
            // The failure is rethrown as it was
        }

        $records = $this->readRecords('audit_log.keys_rewrapped');

        self::assertSame(['failure:journal_broken', 'failure:rewrap_failed'], self::endings($records));

        foreach ($records as $record) {
            $properties = self::propertiesOf($record);

            self::assertSame([null, null, null, null], [$properties['status'], $properties['keys_rewrapped'], $properties['wrap_key_id'], $properties['batches']]);
        }
    }

    /**
     * The erasure's record is delivered like any package record: queued in the
     * outbox once the erasure commits, and stored and announced as
     * `AuditRecorded` when the outbox drains to the destinations.
     *
     * @return void
     */
    public function testTheSubjectErasedRecordReachesTheDestinations(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::OUTBOX->value);

        $this->makeSubjectKey(self::owner(), null, 'billing');

        $result = $this->lifecycle()->erase(self::owner(), self::authority());

        self::assertTrue($result->recorded);
        self::assertSame([], $this->readRecords('audit_log.subject_erased'));
        self::assertSame(1, DB::connection(DeliveryTables::resolvedOutboxConnection())->table(DeliveryTables::outboxTable())->count());

        $announced = [];

        Event::listen(AuditRecorded::class, static function (AuditRecorded $event) use (&$announced): void {
            $announced[] = $event->code;
        });

        self::assertSame(1, app(OutboxDrainer::class)->drain(100, false)->delivered());
        self::assertSame(['audit_log.subject_erased'], $announced);
        self::assertSame($result->operationId, self::operationOf($this->readRecords('audit_log.subject_erased')[0]));
    }

    /**
     * Erasing again from a file erases each owner as `erase()` does, each
     * recorded, and journals the restore reconciled.
     *
     * @return void
     */
    public function testReapplyingErasesEachOwnerAsEraseDoes(): void
    {
        $this->makeSubjectKey(self::owner(), null, 'billing');

        $resolved = 0;

        app()->resolving(ErasureReapplier::class, static function () use (&$resolved): void {
            $resolved++;
        });

        $result = $this->lifecycle()->reapplyErasures($this->file(['{"type":"App\\\Models\\\User","id":"42"}', '{"type":"App\\\Models\\\User","id":"43"}']), self::authority());

        self::assertTrue($result->reconciled);
        self::assertTrue($result->recorded);
        self::assertSame([2, 2, 0], [$result->owners, $result->erased, $result->alreadyErased]);
        self::assertSame(1, $resolved);
        self::assertCount(2, $this->readRecords('audit_log.subject_erased'));
        self::assertSame([JournalKind::ERASURE->value, JournalKind::ERASURE->value, JournalKind::RESTORE_RECONCILED->value], array_column($this->journalRows(), 'kind'));
    }

    /**
     * Rebuilding the key uses adds the ones missing from the verified entries,
     * and a dry run counts them and adds nothing.
     *
     * @return void
     */
    public function testRebuildingTheKeyUsesAddsWhatIsMissing(): void
    {
        $this->captureCards();
        $this->chargeCard(self::owner());

        DB::connection(StorageConnection::name())->table(KeyTables::keyUsesTable())->delete();

        self::assertSame([1, 1, 0, 1, true], array_values($this->lifecycle()->rebuildKeyUses(true)->toArray()));
        self::assertSame(0, DB::connection(StorageConnection::name())->table(KeyTables::keyUsesTable())->count());
        self::assertSame(1, $this->lifecycle()->rebuildKeyUses()->added);
        self::assertSame(1, DB::connection(StorageConnection::name())->table(KeyTables::keyUsesTable())->count());
    }

    /**
     * The privacy operations resolve their services from the container on every
     * call.
     *
     * @return void
     */
    public function testThePrivacyOperationsResolveTheirServicesOnEveryCall(): void
    {
        $this->keyWrapper();

        $resolved = [];

        foreach ([Eraser::class, Reinstater::class, Rewrapper::class, KeyUseRebuilder::class] as $service) {
            app()->resolving($service, static function () use (&$resolved, $service): void {
                $resolved[] = $service;
            });
        }

        $lifecycle = $this->lifecycle();

        $lifecycle->erase(self::owner(), self::authority());
        $lifecycle->erase(self::owner(), self::authority());
        $lifecycle->reinstate(self::owner(), self::authority());
        $lifecycle->rewrap(self::authority(), false, true);
        $lifecycle->rewrap(self::authority(), false, true);
        $lifecycle->rebuildKeyUses(true);
        $lifecycle->rebuildKeyUses(true);

        self::assertSame([Eraser::class, Eraser::class, Reinstater::class, Rewrapper::class, Rewrapper::class, KeyUseRebuilder::class, KeyUseRebuilder::class], $resolved);
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
     * Bind the service to a factory that fails with the failure, so every
     * operation that resolves it throws.
     *
     * @param  class-string  $service
     * @param  \Throwable  $failure
     * @return void
     *
     * @throws \Throwable
     */
    private function failing(string $service, \Throwable $failure): void
    {
        app()->bind($service, static fn (): never => throw $failure);
    }

    /**
     * How each record ended, as its outcome, a colon and its reason, sorted.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<array<string, mixed>>  $records
     * @return list<string>
     */
    private static function endings(array $records): array
    {
        $endings = array_map(static fn (array $record): string => sprintf('%s:%s', $record['outcome'], $record['reason'] ?? ''), $records);

        sort($endings);

        return $endings;
    }

    /**
     * The properties an erasure's record keeps, in its code's order, for the
     * owner every test erases, on the authority every test gives.
     *
     * @param  string  $operationId
     * @param  ?string  $erasureId
     * @param  ?string  $status
     * @param  array{0: int, 1: int, 2: int}  $counts
     * @param  array<string, int>  $blocked
     * @param  string  $outcome
     * @return array<string, array<string, int>|bool|int|string|null>
     */
    private static function erasedProperties(string $operationId, ?string $erasureId, ?string $status, array $counts, array $blocked, string $outcome): array
    {
        [$fingerprintKey, $fingerprint] = app(OwnerFingerprint::class)->of(self::owner());

        return [
            'operation_id'      => $operationId,
            'erasure_id'        => $erasureId,
            'owner_fingerprint' => $fingerprint,
            'fingerprint_key'   => $fingerprintKey,
            'status'            => $status,
            'keys_destroyed'    => $counts[0],
            'keys_kept'         => $counts[1],
            'entries_affected'  => $counts[2],
            'blocked'           => $blocked,
            'pending_accepted'  => false,
            'authority_reason'  => 'case.review',
            'outcome'           => $outcome,
        ];
    }

    /**
     * The operation a record's properties name.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $record
     * @return string
     */
    private static function operationOf(array $record): string
    {
        $operationId = self::propertiesOf($record)['operation_id'] ?? null;

        self::assertIsString($operationId);

        return $operationId;
    }

    /**
     * Bind the package's encrypter and reader, and define the card charge, its
     * card encrypted under its actor's key, as the only code the facade's
     * recorder knows.
     *
     * @return void
     */
    private function captureCards(): void
    {
        $this->keyWrapper();

        app()->bind(FieldEncrypter::class, SubjectKeyEncrypter::class);
        app()->bind(FieldReader::class, SubjectKeyFieldReader::class);

        $catalogue = new EventCatalogue;

        $catalogue->define(EventDefinition::for(self::CARD)->category('billing')->retain('amount')->encrypt('card', KeyOwner::ACTOR));

        $recorder = new Recorder($catalogue, new ContributorRegistry);

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, $recorder);

        AuditLog::swap($recorder);
    }

    /**
     * Capture a charge of a card the actor owns, encrypted under the actor's
     * key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @return void
     */
    private function chargeCard(Reference $actor): void
    {
        AuditLog::event(self::CARD)->by($actor)->withProperties(['amount' => '12.00', 'card' => '4242'])->record();
    }

    /**
     * The owner every privacy operation names, unless a test gives another: an
     * id no hex, base64url or UUID holds by chance, so a record can be searched
     * for it.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(): Reference
    {
        return Reference::of(self::OWNER_TYPE, self::OWNER_ID);
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
