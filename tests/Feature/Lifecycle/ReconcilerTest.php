<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalPruneLedger;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecorder;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecordFailedException;
use SineMacula\Laravel\AuditLog\Lifecycle\Pruner;
use SineMacula\Laravel\AuditLog\Lifecycle\Reconciler;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for recording again the lifecycle operations the journal holds
 * and no entry records.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Reconciler::class)]
final class ReconcilerTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail, SealsEntries;

    /** @var string When the reconciler runs, unless a test moves the clock. */
    private const string NOW = '2026-11-02 09:00:00.123456';

    /** @var string The hold the hold and release rows name. */
    private const string HOLD_ID = '01932b4e-d000-7000-8000-000000000001';

    /** @var string The prune run the run rows name. */
    private const string RUN_ID = '01932b4e-a000-7000-8000-000000000001';

    /** @var string The import batch the import rows name. */
    private const string BATCH_ID = '01932b4e-b000-7000-8000-000000000001';

    /** @var string The version of the policy a prune run ran under. */
    private const string POLICY_VERSION = 'config:0123456789abcdef';

    /** @var ?\Tests\Fixtures\Privacy\RecordingExceptionHandler What each failure to record is reported to. */
    private ?RecordingExceptionHandler $reporter = null;

    /**
     * Freeze the clock, and report to a recording handler.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $this->reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $this->reporter);
    }

    /**
     * Put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Rows of `[journal, code, properties, actor, outcome and reason]` of
     * unrecorded operations.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(self): array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: array<string, array<string, int>|int|string|null>, 2: ?array{0: string, 1: string}, 3: array{0: string, 1: ?string}}}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideOperations(): iterable
    {
        yield from [
            'a prune run' => [static fn (self $test): array => $test->journalPruneRun()],
            'a hold'      => [static fn (self $test): array => $test->journalHeld()],
            'a release'   => [static fn (self $test): array => $test->journalReleased()],
            'an import'   => [static fn (self $test): array => $test->journalImport()],
        ];
    }

    /**
     * An unrecorded operation is recorded again with exactly the properties its
     * journal rows give.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(self): array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: array<string, array<string, int>|int|string|null>, 2: ?array{0: string, 1: string}, 3: array{0: string, 1: ?string}}  $journal
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[DataProvider('provideOperations')]
    public function testAMissingRecordIsRecordedAgain(\Closure $journal): void
    {
        [$activity, $properties, $actor, $outcome] = $journal($this);

        $result = $this->reconciler()->reconcile();

        self::assertSame(['examined' => 1, 'recorded' => 1, 'already_recorded' => 0, 'unverifiable' => 0, 'unfinished' => 0, 'failed' => 0], $result->toArray());

        $records = $this->readRecords($activity->value);

        self::assertCount(1, $records);
        self::assertCount(1, $this->readRecords());
        self::assertSameProperties($properties, self::propertiesOf($records[0]));
        self::assertSame($actor ?? [null, null], [$records[0]['actor_type'], $records[0]['actor_id']]);
        self::assertSame([null, null], [$records[0]['tenant_type'], $records[0]['tenant_id']]);
        self::assertSame($outcome, [$records[0]['outcome'], $records[0]['reason']]);
        self::assertSame([], $this->reporter?->reports());
    }

    /**
     * An operation already recorded under its own code is skipped.
     *
     * @return void
     */
    public function testAnOperationRecordedAlreadyIsSkipped(): void
    {
        $hold = $this->holdRow();

        $this->record(PackageActivity::RELEASED, ['operation_id' => $hold->operationId, 'hold_id' => self::HOLD_ID, 'authority_reason' => 'case.review', 'outcome' => 'success']);

        self::assertSame(1, $this->reconciler()->reconcile()->recorded);

        $release = $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD_ID], self::HOLD_ID);

        $this->record(PackageActivity::RELEASED, [
            'operation_id'     => $release->operationId,
            'hold_id'          => self::HOLD_ID,
            'authority_reason' => 'case.review',
            'outcome'          => 'success',
        ]);

        $entries = count($this->readRecords());
        $result  = $this->reconciler()->reconcile();

        self::assertSame(['examined' => 2, 'recorded' => 0, 'already_recorded' => 2, 'unverifiable' => 0, 'unfinished' => 0, 'failed' => 0], $result->toArray());
        self::assertCount($entries, $this->readRecords());
    }

    /**
     * A second run records nothing.
     *
     * @return void
     */
    public function testASecondRunRecordsNothing(): void
    {
        $this->journalPruneRun();
        $this->journalHeld();
        $this->journalReleased();
        $this->journalImport();

        $first  = $this->reconciler()->reconcile();
        $second = $this->reconciler()->reconcile();

        self::assertSame([4, 4, 0], [$first->examined, $first->recorded, $first->alreadyRecorded]);
        self::assertSame([4, 0, 4], [$second->examined, $second->recorded, $second->alreadyRecorded]);
        self::assertCount(4, $this->readRecords());
    }

    /**
     * Only operations within the days looked back are reconciled.
     *
     * @return void
     */
    public function testOnlyTheWindowIsReconciled(): void
    {
        CarbonImmutable::setTestNow(new CarbonImmutable('2026-10-20 09:00:00', 'UTC'));

        $this->holdRow();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $this->releaseRow();

        self::assertSame([1, 1], [$this->reconciler()->reconcile()->examined, count($this->readRecords())]);
        self::assertSame(PackageActivity::RELEASED->value, $this->readRecords()[0]['event']);

        $result = $this->reconciler()->reconcile(14);

        self::assertSame([2, 1, 1], [$result->examined, $result->recorded, $result->alreadyRecorded]);
        self::assertCount(1, $this->readRecords(PackageActivity::HELD->value));
    }

    /**
     * The window starts exactly the days given before the clock.
     *
     * @return void
     */
    public function testTheWindowStartsExactlyTheDaysGivenBack(): void
    {
        CarbonImmutable::setTestNow(new CarbonImmutable('2026-10-26 09:00:00.123455', 'UTC'));

        $this->journalRow(JournalKind::RELEASE, ['hold_id' => '01932b4e-d000-7000-8000-000000000009'], '01932b4e-d000-7000-8000-000000000009');

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-10-26 09:00:00.123456', 'UTC'));

        $this->releaseRow();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        self::assertSame(1, $this->reconciler()->reconcile()->examined);
        self::assertSame(self::HOLD_ID, self::propertiesOf($this->readRecords()[0])['hold_id']);
    }

    /**
     * Rows of `[the days looked back]`: none, and more than ten years.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideRefusedWindows(): iterable
    {
        yield from [
            'no day'            => [0],
            'a negative number' => [-7],
            'over ten years'    => [3651],
        ];
    }

    /**
     * A window outside 1 to 3650 days is refused before anything is read.
     *
     * @param  int  $days
     * @return void
     */
    #[DataProvider('provideRefusedWindows')]
    public function testAWindowOutsideItsRangeIsRefused(int $days): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A reconciliation looks back from 1 to 3650 days.');

        $this->reconciler()->reconcile($days);
    }

    /**
     * A window of one day and one of ten years are accepted.
     *
     * @return void
     */
    public function testTheWindowsBoundsAreAccepted(): void
    {
        $this->holdRow();

        self::assertSame(1, $this->reconciler()->reconcile(1)->recorded);
        self::assertSame(1, $this->reconciler()->reconcile(Reconciler::MAX_SINCE_DAYS)->alreadyRecorded);
    }

    /**
     * Rows of `[what is done to the hold's stored row]`.
     *
     * @return iterable<string, array{0: array<string, string>}>
     */
    public static function provideTamperedRows(): iterable
    {
        yield from [
            'an edited reason'  => [['reason' => 'case.closed']],
            'an edited payload' => [['payload' => '{"basis":"other","hold_id":"' . self::HOLD_ID . '","review_by":null,"scope":{}}']],
            'a key not held'    => [['key_id' => 'removed']],
            'a malformed HMAC'  => [['hmac' => 'not-an-hmac']],
        ];
    }

    /**
     * A row that does not verify is counted unverifiable and never recorded.
     *
     * @param  array<string, string>  $columns
     * @return void
     */
    #[DataProvider('provideTamperedRows')]
    public function testAnUnverifiableRowIsNeverRecorded(array $columns): void
    {
        $this->holdRow();
        $this->tamperJournal(1, $columns);

        $result = $this->reconciler()->reconcile();

        self::assertSame(['examined' => 1, 'recorded' => 0, 'already_recorded' => 0, 'unverifiable' => 1, 'unfinished' => 0, 'failed' => 0], $result->toArray());
        self::assertSame([], $this->readRecords());
        self::assertFalse($result->isComplete());
    }

    /**
     * Rows of `[the payload of a hold row signed as it is]`: verified, and yet
     * not a hold.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideMalformedHolds(): iterable
    {
        yield from [
            'another hold id'   => [['hold_id' => '01932b4e-d000-7000-8000-0000000000ff', 'scope' => HoldScope::all()->toArray(), 'basis' => 'legal_claim', 'review_by' => null]],
            'no scope'          => [['hold_id' => self::HOLD_ID, 'basis' => 'legal_claim', 'review_by' => null]],
            'a malformed scope' => [['hold_id' => self::HOLD_ID, 'scope' => ['v' => 2], 'basis' => 'legal_claim', 'review_by' => null]],
            'an unknown basis'  => [['hold_id' => self::HOLD_ID, 'scope' => HoldScope::all()->toArray(), 'basis' => 'whim', 'review_by' => null]],
            'a numeric review'  => [['hold_id' => self::HOLD_ID, 'scope' => HoldScope::all()->toArray(), 'basis' => 'legal_claim', 'review_by' => 7]],
        ];
    }

    /**
     * A verified hold row whose payload is not a hold is counted unverifiable.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $payload
     * @return void
     */
    #[DataProvider('provideMalformedHolds')]
    public function testAHoldRowThatDescribesNoHoldIsNeverRecorded(array $payload): void
    {
        $this->journalRow(JournalKind::HOLD, $payload, self::HOLD_ID);

        self::assertSame(1, $this->reconciler()->reconcile()->unverifiable);
        self::assertSame([], $this->readRecords());
    }

    /**
     * The record names the operation by its journal row's id, by the row's
     * operator.
     *
     * @return void
     */
    public function testTheRecordCarriesTheOperationId(): void
    {
        $hold = $this->journalRow(JournalKind::HOLD, $this->holdPayload(), self::HOLD_ID, authority: ['operator', 'ops-1'], reason: 'legal.notice');

        $this->reconciler()->reconcile();

        $record = $this->readRecords(PackageActivity::HELD->value)[0];

        self::assertSame($hold->operationId, self::propertiesOf($record)[LifecycleEvidence::OPERATION_KEY]);
        self::assertSame('legal.notice', self::propertiesOf($record)['authority_reason']);
        self::assertSame(['operator', 'ops-1'], [$record['actor_type'], $record['actor_id']]);
    }

    /**
     * Entries are read by event and time and decoded in PHP, with no JSON path
     * query.
     *
     * @return void
     */
    public function testNoJsonPathQueryIsIssued(): void
    {
        $this->journalPruneRun();
        $this->journalHeld();
        $this->journalReleased();
        $this->journalImport();
        $this->reconciler()->reconcile();

        $this->captureQueries();

        self::assertSame(4, $this->reconciler()->reconcile()->alreadyRecorded);

        $statements = array_map(static fn (QueryExecuted $query): string => $query->sql, $this->capturedQueries());

        self::assertNotSame([], $statements);

        foreach ($statements as $statement) {
            self::assertDoesNotMatchRegularExpression('/->|#>|json_|jsonb|::json/i', $statement, $statement);
        }

        $entryReads = array_filter($statements, static fn (string $statement): bool => preg_match('/from ["`]?audit_log_entries["`]? where ["`]?event["`]? in/i', $statement) > 0);

        self::assertCount(1, $entryReads);
    }

    /**
     * An unfinished prune run is counted apart.
     *
     * @return void
     */
    public function testAnUnfinishedPruneRunIsCountedApart(): void
    {
        $this->journalRow(JournalKind::PRUNE_RUN, self::runStart(self::RUN_ID));

        $result = $this->reconciler()->reconcile();

        self::assertSame(['examined' => 1, 'recorded' => 0, 'already_recorded' => 0, 'unverifiable' => 0, 'unfinished' => 1, 'failed' => 0], $result->toArray());
        self::assertSame([], $this->readRecords());
        self::assertTrue($result->isComplete());
    }

    /**
     * Rows of `[start kind, start payload, finish kind, finish payload]`, each
     * started early.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind, 1: array<string, bool|int|string|null>, 2: \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind, 3: array<string, array<string, int>|int|string|null>, 4: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideEarlyStarts(): iterable
    {
        yield from [
            'a prune run' => [JournalKind::PRUNE_RUN, self::runStart(self::RUN_ID), JournalKind::PRUNE_RUN, self::runFinish(self::RUN_ID, 'partial'), PackageActivity::PRUNED],
            'an import'   => [JournalKind::IMPORT_STARTED, self::importStart(null), JournalKind::IMPORT_FINISHED, self::importFinish('complete'), PackageActivity::IMPORTED],
        ];
    }

    /**
     * An operation started before the window is recorded from its start behind
     * it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $startKind
     * @param  array<string, bool|int|string|null>  $start
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $finishKind
     * @param  array<string, array<string, int>|int|string|null>  $finish
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @return void
     */
    #[DataProvider('provideEarlyStarts')]
    public function testAStartBeforeTheWindowIsFound(JournalKind $startKind, array $start, JournalKind $finishKind, array $finish, PackageActivity $activity): void
    {
        CarbonImmutable::setTestNow(new CarbonImmutable('2026-10-01 09:00:00', 'UTC'));

        $this->journalRow($startKind, $start);

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-10-20 09:00:00', 'UTC'));

        $this->journalRow(JournalKind::PRUNE_RUN, self::runFinish('01932b4e-a000-7000-8000-000000000009', 'complete'));
        $this->journalRow(JournalKind::IMPORT_STARTED, [...self::importStart(null), 'batch_id' => '01932b4e-b000-7000-8000-000000000009']);

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $this->journalRow($finishKind, $finish, authority: $finishKind->carriesAuthority() ? self::JOURNAL_AUTHORITY : null);

        $result = $this->reconciler()->reconcile();

        self::assertSame([1, 1, 0], [$result->examined, $result->recorded, $result->unverifiable]);
        self::assertCount(1, $this->readRecords($activity->value));
    }

    /**
     * A finish without a verified start is counted unverifiable and never
     * recorded.
     *
     * @return void
     */
    public function testAFinishWithoutAVerifiedStartIsNeverRecorded(): void
    {
        $this->journalRow(JournalKind::PRUNE_RUN, self::runFinish(self::RUN_ID, 'complete'));

        self::assertSame(1, $this->reconciler()->reconcile()->unverifiable);

        $this->journalRow(JournalKind::IMPORT_STARTED, self::importStart(null), authority: self::JOURNAL_AUTHORITY);
        $this->journalRow(JournalKind::IMPORT_FINISHED, self::importFinish('complete'), authority: self::JOURNAL_AUTHORITY);
        $this->tamperJournal(2, ['reason' => 'case.closed']);

        $result = $this->reconciler()->reconcile();

        self::assertSame(['examined' => 3, 'recorded' => 0, 'already_recorded' => 0, 'unverifiable' => 3, 'unfinished' => 0, 'failed' => 0], $result->toArray());
        self::assertSame([], $this->readRecords());
    }

    /**
     * Rows of `[the finish's status, its failure, the record's outcome and
     * reason]`.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: array{0: string, 1: ?string}}>
     */
    public static function providePruneOutcomes(): iterable
    {
        yield from [
            'complete'                   => ['complete', null, ['success', null]],
            'partial'                    => ['partial', null, ['success', null]],
            'failed with its reason'     => ['failed', 'journal_broken', ['failure', 'journal_broken']],
            'failed with no reason kept' => ['failed', null, ['failure', null]],
            'failed with no such reason' => ['failed', 'whim', ['failure', null]],
        ];
    }

    /**
     * A prune run's status decides its record's outcome and reason.
     *
     * @param  string  $status
     * @param  ?string  $failure
     * @param  array{0: string, 1: ?string}  $outcome
     * @return void
     */
    #[DataProvider('providePruneOutcomes')]
    public function testAPruneRunIsRecordedWithItsOutcome(string $status, ?string $failure, array $outcome): void
    {
        $this->journalRow(JournalKind::PRUNE_RUN, self::runStart(self::RUN_ID));
        $this->journalRow(JournalKind::PRUNE_RUN, [...self::runFinish(self::RUN_ID, $status), 'failure' => $failure]);

        $this->reconciler()->reconcile();

        $record = $this->readRecords(PackageActivity::PRUNED->value)[0];

        self::assertSame($outcome, [$record['outcome'], $record['reason']]);
        self::assertSame($status, self::propertiesOf($record)['status']);
        self::assertSame($outcome[0], self::propertiesOf($record)['outcome']);
    }

    /**
     * A failed prune run is recorded with its reason and tenants, as its own
     * record would have been.
     *
     * @return void
     */
    public function testAFailedPruneRunIsRecordedWithItsReasonAndTenants(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.after_days', 30);
        app()->bind(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
        app()->bind(PruneLedger::class, JournalPruneLedger::class);

        foreach (['2026-10-01 12:00:00', '2026-10-01 14:00:00'] as $index => $at) {
            $this->storeEntryAt($at);
            $this->sealAt(sprintf('2026-10-01 1%d:30:00', 2 + (2 * $index)));
            $this->sealAll();
        }

        $inserts = 0;

        DB::listen(static function (QueryExecuted $query) use (&$inserts): void {
            $isPruneRow = str_starts_with($query->sql, 'insert')
                && str_contains($query->sql, LifecycleTables::journalTable())
                && in_array(JournalKind::PRUNE->value, $query->bindings, true);

            if ($isPruneRow && ++$inserts === 2) {
                throw new \RuntimeException('The disk is full.');
            }
        });

        $result = app(Pruner::class)->run();

        self::assertSame(['prune_failed', 1, 1], [$result->failure, $result->deleted, $result->tenantsAffected]);

        $this->reconciler()->reconcile();

        $record = $this->readRecords(PackageActivity::PRUNED->value)[0];

        self::assertSame(['failure', 'prune_failed'], [$record['outcome'], $record['reason']]);
        self::assertSameProperties([
            'operation_id'     => $result->operationId,
            'status'           => 'failed',
            'policy_version'   => $result->policyVersion,
            'deleted'          => 1,
            'seals'            => 1,
            'held'             => 0,
            'pending_delivery' => 0,
            'skipped_seals'    => 0,
            'categories'       => $result->categories,
            'tenants_affected' => 1,
            'outcome'          => 'failure',
        ], self::propertiesOf($record));
    }

    /**
     * In outbox mode a second run before the drain finds the first run's record
     * in the outbox.
     *
     * @return void
     */
    public function testASecondRunBeforeTheOutboxDrainsRecordsNothing(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', 'outbox');

        $row = $this->holdRow();

        $first  = $this->reconciler()->reconcile();
        $second = $this->reconciler()->reconcile();

        self::assertSame([1, 0], [$first->recorded, $first->alreadyRecorded]);
        self::assertSame([0, 1], [$second->recorded, $second->alreadyRecorded]);
        self::assertSame(1, DB::connection(StorageConnection::name())->table(DeliveryTables::outboxTable())->count());
        $queued = DB::connection(StorageConnection::name())->table(DeliveryTables::outboxTable())->value('id');

        self::assertSame(LifecycleRecorder::recordIdOf(PackageActivity::HELD, $row->operationId), $queued);
        self::assertSame([], $this->readRecords());
    }

    /**
     * In sync mode the outbox is never read.
     *
     * @return void
     */
    public function testInSyncModeTheOutboxIsNeverRead(): void
    {
        $this->holdRow();

        $read = [];

        DB::listen(static function (QueryExecuted $query) use (&$read): void {
            if (!str_contains($query->sql, DeliveryTables::outboxTable())) {
                return;
            }

            $read[] = $query->sql;
        });

        $first  = $this->reconciler()->reconcile();
        $second = $this->reconciler()->reconcile();

        self::assertSame([1, 0], [$first->recorded, $first->alreadyRecorded]);
        self::assertSame([0, 1], [$second->recorded, $second->alreadyRecorded]);
        self::assertSame([], $read);
    }

    /**
     * A concurrent run never writes the record twice.
     *
     * @return void
     */
    public function testAConcurrentRunNeverWritesTheRecordTwice(): void
    {
        $row     = $this->holdRow();
        $written = false;

        DB::connection(StorageConnection::name())->beforeExecuting(function (string $sql) use (&$written): void {
            if ($written || !str_starts_with(strtolower($sql), 'insert') || !str_contains($sql, EntrySettings::table())) {
                return;
            }

            $written = true;

            $this->reconciler()->reconcile();
        });

        $result = $this->reconciler()->reconcile();

        self::assertTrue($written);
        self::assertSame(1, $result->recorded + $result->failed);
        self::assertCount(1, $this->readRecords(PackageActivity::HELD->value));
        self::assertSame(LifecycleRecorder::recordIdOf(PackageActivity::HELD, $row->operationId), $this->readRecords(PackageActivity::HELD->value)[0]['id']);
    }

    /**
     * The derived record id is a stable lower-case UUID v8 per code and
     * operation.
     *
     * @return void
     */
    public function testTheDerivedRecordIdIsStable(): void
    {
        $id = LifecycleRecorder::recordIdOf(PackageActivity::HELD, self::RUN_ID);

        self::assertMatchesRegularExpression('/\A[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/', $id);
        self::assertSame($id, LifecycleRecorder::recordIdOf(PackageActivity::HELD, self::RUN_ID));
        self::assertNotSame($id, LifecycleRecorder::recordIdOf(PackageActivity::RELEASED, self::RUN_ID));
        self::assertNotSame($id, LifecycleRecorder::recordIdOf(PackageActivity::HELD, self::BATCH_ID));
    }

    /**
     * Rows of `[the finish's status, the record's outcome and reason]`.
     *
     * @return iterable<string, array{0: string, 1: array{0: string, 1: ?string}}>
     */
    public static function provideImportOutcomes(): iterable
    {
        yield from [
            'complete'    => ['complete', ['success', null]],
            'partial'     => ['partial', ['success', null]],
            'failed'      => ['failed', ['failure', 'import_failed']],
            'interrupted' => ['interrupted', ['failure', 'interrupted']],
        ];
    }

    /**
     * An import's status decides whether it is recorded a success, failure or
     * interrupted.
     *
     * @param  string  $status
     * @param  array{0: string, 1: ?string}  $outcome
     * @return void
     */
    #[DataProvider('provideImportOutcomes')]
    public function testAnImportIsRecordedWithItsOutcome(string $status, array $outcome): void
    {
        $this->journalRow(JournalKind::IMPORT_STARTED, self::importStart(null), authority: self::JOURNAL_AUTHORITY);
        $this->journalRow(JournalKind::IMPORT_FINISHED, self::importFinish($status), authority: self::JOURNAL_AUTHORITY);

        $this->reconciler()->reconcile();

        $record = $this->readRecords(PackageActivity::IMPORTED->value)[0];

        self::assertSame($outcome, [$record['outcome'], $record['reason']]);
        self::assertSame($status, self::propertiesOf($record)['status']);
    }

    /**
     * Rows of `[the kind, the payload]`: finish rows of an unknown status.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind, 1: array<string, array<string, int>|int|string|null>}>
     */
    public static function provideUnknownStatuses(): iterable
    {
        yield from [
            'a prune run' => [JournalKind::PRUNE_RUN, self::runFinish(self::RUN_ID, 'running')],
            'an import'   => [JournalKind::IMPORT_FINISHED, self::importFinish('running')],
        ];
    }

    /**
     * A finish of an unknown status is never recorded.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  array<string, array<string, int>|int|string|null>  $payload
     * @return void
     */
    #[DataProvider('provideUnknownStatuses')]
    public function testAFinishOfAnUnknownStatusIsNeverRecorded(JournalKind $kind, array $payload): void
    {
        $this->journalRow(JournalKind::PRUNE_RUN, self::runStart(self::RUN_ID));
        $this->journalRow(JournalKind::IMPORT_STARTED, self::importStart(null), authority: self::JOURNAL_AUTHORITY);
        $this->journalRow($kind, $payload, authority: $kind->carriesAuthority() ? self::JOURNAL_AUTHORITY : null);

        $result = $this->reconciler()->reconcile();

        self::assertSame(1, $result->unverifiable);
        self::assertSame([], $this->readRecords());
    }

    /**
     * A held import records both its import and its hold, each once.
     *
     * @return void
     */
    public function testAHeldImportRecordsBothCodes(): void
    {
        $this->journalRow(JournalKind::IMPORT_STARTED, self::importStart(self::HOLD_ID), authority: self::JOURNAL_AUTHORITY);
        $this->journalRow(JournalKind::HOLD, [...$this->holdPayload(), 'scope' => HoldScope::all()->importBatch(self::BATCH_ID)->toArray()], self::HOLD_ID);
        $this->journalRow(JournalKind::IMPORT_FINISHED, self::importFinish('complete'), authority: self::JOURNAL_AUTHORITY);

        $result = $this->reconciler()->reconcile();

        self::assertSame([2, 2], [$result->examined, $result->recorded]);
        self::assertSame(self::HOLD_ID, self::propertiesOf($this->readRecords(PackageActivity::IMPORTED->value)[0])['hold_id']);
        self::assertSame(HoldScope::all()->importBatch(self::BATCH_ID)->digest(), self::propertiesOf($this->readRecords(PackageActivity::HELD->value)[0])['scope_digest']);
    }

    /**
     * A record that cannot be written is counted failed and tried again next
     * run.
     *
     * @return void
     */
    public function testARecordThatCannotBeWrittenIsCountedFailed(): void
    {
        $this->holdRow();

        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['basis']);

        $result = $this->reconciler()->reconcile();
        $again  = $this->reconciler()->reconcile();

        self::assertSame(['examined' => 1, 'recorded' => 0, 'already_recorded' => 0, 'unverifiable' => 0, 'unfinished' => 0, 'failed' => 1], $result->toArray());
        self::assertSame(1, $again->failed);
        self::assertSame([], $this->readRecords());
        self::assertInstanceOf(LifecycleRecordFailedException::class, ($this->reporter?->reports() ?? [])[0] ?? null);
    }

    /**
     * Journal rows and entries beyond a page are each read.
     *
     * @return void
     */
    public function testMoreThanAPageOfRowsIsRead(): void
    {
        foreach (range(1, 501) as $number) {
            $holdId = sprintf('01932b4e-d000-7000-8000-%012d', $number);

            $this->journalRow(JournalKind::RELEASE, ['hold_id' => $holdId], $holdId);
        }

        $first  = $this->reconciler()->reconcile();
        $second = $this->reconciler()->reconcile();

        self::assertSame([501, 501], [$first->examined, $first->recorded]);
        self::assertSame([501, 0, 501], [$second->examined, $second->recorded, $second->alreadyRecorded]);
        self::assertCount(501, $this->readRecords(PackageActivity::RELEASED->value));
    }

    /**
     * An erasure missing its record is recorded from its journal row.
     *
     * @return void
     */
    public function testAnErasureMissingItsRecordIsRecorded(): void
    {
        $owner = Reference::of('App\Models\User', '42');

        $this->makeSubjectKey($owner, null, 'billing');

        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['entries_affected']);

        $result = app(AuditLifecycle::class)->erase($owner, self::authority());

        app(ConfigRepository::class)->set('audit-log.redaction.keys', []);

        self::assertFalse($result->recorded);
        $tally = $this->reconciler()->reconcile()->toArray();

        self::assertSame(['examined' => 1, 'recorded' => 1, 'already_recorded' => 0, 'unverifiable' => 0, 'unfinished' => 0, 'failed' => 0], $tally);

        $records = $this->readRecords(PackageActivity::SUBJECT_ERASED->value);

        [$fingerprintKey, $fingerprint] = app(OwnerFingerprint::class)->of($owner);

        self::assertCount(1, $records);
        self::assertSame(['success', null, 'App\Models\User', '7'], [$records[0]['outcome'], $records[0]['reason'], $records[0]['actor_type'], $records[0]['actor_id']]);
        self::assertSameProperties([
            'operation_id'      => $result->operationId,
            'erasure_id'        => $result->erasureId,
            'owner_fingerprint' => $fingerprint,
            'fingerprint_key'   => $fingerprintKey,
            'status'            => 'complete',
            'keys_destroyed'    => 1,
            'keys_kept'         => 0,
            'entries_affected'  => 0,
            'blocked'           => [],
            'pending_accepted'  => false,
            'authority_reason'  => 'case.review',
            'outcome'           => 'success',
        ], self::propertiesOf($records[0]));
        self::assertSame(0, $this->reconciler()->reconcile()->recorded);
    }

    /**
     * A partial erasure is recorded `partial` with its kept keys and reasons.
     *
     * @return void
     */
    public function testAPartialErasureIsRecordedWithItsBlocks(): void
    {
        $owner = Reference::of('App\Models\User', '42');

        [$kept]  = $this->makeSubjectKey($owner, null, 'billing');
        [$other] = $this->makeSubjectKey($owner, null, 'support');

        $this->eraseByHand($owner, [$kept->id => ['unverified', 'held:' . self::HOLD_ID], $other->id => ['unverified']], true);

        self::assertSame(1, $this->reconciler()->reconcile()->recorded);

        $properties = self::propertiesOf($this->readRecords(PackageActivity::SUBJECT_ERASED->value)[0]);

        self::assertSame(['partial', 0, 2], [$properties['status'], $properties['keys_destroyed'], $properties['keys_kept']]);
        self::assertSameProperties(['held:' . self::HOLD_ID => 1, 'unverified' => 1], $properties['blocked']);
    }

    /**
     * Rewraps and reinstatements missing their records are recorded.
     *
     * @return void
     */
    public function testRewrapsAndReinstatementsAreReconciled(): void
    {
        $owner     = Reference::of('App\Models\User', '42');
        $lifecycle = app(AuditLifecycle::class);

        $this->makeSubjectKey($owner, null, 'billing');
        $lifecycle->erase($owner, self::authority());

        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['generation_floor', 'keys_rotated']);

        $reinstated = $lifecycle->reinstate($owner, self::authority());

        $this->makeSubjectKey(Reference::of('App\Models\User', '43'), null, 'billing');

        $rewrapped = $lifecycle->rewrap(self::authority(), true);

        app(ConfigRepository::class)->set('audit-log.redaction.keys', []);

        self::assertSame([false, false], [$reinstated->recorded, $rewrapped->recorded]);
        $tally = $this->reconciler()->reconcile()->toArray();

        self::assertSame(['examined' => 3, 'recorded' => 2, 'already_recorded' => 1, 'unverifiable' => 0, 'unfinished' => 0, 'failed' => 0], $tally);

        $reinstatement = self::propertiesOf($this->readRecords(PackageActivity::KEYS_REINSTATED->value)[0]);
        $rewrap        = self::propertiesOf($this->readRecords(PackageActivity::KEYS_REWRAPPED->value)[0]);

        self::assertSame(
            [$reinstated->operationId, $reinstated->reinstatementId, 1],
            [$reinstatement['operation_id'], $reinstatement['reinstatement_id'], $reinstatement['generation_floor']],
        );
        self::assertSameProperties([
            'operation_id'     => $rewrapped->operationId,
            'status'           => 'complete',
            'keys_rewrapped'   => 0,
            'keys_rotated'     => 1,
            'keys_skipped'     => 0,
            'wrap_key_id'      => $this->keyWrapper()->currentKeyId(),
            'batches'          => 1,
            'authority_reason' => 'case.review',
            'outcome'          => 'success',
        ], $rewrap);
    }

    /**
     * A privacy row that describes no operation is counted unverifiable.
     *
     * @return void
     */
    public function testAPrivacyRowThatDescribesNoOperationIsNeverRecorded(): void
    {
        $this->journalRow(JournalKind::ERASURE, ['owner_fingerprint' => 'f']);
        $this->journalRow(JournalKind::REINSTATE, ['owner_fingerprint' => 'f', 'fingerprint_key' => 'k']);
        $this->journalRow(JournalKind::REWRAP, ['run_id' => 'another run', 'keys' => [], 'skipped' => []]);

        $result = $this->reconciler()->reconcile();

        self::assertSame([0, 3], [$result->recorded, $result->unverifiable]);
        self::assertSame([], $this->readRecords());
    }

    /**
     * The authority every operation is asked for on, the journal's own
     * operator.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of(...self::JOURNAL_AUTHORITY), 'case.review');
    }

    /**
     * The reconciler resolved from the container.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Reconciler
     */
    private function reconciler(): Reconciler
    {
        return app(Reconciler::class);
    }

    /**
     * Record the activity with the properties given, as the operation's own
     * record would be.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @param  array<string, int|string|null>  $properties
     * @return void
     */
    private function record(PackageActivity $activity, array $properties): void
    {
        self::assertTrue(app(LifecycleRecorder::class)->record($activity, Reference::of(...self::JOURNAL_AUTHORITY), new LifecycleEvidence($properties), Outcome::SUCCESS));
    }

    /**
     * Journal a hold of everything, and return its row.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private function holdRow(): JournalRow
    {
        return $this->journalRow(JournalKind::HOLD, $this->holdPayload(), self::HOLD_ID);
    }

    /**
     * Journal the release of the hold, and return its row.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private function releaseRow(): JournalRow
    {
        return $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD_ID], self::HOLD_ID);
    }

    /**
     * The payload of a hold of everything on a legal claim, with no review
     * date.
     *
     * @return array<string, array<string, bool|int|list<array{0: string, 1: string}>|list<string>|string|null>|string|null>
     */
    private function holdPayload(): array
    {
        return ['hold_id' => self::HOLD_ID, 'scope' => HoldScope::all()->toArray(), 'basis' => 'legal_claim', 'review_by' => null];
    }

    /**
     * Journal a complete prune run and return what it is recorded as.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: array<string, array<string, int>|int|string|null>, 2: ?array{0: string, 1: string}, 3: array{0: string, 1: ?string}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function journalPruneRun(): array
    {
        $this->journalRow(JournalKind::PRUNE_RUN, self::runStart(self::RUN_ID));
        $this->journalRow(JournalKind::PRUNE_RUN, self::runFinish(self::RUN_ID, 'complete'));

        return [PackageActivity::PRUNED, [
            'operation_id'     => self::RUN_ID,
            'status'           => 'complete',
            'policy_version'   => self::POLICY_VERSION,
            'deleted'          => 5,
            'seals'            => 2,
            'held'             => 1,
            'pending_delivery' => 0,
            'skipped_seals'    => 0,
            'categories'       => ['audit' => 1, 'security' => 4],
            'tenants_affected' => 3,
            'outcome'          => 'success',
        ], null, ['success', null]];
    }

    /**
     * Journal a hold of everything, and give what it is recorded as.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: array<string, array<string, int>|int|string|null>, 2: ?array{0: string, 1: string}, 3: array{0: string, 1: ?string}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function journalHeld(): array
    {
        $row = $this->journalRow(JournalKind::HOLD, [...$this->holdPayload(), 'review_by' => '2027-05-01T00:00:00.000000Z'], self::HOLD_ID);

        return [PackageActivity::HELD, [
            'operation_id'     => $row->operationId,
            'hold_id'          => self::HOLD_ID,
            'basis'            => 'legal_claim',
            'scope_digest'     => HoldScope::all()->digest(),
            'review_by'        => '2027-05-01T00:00:00.000000Z',
            'authority_reason' => self::JOURNAL_REASON,
            'outcome'          => 'success',
        ], self::JOURNAL_AUTHORITY, ['success', null]];
    }

    /**
     * Journal the release of a hold, and give what it is recorded as.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: array<string, array<string, int>|int|string|null>, 2: ?array{0: string, 1: string}, 3: array{0: string, 1: ?string}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function journalReleased(): array
    {
        $row = $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD_ID], self::HOLD_ID, reason: 'case.closed');

        return [PackageActivity::RELEASED, [
            'operation_id'     => $row->operationId,
            'hold_id'          => self::HOLD_ID,
            'authority_reason' => 'case.closed',
            'outcome'          => 'success',
        ], self::JOURNAL_AUTHORITY, ['success', null]];
    }

    /**
     * Journal a partial import and return what it is recorded as.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: array<string, array<string, int>|int|string|null>, 2: ?array{0: string, 1: string}, 3: array{0: string, 1: ?string}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function journalImport(): array
    {
        $this->journalRow(JournalKind::IMPORT_STARTED, self::importStart(null), authority: self::JOURNAL_AUTHORITY);

        $finish = $this->journalRow(JournalKind::IMPORT_FINISHED, self::importFinish('partial'), authority: ['operator', 'ops-2'], reason: 'import.close');

        return [PackageActivity::IMPORTED, [
            'operation_id'     => $finish->operationId,
            'batch_id'         => self::BATCH_ID,
            'source_id'        => 'legacy',
            'format'           => 'audit-log-import/v1',
            'status'           => 'partial',
            'lines_read'       => 4,
            'imported'         => 2,
            'duplicates'       => 1,
            'conflicts'        => 0,
            'rejected'         => 1,
            'hold_id'          => null,
            'authority_reason' => 'import.close',
            'outcome'          => 'success',
        ], ['operator', 'ops-2'], ['success', null]];
    }

    /**
     * The payload of a prune run's start row.
     *
     * @param  string  $runId
     * @return array<string, int|string|null>
     */
    private static function runStart(string $runId): array
    {
        return [
            'run_id'            => $runId,
            'phase'             => 'start',
            'policy_version'    => self::POLICY_VERSION,
            'boundary_sequence' => 3,
            'cutoff_midnight'   => '2026-11-02T00:00:00.000000Z',
            'resume_from'       => 1,
        ];
    }

    /**
     * The payload of a prune run's finish row, of the status given.
     *
     * @param  string  $runId
     * @param  string  $status
     * @return array<string, array<string, int>|int|string|null>
     */
    private static function runFinish(string $runId, string $status): array
    {
        return [
            'run_id'            => $runId,
            'phase'             => 'finish',
            'status'            => $status,
            'failure'           => null,
            'deleted'           => 5,
            'seals'             => 2,
            'held'              => 1,
            'pending_delivery'  => 0,
            'skipped_seals'     => 0,
            'cursor'            => 3,
            'remaining'         => 0,
            'categories'        => ['audit' => 1, 'security' => 4],
            'tenants_affected'  => 3,
            'pairs'             => 2,
            'decisions_omitted' => 0,
            'decisions_digest'  => str_repeat('d', 64),
        ];
    }

    /**
     * The payload of an import's start row, holding the hold given or none.
     *
     * @param  ?string  $holdId
     * @return array<string, bool|int|string|null>
     */
    private static function importStart(?string $holdId): array
    {
        return [
            'batch_id'            => self::BATCH_ID,
            'source_id'           => 'legacy',
            'source_region'       => null,
            'format'              => 'audit-log-import/v1',
            'file_sha256'         => str_repeat('f', 64),
            'externally_verified' => false,
            'hold_id'             => $holdId,
        ];
    }

    /**
     * The payload of an import's finish row, of the status given.
     *
     * @param  string  $status
     * @return array<string, int|string>
     */
    private static function importFinish(string $status): array
    {
        return [
            'batch_id'    => self::BATCH_ID,
            'status'      => $status,
            'lines_read'  => 4,
            'imported'    => 2,
            'duplicates'  => 1,
            'conflicts'   => 0,
            'rejected'    => 1,
            'file_sha256' => str_repeat('f', 64),
        ];
    }
}
