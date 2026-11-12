<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Delivery\CaptureSignal;
use SineMacula\Laravel\AuditLog\Delivery\PackageWrite;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecorder;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecordFailedException;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Contributors\ActorFillingContributor;
use Tests\Fixtures\Contributors\TenantContributor;
use Tests\Fixtures\Contributors\TransactionOpeningContributor;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for the writer of the lifecycle's own records.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleRecorder::class)]
final class LifecycleRecorderTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore, InteractsWithOutbox, ReadsTheTrail;

    /** @var string The operation every record names. */
    private const string OPERATION_ID = '019a4b2e-7c10-7000-8000-00000000000a';

    /** @var string The hold the records of a hold and a release name. */
    private const string HOLD_ID = '019a4b2e-7c10-7000-8000-00000000000b';

    /** @var ?\Tests\Fixtures\Privacy\RecordingExceptionHandler What each failure is reported to. */
    private ?RecordingExceptionHandler $reporter = null;

    /**
     * Report to a recording handler, and capture every line logged.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->captureLogLines();

        $this->reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $this->reporter);
    }

    /**
     * Roll back any open transaction, and restore the entries table and the
     * outbox.
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

        $this->removeProbeTable();
        $this->removeMovedOutbox();

        parent::tearDown();
    }

    /**
     * The record goes through the package write, fail-closed and immediate.
     *
     * @return void
     */
    public function testItWritesThroughThePackageWriteFailClosedAndImmediate(): void
    {
        $delivery = $this->spyOnTheDelivery();

        self::assertTrue($this->recordsAHold());

        self::assertSame([[Timing::IMMEDIATE, null, true, false, true]], $delivery->delivered);
        self::assertCount(1, $this->readRecords(PackageActivity::HELD->value));
        self::assertSame([], $this->reporter?->reports());
    }

    /**
     * A failed write fails the attempt under the `report` failure mode as under
     * `throw`.
     *
     * @return void
     */
    public function testTheAttemptIsFailClosedWhateverTheFailureMode(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', 'report');

        $this->pointAtProbeTable();

        self::assertFalse($this->recordsAHold());

        $reports = $this->reporter?->reports() ?? [];

        self::assertCount(1, $reports);
        self::assertInstanceOf(LifecycleRecordFailedException::class, $reports[0]);
        self::assertSame(AuditWriteFailedException::class, $reports[0]->failure);
        self::assertCount(1, $this->spillLines());
        self::assertSame(0, $this->probeCount());
    }

    /**
     * The record is the operator's, in explicitly no tenant, whatever a
     * contributor names.
     *
     * @return void
     */
    public function testTheRecordIsTheAuthoritysWithNoTenant(): void
    {
        $this->contribute(ActorFillingContributor::class, TenantContributor::class);

        self::assertTrue($this->recordsARelease(Outcome::DENIED, 'unknown_hold'));

        $record = $this->readRecords()[0];

        self::assertSame(['operator', 'ops-1'], [$record['actor_type'], $record['actor_id']]);
        self::assertSame([null, null], [$record['tenant_type'], $record['tenant_id']]);
        self::assertSame(['denied', 'unknown_hold'], [$record['outcome'], $record['reason']]);
    }

    /**
     * A prune's record names explicitly no actor.
     *
     * @return void
     */
    public function testAPruneHasNoActor(): void
    {
        $this->contribute(ActorFillingContributor::class);

        self::assertTrue($this->recorder()->record(PackageActivity::PRUNED, null, self::evidenceOf(PackageActivity::PRUNED), Outcome::FAILURE, 'journal_broken'));

        $record = $this->readRecords()[0];

        self::assertSame([null, null], [$record['actor_type'], $record['actor_id']]);
        self::assertSame(['failure', 'journal_broken'], [$record['outcome'], $record['reason']]);
    }

    /**
     * The record keeps the evidence exactly, with no metadata.
     *
     * @return void
     */
    public function testTheEvidenceIsKeptExactly(): void
    {
        $evidence = self::evidenceOf(PackageActivity::IMPORTED);

        self::assertTrue($this->recorder()->record(PackageActivity::IMPORTED, self::operator(), $evidence, Outcome::SUCCESS));

        self::assertSameProperties($evidence->properties, self::propertiesOf($this->readRecords()[0]));
    }

    /**
     * Evidence a redaction key would drop refuses the record before anything is
     * written.
     *
     * @return void
     */
    public function testEvidenceTheRecordWouldNotKeepIsRefused(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['basis']);

        self::assertFalse($this->recordsAHold());

        $reports = $this->reporter?->reports() ?? [];

        self::assertSame(0, $this->entryCount());
        self::assertSame([], $this->spillLines());
        self::assertCount(1, $reports);
        self::assertInstanceOf(LifecycleRecordFailedException::class, $reports[0]);
        self::assertSame(\LogicException::class, $reports[0]->failure);
    }

    /**
     * A failed write is reported once as a payload-free failure and answered
     * `false`.
     *
     * @return void
     */
    public function testAFailedRecordIsReportedOnceAndReturnsFalse(): void
    {
        $this->pointAtProbeTable();

        self::assertFalse($this->recordsAHold());

        $reports = $this->reporter?->reports() ?? [];

        self::assertCount(1, $reports);
        self::assertSame(LifecycleRecordFailedException::of(self::OPERATION_ID, PackageActivity::HELD, AuditWriteFailedException::class)->getMessage(), $reports[0]->getMessage());
        self::assertNull($reports[0]->getPrevious());
        self::assertCount(1, $this->spillLines());
    }

    /**
     * A failure inside a running report is not reported again.
     *
     * @return void
     */
    public function testAFailureInsideARunningReportIsNotReportedAgain(): void
    {
        $this->pointAtProbeTable();

        $recorded = null;

        app(ReportLatch::class)->once(function () use (&$recorded): void {
            $recorded = $this->recordsAHold();
        });

        self::assertFalse($recorded);
        self::assertSame([], $this->reporter?->reports());
    }

    /**
     * A write never acknowledged is reported and answered `false`.
     *
     * @return void
     */
    public function testAWriteNeverAcknowledgedReturnsFalse(): void
    {
        app()->instance(RecordDelivery::class, new class {
            /**
             * Refuse nothing.
             *
             * @return void
             */
            public function check(): void {}

            /**
             * Deliver nothing, and acknowledge nothing.
             *
             * @return void
             */
            public function deliver(): void {}
        });

        self::assertFalse($this->recordsAHold());

        $reports = $this->reporter?->reports() ?? [];

        self::assertCount(1, $reports);
        self::assertSame(LifecycleRecordFailedException::unacknowledged(self::OPERATION_ID, PackageActivity::HELD)->getMessage(), $reports[0]->getMessage());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * Rows of `[delivery mode]`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideDeliveryModes(): iterable
    {
        yield from [
            'sync'   => ['sync'],
            'outbox' => ['outbox'],
        ];
    }

    /**
     * A transaction open on the acknowledging connection refuses the record
     * before it is written.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideDeliveryModes')]
    public function testAnOpenTransactionOnTheAcknowledgingConnectionRefusesTheRecord(string $mode): void
    {
        $connection = $this->acknowledgingConnectionIn($mode);

        DB::connection($connection)->beginTransaction();

        self::assertFalse($this->recordsAHold());

        DB::connection($connection)->rollBack();

        $reports = $this->reporter?->reports() ?? [];

        self::assertCount(1, $reports);
        self::assertSame(LifecycleRecordFailedException::inTransaction(self::OPERATION_ID, PackageActivity::HELD, $connection)->getMessage(), $reports[0]->getMessage());
        self::assertSame(0, $this->entryCount());
        self::assertSame(0, $this->outboxCount());
        self::assertSame([], $this->spillLines());
    }

    /**
     * A transaction on another connection does not refuse the record.
     *
     * @return void
     */
    public function testATransactionOnAnotherConnectionDoesNotRefuseTheRecord(): void
    {
        $this->acknowledgingConnectionIn('outbox');

        $this->storageConnection()->beginTransaction();

        self::assertTrue($this->recordsAHold());

        $this->storageConnection()->rollBack();

        self::assertSame(1, $this->outboxCount());
        self::assertSame([], $this->reporter?->reports());
    }

    /**
     * An acknowledgement inside a contributor's open transaction is never
     * accepted.
     *
     * @return void
     */
    public function testAnAcknowledgementInsideATransactionAContributorOpenedIsRefused(): void
    {
        $this->contribute(TransactionOpeningContributor::class);

        $connection = $this->storageConnection();

        self::assertFalse($this->recordsAHold());
        self::assertSame(1, $connection->transactionLevel());

        $reports = $this->reporter?->reports() ?? [];

        self::assertCount(1, $reports);
        self::assertSame(LifecycleRecordFailedException::inTransaction(self::OPERATION_ID, PackageActivity::HELD, self::CONNECTION)->getMessage(), $reports[0]->getMessage());

        $connection->rollBack();

        self::assertSame(0, $this->entryCount());
    }

    /**
     * In outbox mode the committed outbox row is the acknowledgement.
     *
     * @return void
     */
    public function testInOutboxModeACommittedOutboxRowIsTheAcknowledgement(): void
    {
        $this->outboxModeOn();

        self::assertTrue($this->recordsAHold());

        self::assertSame(1, $this->outboxCount());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * Nothing the attempt meets is rethrown.
     *
     * @return void
     */
    public function testNothingIsRethrown(): void
    {
        $handler = new RecordingExceptionHandler(throwsOnReport: true);

        app()->instance(ExceptionHandler::class, $handler);
        app()->instance(RecordDelivery::class, new class {
            /**
             * Refuse everything.
             *
             * @return never
             *
             * @throws \DomainException
             */
            public function check(): never
            {
                throw new \DomainException('The delivery is down.');
            }
        });

        self::assertFalse($this->recordsAHold());

        self::assertCount(1, $handler->reports());
        self::assertSame(\DomainException::class, $handler->reports()[0] instanceof LifecycleRecordFailedException ? $handler->reports()[0]->failure : null);
    }

    /**
     * A malformed delivery mode is reported and answered `false` like any
     * failure.
     *
     * @return void
     */
    public function testAMalformedDeliveryModeIsAFailure(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', 'carrier-pigeon');

        self::assertFalse($this->recordsAHold());

        $reports = $this->reporter?->reports() ?? [];

        self::assertCount(1, $reports);
        self::assertInstanceOf(LifecycleRecordFailedException::class, $reports[0]);
        self::assertSame(\InvalidArgumentException::class, $reports[0]->failure);
    }

    /**
     * Rows of `[activity]`: every lifecycle code.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity}>
     */
    public static function provideLifecycleCodes(): iterable
    {
        yield from [
            'pruned'   => [PackageActivity::PRUNED],
            'held'     => [PackageActivity::HELD],
            'released' => [PackageActivity::RELEASED],
            'imported' => [PackageActivity::IMPORTED],
        ];
    }

    /**
     * Every lifecycle code is recorded in the `audit` category with all its
     * evidence.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @return void
     */
    #[DataProvider('provideLifecycleCodes')]
    public function testTheCategoryIsAudit(PackageActivity $activity): void
    {
        $evidence = self::evidenceOf($activity);

        self::assertTrue($this->recorder()->record($activity, self::operator(), $evidence, Outcome::SUCCESS));

        $record = $this->readRecords()[0];

        self::assertSame([$activity->value, 'audit'], [$record['event'], $record['category']]);
        self::assertSamePropertyKeys(array_keys($evidence->properties), self::propertiesOf($record));
        self::assertSame([], $this->reporter?->reports());
    }

    /**
     * The recorder the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecorder
     */
    private function recorder(): LifecycleRecorder
    {
        return app(LifecycleRecorder::class);
    }

    /**
     * Record a hold the operator placed, and say whether it was acknowledged.
     *
     * @return bool
     */
    private function recordsAHold(): bool
    {
        return $this->recorder()->record(PackageActivity::HELD, self::operator(), self::evidenceOf(PackageActivity::HELD), Outcome::SUCCESS);
    }

    /**
     * Record a release as the outcome with the reason, and say whether it was
     * acknowledged.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @return bool
     */
    private function recordsARelease(Outcome $outcome, ?string $reason): bool
    {
        return $this->recorder()->record(PackageActivity::RELEASED, self::operator(), self::evidenceOf(PackageActivity::RELEASED, $outcome), $outcome, $reason);
    }

    /**
     * The operator who asks for every operation.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function operator(): Reference
    {
        return Reference::of('operator', 'ops-1');
    }

    /**
     * The evidence of the activity, with every property its code keeps, in its
     * code's order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence
     */
    private static function evidenceOf(PackageActivity $activity, Outcome $outcome = Outcome::SUCCESS): LifecycleEvidence
    {
        $operation = ['operation_id' => self::OPERATION_ID];
        $ended     = ['outcome' => $outcome->value];

        return new LifecycleEvidence(match ($activity) {
            PackageActivity::PRUNED => [
                ...$operation,
                'status'           => 'complete',
                'policy_version'   => 'config:0123456789abcdef',
                'deleted'          => 42,
                'seals'            => 2,
                'held'             => 1,
                'pending_delivery' => 0,
                'skipped_seals'    => 0,
                'categories'       => ['finance' => 40, 'audit' => 2],
                'tenants_affected' => 3,
                ...$ended,
            ],
            PackageActivity::HELD => [
                ...$operation,
                'hold_id'          => self::HOLD_ID,
                'basis'            => 'litigation',
                'scope_digest'     => str_repeat('c', 64),
                'review_by'        => null,
                'authority_reason' => 'case.review',
                ...$ended,
            ],
            PackageActivity::RELEASED => [...$operation, 'hold_id' => self::HOLD_ID, 'authority_reason' => 'case.closed', ...$ended],
            default                   => [
                ...$operation,
                'batch_id'         => '019a4b2e-7c10-7000-8000-00000000000c',
                'source_id'        => 'legacy-app',
                'format'           => 'audit-log-import/v1',
                'status'           => 'partial',
                'lines_read'       => 10,
                'imported'         => 7,
                'duplicates'       => 1,
                'conflicts'        => 1,
                'rejected'         => 1,
                'hold_id'          => null,
                'authority_reason' => 'migration',
                ...$ended,
            ],
        });
    }

    /**
     * Put the application in the delivery mode and return the acknowledging
     * connection's name.
     *
     * @param  string  $mode
     * @return string
     */
    private function acknowledgingConnectionIn(string $mode): string
    {
        if ($mode === 'sync') {
            return self::CONNECTION;
        }

        $this->moveOutboxToItsOwnConnection();
        $this->outboxModeOn();

        return self::MOVED_OUTBOX_CONNECTION;
    }

    /**
     * Put the application in outbox mode.
     *
     * @return void
     */
    private function outboxModeOn(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', 'outbox');
    }

    /**
     * Bind a registry of the contributors given.
     *
     * @param  class-string<\SineMacula\Laravel\AuditLog\Contracts\ContextContributor>  ...$contributors
     * @return void
     */
    private function contribute(string ...$contributors): void
    {
        $registry = new ContributorRegistry;

        foreach ($contributors as $contributor) {
            $registry->add($contributor);
        }

        app()->instance(ContributorRegistry::class, $registry);
    }

    /**
     * Bind a delivery that keeps what each record was delivered with and passes
     * it on.
     *
     * @return object{delivered: list<array{0: \SineMacula\Laravel\AuditLog\Records\Enums\Timing, 1: ?string, 2: bool, 3: bool, 4: bool}>}
     */
    private function spyOnTheDelivery(): object
    {
        $spy = new class (app(RecordDelivery::class)) {
            /** @var list<array{0: \SineMacula\Laravel\AuditLog\Records\Enums\Timing, 1: ?string, 2: bool, 3: bool, 4: bool}> What each record was delivered with. */
            public array $delivered = [];

            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\AuditLog\Delivery\RecordDelivery  $delivery
             */
            public function __construct(

                /** The delivery each call is handed to. */
                private readonly RecordDelivery $delivery,
            ) {}

            /**
             * Hand the check to the delivery.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
             * @param  ?string  $connection
             * @param  bool  $failClosed
             * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
             * @return void
             */
            public function check(Timing $timing, ?string $connection, bool $failClosed = false, #[\SensitiveParameter] ?CaptureSignal $capture = null): void
            {
                $this->delivery->check($timing, $connection, $failClosed, $capture);
            }

            /**
             * Keep what the record is delivered with, then hand it to the
             * delivery.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
             * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
             * @param  ?string  $connection
             * @param  bool  $failClosed
             * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
             * @param  ?\SineMacula\Laravel\AuditLog\Delivery\PackageWrite  $package
             * @return void
             */
            public function deliver(
                #[\SensitiveParameter] AuditRecord $record,
                Timing $timing,
                ?string $connection,
                bool $failClosed = false,
                #[\SensitiveParameter] ?CaptureSignal $capture = null,
                #[\SensitiveParameter] ?PackageWrite $package = null,
            ): void {
                $this->delivered[] = [$timing, $connection, $failClosed, $capture !== null, $package !== null];

                $this->delivery->deliver($record, $timing, $connection, $failClosed, $capture, $package);
            }
        };

        app()->instance(RecordDelivery::class, $spy);

        return $spy;
    }
}
