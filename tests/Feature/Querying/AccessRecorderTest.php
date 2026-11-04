<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Delivery\SpillReader;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Querying\AccessEvidence;
use SineMacula\Laravel\AuditLog\Querying\AccessRecorder;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Querying\Enums\ReadRefusal;
use SineMacula\Laravel\AuditLog\Querying\FieldDisclosure;
use SineMacula\Laravel\AuditLog\Querying\ReadTerms;
use SineMacula\Laravel\AuditLog\Querying\TrailFilters;
use SineMacula\Laravel\AuditLog\Querying\Viewer;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\NullAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Contributors\ActorFillingContributor;
use Tests\Fixtures\Contributors\TenantContributor;
use Tests\Fixtures\Contributors\TransactionOpeningContributor;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Querying\ClosurePolicy;
use Tests\TestCase;

/**
 * Feature tests for the writer of the records of the package's own reads: the
 * viewer's record in the `audit` category, fail-closed whatever the failure
 * mode, its disclosure attachment, the tenant of a scope of exactly one or
 * explicitly none, its evidence kept exactly or the read refused, a failed
 * write spilled with its attachment, reported once and refused, a committed
 * outbox row as the acknowledgement, the acknowledged record returned, and a
 * store that cannot keep it, a write never acknowledged and a transaction the
 * policy opened each refusing the read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AccessRecorder::class)]
final class AccessRecorderTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore, InteractsWithOutbox, ReadsTheTrail;

    /** @var string The organisation a scope of one tenant sees. */
    private const string TENANT_ID = 'org_01';

    /** @var list<array{0: string, 1: string}> The entries a page showed, by id and HMAC. */
    private const array RETURNED = [
        ['01932b4e-8a40-7000-8000-000000000002', 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2'],
        ['01932b4e-8a40-7000-8000-000000000001', 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1'],
    ];

    /** @var ?\Tests\Fixtures\Privacy\RecordingExceptionHandler What each failure is reported to. */
    private ?RecordingExceptionHandler $reporter = null;

    /**
     * Bind the read path, report to a recording handler, and capture every line
     * logged.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
        $this->captureLogLines();

        $this->reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $this->reporter);
    }

    /**
     * Roll back any transaction a test left open, and put the entries table
     * back.
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

        parent::tearDown();
    }

    /**
     * The record is the viewer's, by its reference, whoever a contributor would
     * name, under the read's code, in the `audit` category, with the evidence's
     * properties in their order and its outcome.
     *
     * @return void
     */
    public function testTheRecordIsTheViewersInTheAuditCategory(): void
    {
        $this->contribute(ActorFillingContributor::class);

        $finalised = $this->record();
        $records   = $this->readRecords();

        self::assertCount(1, $records);
        self::assertSame($finalised->record->id, $records[0]['id']);
        self::assertSame('audit_log.trail_read', $records[0]['event']);
        self::assertSame('audit', $records[0]['category']);
        self::assertSame('success', $records[0]['outcome']);
        self::assertNull($records[0]['reason']);
        self::assertSame(['App\Models\User', '7'], [$records[0]['actor_type'], $records[0]['actor_id']]);
        self::assertSamePropertyKeys(
            ['purpose', 'query_fingerprint', 'scope_fingerprint', 'fingerprint_key', 'policy', 'page', 'per_page', 'returned', 'reveal', 'fields', 'outcome', '_audit'],
            self::propertiesOf($records[0]),
        );
        self::assertSame(2, self::propertiesOf($records[0])['returned']);
        self::assertFalse(self::propertiesOf($records[0])['reveal']);
        self::assertSameProperties(['encrypted' => 2, 'erased' => 0, 'revealed' => 0, 'unreadable' => 0], self::propertiesOf($records[0])['fields']);
    }

    /**
     * A denial and a failure are recorded with their reasons.
     *
     * @return void
     */
    public function testTheOutcomeGoesWithItsReason(): void
    {
        $this->record(outcome: Outcome::DENIED, reason: 'no_scope');
        $this->record(outcome: Outcome::FAILURE, reason: 'query_failed');

        $records = $this->readRecords();

        self::assertSame([['denied', 'no_scope'], ['failure', 'query_failed']], array_map(static fn (array $record): array => [$record['outcome'], $record['reason']], $records));
        self::assertSame([0, 0], array_map(static fn (array $record): mixed => self::propertiesOf($record)['returned'], $records));
    }

    /**
     * Rows of `[failure mode]`: both.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideFailureModes(): iterable
    {
        yield from [
            'report' => ['report'],
            'throw'  => ['throw'],
        ];
    }

    /**
     * The record is fail-closed whatever the failure mode: under `report`,
     * where an application's record would go on, a failed write refuses the
     * read as under `throw`.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideFailureModes')]
    public function testTheRecordIsFailClosedWhateverTheFailureMode(string $mode): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', $mode);

        $this->pointAtProbeTable();

        $this->assertUnrecorded(fn () => $this->record());

        self::assertSame(0, $this->probeCount());
        self::assertCount(1, $this->spillLines());
    }

    /**
     * The record carries a disclosure attachment holding the read's normalised
     * filters, its whole scope and the id and HMAC of each entry it showed, in
     * the order shown, described by the signed descriptor.
     *
     * @return void
     */
    public function testTheDisclosureAttachmentHoldsFiltersScopeAndReturnedPairs(): void
    {
        $filters = TrailFilters::none()->withCategories(['finance']);
        $scope   = AccessScope::tenants(self::tenant());

        $finalised  = $this->recordUnder($scope, $filters);
        $disclosure = $this->disclosureOf($finalised->record->id);
        $nonce      = $disclosure['nonce'] ?? null;

        unset($disclosure['nonce']);

        self::assertSame([
            'disclosure_version' => 1,
            'filters'            => $filters->normalised(),
            'members'            => self::RETURNED,
            'page'               => null,
            'scope'              => $scope->toArray(),
        ], $disclosure);
        self::assertIsString($nonce);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $nonce);

        $descriptor = $finalised->record->properties['_audit']['manifest'] ?? null;

        self::assertIsArray($descriptor);
        self::assertSame([ArtifactKind::DISCLOSURE->value, 2], [$descriptor['kind'], $descriptor['count']]);
    }

    /**
     * The disclosure attachment keeps the owner whose data the read's entries
     * hold among its normalised filters, and the record's own properties hold
     * only the keyed fingerprint of them, never the owner.
     *
     * @return void
     */
    public function testTheDisclosureAttachmentHoldsTheOwnerHoldingData(): void
    {
        $owner   = Reference::of('App\Models\User', 'owner_9917');
        $filters = TrailFilters::none()->withHoldingDataOf($owner);

        $finalised  = $this->recordUnder(AccessScope::all(), $filters);
        $disclosure = $this->disclosureOf($finalised->record->id);

        self::assertSame($filters->normalised(), $disclosure['filters']);
        self::assertSame(['App\Models\User', 'owner_9917'], $disclosure['filters']['holding_data_of']);
        self::assertSame(self::termsOf($filters, AccessScope::all())->queryFingerprint, $finalised->record->properties['query_fingerprint'] ?? null);
        self::assertStringNotContainsString('owner_9917', json_encode($finalised->record->properties, JSON_THROW_ON_ERROR));
    }

    /**
     * A scope of exactly one tenant records the read in that tenant.
     *
     * @return void
     */
    public function testASingleTenantScopeRecordsThatTenant(): void
    {
        $this->recordUnder(AccessScope::tenants(self::tenant()));

        $record = $this->readRecords()[0];

        self::assertSame(['organisation', self::TENANT_ID], [$record['tenant_type'], $record['tenant_id']]);
    }

    /**
     * Rows of `[scope]`: every scope that is not exactly one tenant, and no
     * scope at all, as a policy that failed gives.
     *
     * @return iterable<string, array{0: ?\SineMacula\Laravel\AuditLog\Access\AccessScope}>
     */
    public static function provideOtherScopes(): iterable
    {
        yield from [
            'every tenant'                  => [AccessScope::all()],
            'two tenants'                   => [AccessScope::tenants(self::tenant(), Reference::of('organisation', 'org_02'))],
            'one tenant and the tenantless' => [AccessScope::tenants(self::tenant())->withTenantless()],
            'denied'                        => [AccessScope::none()],
            'no scope'                      => [null],
        ];
    }

    /**
     * Any other scope records the read in explicitly no tenant, even with a
     * contributor that fills the tenant of every record, which an application's
     * record does take.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return void
     */
    #[DataProvider('provideOtherScopes')]
    public function testAnyOtherScopeRecordsNoTenantEvenWithAnAmbientOne(?AccessScope $scope): void
    {
        $registry = $this->contribute(TenantContributor::class);

        $this->recordUnder($scope);

        $record = $this->readRecords()[0];

        self::assertNull($record['tenant_type']);
        self::assertNull($record['tenant_id']);

        $ambient = (new Recorder(app(EventCatalogue::class), $registry))->event('invoice.approved')->immediately()->record();

        self::assertSame(TenantContributor::ID, $ambient->tenantId);
    }

    /**
     * A redaction key that names an evidence property would store the record
     * without that evidence, so the read is refused as altering its evidence,
     * before anything is written, spilled or reported.
     *
     * @return void
     */
    public function testAnEvidenceKeyRedactedByConfigurationRefusesTheRead(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['page']);

        $this->expectExceptionObject(AuditReadRefusedException::evidenceAltered());

        try {
            $this->record();
        } finally {
            self::assertSame(0, $this->entryCount());
            self::assertSame([], $this->spillLines());
            self::assertSame([], $this->reporter?->reports());
        }
    }

    /**
     * A failed write is spilled, reported once as the store's sanitised
     * failure, and refuses the read as unrecorded, carrying nothing of it.
     *
     * @return void
     */
    public function testAFailedWriteIsSpilledReportedOnceAndRefused(): void
    {
        $this->pointAtProbeTable();

        $refusal = $this->assertUnrecorded(fn () => $this->record());
        $reports = $this->reporter?->reports() ?? [];

        self::assertNull($refusal->getPrevious());
        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $reports);
        self::assertInstanceOf(AuditWriteFailedException::class, $reports[0]);
    }

    /**
     * The spilled record is the whole bundle, its disclosure attachment
     * included, so a replay restores both.
     *
     * @return void
     */
    public function testASpilledReadRecordKeepsItsAttachment(): void
    {
        $this->pointAtProbeTable();

        $this->assertUnrecorded(fn () => $this->record());

        $spilled = app(EnvelopeCodec::class)->decode((string) SpillReader::extract($this->spillLines()[0]));

        self::assertSame('audit_log.trail_read', $spilled->record->event);
        self::assertSame(ArtifactKind::DISCLOSURE->value, $spilled->record->attachment?->kind);
        self::assertSame(2, $spilled->record->attachment->memberCount);
    }

    /**
     * In outbox mode the committed outbox row is the acknowledgement: the
     * finalised record is returned once it is inserted, before any drain stores
     * it.
     *
     * @return void
     */
    public function testInOutboxModeACommittedOutboxRowIsTheAcknowledgement(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', 'outbox');

        $finalised = $this->record();

        self::assertNotNull($this->outboxRow($finalised->record->id));
        self::assertSame(0, $this->entryCount());
    }

    /**
     * Rows of `[delivery mode]`: the store writes the record, or the outbox
     * does on the storage connection.
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
     * A contributor that leaves a transaction open on the acknowledging
     * connection, after the check made before the write, has the record
     * inserted inside it: that acknowledgement could still roll back, so it is
     * never accepted, and the read is refused naming the connection, reported
     * once. Once the transaction rolls back, nothing of the read is left.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideDeliveryModes')]
    public function testAnAcknowledgementInsideATransactionAContributorOpenedIsRefused(string $mode): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', $mode);

        $handler = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $handler);

        $this->contribute(TransactionOpeningContributor::class);

        $connection = DB::connection(self::CONNECTION);
        $level      = $connection->transactionLevel();

        try {
            $this->record();
            self::fail('Expected the read to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(ReadRefusal::IN_TRANSACTION, $refusal->reason);
            self::assertSame(self::CONNECTION, $refusal->connection);
        }

        self::assertSame($level + 1, $connection->transactionLevel());
        self::assertCount(1, $handler->reports());

        $connection->rollBack();

        self::assertSame([], $this->readRecords());
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * The finalised record returned is the one the store acknowledged: its id,
     * recorded time, key and HMAC are the stored row's, and it carries its
     * attachment.
     *
     * @return void
     */
    public function testTheAcknowledgedRecordIsReturned(): void
    {
        $finalised = $this->record();
        $stored    = $this->storedRow($finalised->record->id);

        self::assertSame([$stored['recorded_at'], $stored['key_id'], $stored['hmac']], [$finalised->recordedAt, $finalised->keyId, $finalised->hmac]);
        self::assertNotNull($finalised->record->attachment);
    }

    /**
     * A record without an artifact, as a failed publication's, is written and
     * returned with no attachment.
     *
     * @return void
     */
    public function testARecordWithoutAManifestCarriesNoArtifact(): void
    {
        $evidence  = AccessEvidence::forPublishFailure('01932b4e-8a40-7000-8000-000000000001');
        $finalised = app(AccessRecorder::class)->record(PackageActivity::EXPORT_PUBLISH_FAILED, Viewer::of($this->viewer()), null, $evidence, Outcome::FAILURE, 'publish_failed');

        self::assertNull($finalised->record->attachment);
        self::assertSame(1, $this->entryCount());
        self::assertSame(0, $this->artifactCount());
    }

    /**
     * In sync mode a store that does not say a return is durable cannot keep
     * the record fail-closed, so the delivery refuses it, the refusal is
     * reported once, and the read is refused as unrecorded.
     *
     * @return void
     */
    public function testANonDurableStoreIsRefused(): void
    {
        app()->instance(AuditStore::class, new NullAuditStore);

        $this->assertUnrecorded(fn () => $this->record());

        $reports = $this->reporter?->reports() ?? [];

        self::assertCount(1, $reports);
        self::assertInstanceOf(\LogicException::class, $reports[0]);
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A write that returns without the delivery acknowledging it, whatever let
     * it, is never taken as written: the refusal is reported once and the read
     * is refused as unrecorded.
     *
     * @return void
     */
    public function testAWriteNeverAcknowledgedIsRefused(): void
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

        $this->assertUnrecorded(fn () => $this->record());

        $reports = $this->reporter?->reports() ?? [];

        self::assertCount(1, $reports);
        self::assertSame(AuditReadRefusedException::unrecorded()->getMessage(), $reports[0]->getMessage());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A reporter that fails is ignored: the read is refused as unrecorded all
     * the same.
     *
     * @return void
     */
    public function testAFailingReporterStillRefuses(): void
    {
        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler(throwsOnReport: true));

        $this->pointAtProbeTable();

        $this->assertUnrecorded(fn () => $this->record());
    }

    /**
     * A policy that opens a transaction on the storage connection, after the
     * gate let the read in, has the read refused just before its record is
     * written: nothing is returned, and once the transaction rolls back no
     * record of the read is left.
     *
     * @return void
     */
    public function testATransactionOpenedByThePolicyRefusesBeforeTheWrite(): void
    {
        $this->seedEntry();

        $policy = $this->usePolicy(static function (): AccessScope {
            DB::connection(self::CONNECTION)->beginTransaction();

            return AccessScope::all();
        });

        $trail = app(AuditTrail::class)->visibleTo($this->viewer());

        try {
            $trail->cursorPaginate();

            self::fail('Expected the read to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(AuditReadRefusedException::inTransaction(self::CONNECTION)->getMessage(), $refusal->getMessage());
        }

        DB::connection(self::CONNECTION)->rollBack();

        self::assertCount(1, $policy->asked());
        self::assertSame([], $this->readRecords());
        self::assertSame([], $this->reporter?->reports());
    }

    /**
     * The organisation a scope of one tenant sees.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function tenant(): Reference
    {
        return Reference::of('organisation', self::TENANT_ID);
    }

    /**
     * Record a page read by the viewer as the outcome with the reason, under
     * every tenant, or no scope for a failure, showing the two returned entries
     * when it succeeded, and return the acknowledged record.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function record(Outcome $outcome = Outcome::SUCCESS, ?string $reason = null): FinalisedRecord
    {
        return $this->recordUnder($outcome === Outcome::FAILURE ? null : AccessScope::all(), null, $outcome, $reason);
    }

    /**
     * Record a page read by the viewer under the scope and the filters, as the
     * outcome with the reason, showing the two returned entries when it
     * succeeded, and return the acknowledged record.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function recordUnder(?AccessScope $scope, ?TrailFilters $filters = null, Outcome $outcome = Outcome::SUCCESS, ?string $reason = null): FinalisedRecord
    {
        $terms    = ReadTerms::of(app(KeyRing::class)->signingKey(), $filters ?? TrailFilters::none(), $scope);
        $fields   = new FieldDisclosure($scope?->revealsEncryptedFields() ?? false, 2, 0, 0, 0);
        $evidence = AccessEvidence::forPage($terms, ClosurePolicy::class, false, null, 50, self::RETURNED, $fields, $outcome);

        return app(AccessRecorder::class)->record(PackageActivity::TRAIL_READ, Viewer::of($this->viewer()), $scope, $evidence, $outcome, $reason);
    }

    /**
     * Assert the work refuses the read as unrecorded, and return the refusal.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(): mixed  $work
     * @return \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function assertUnrecorded(\Closure $work): AuditReadRefusedException
    {
        try {
            $work();
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(AuditReadRefusedException::unrecorded()->getMessage(), $refusal->getMessage());

            return $refusal;
        }

        self::fail('Expected the read to be refused as unrecorded.');
    }

    /**
     * Bind a registry of the default contributors and the one given, as an
     * application registers it while it boots, and return it.
     *
     * @param  class-string<\SineMacula\Laravel\AuditLog\Contracts\ContextContributor>  $contributor
     * @return \SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry
     */
    private function contribute(string $contributor): ContributorRegistry
    {
        $registry = new ContributorRegistry;

        $registry->add($contributor);

        app()->instance(ContributorRegistry::class, $registry);

        return $registry;
    }

    /**
     * The number of rows in the artifacts table.
     *
     * @return int
     */
    private function artifactCount(): int
    {
        return $this->storageConnection()->table(EntrySettings::artifactsTable())->count();
    }
}
