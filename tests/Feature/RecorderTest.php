<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Events\Dispatcher as EventDispatcher;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Ramsey\Uuid\Uuid;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Capture\ModelWatcher;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contributors\ActorContributor;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Contributors\OriginContributor;
use SineMacula\Laravel\AuditLog\Contributors\RequestContributor;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Listeners\CaptureMappedEvent;
use SineMacula\Laravel\AuditLog\Privacy\FieldEncryptionFailedException;
use SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Fixtures\Capture\Events\AccountEvent;
use Tests\Fixtures\Capture\Events\PortalSignedIn;
use Tests\Fixtures\Capture\Events\RenewedPortalSession;
use Tests\Fixtures\Capture\Mappers\NotAMapper;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Capture\Models\PlainLine;
use Tests\Fixtures\Contributors\ActorFillingContributor;
use Tests\Fixtures\Contributors\SecretFillingContributor;
use Tests\Fixtures\Contributors\TenantContributor;
use Tests\Fixtures\Definitions\Enums\DisclosureActivity;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;
use Tests\Fixtures\Definitions\Enums\UnretainedDisclosureActivity;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\Fixtures\Privacy\ThrowingFieldEncrypter;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\Fixtures\Stores\PlainStore;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;
use Tests\Unit\Stubs\Enums\StubActivity;
use Tests\Unit\Stubs\StubAuthUser;
use Tests\Unit\Stubs\StubDocument;

/**
 * Feature tests for the recorder: what each of its calls does, and the capture
 * pipeline a recorded activity runs: the definition, the timing's checks, the
 * contributors in order, minimising what they leave, the clock and source, and
 * delivery, the trail it gives as the way into the read path, and the lifecycle
 * it gives as the way into holds, prunes and imports. Its collaborators come
 * from the current container on every capture, and it holds nothing but
 * registration data.
 *
 * Definitions and contributors are registered on a recorder of a test's own,
 * since the application's has frozen by the time a test runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Recorder::class)]
final class RecorderTest extends TestCase
{
    /** @var string The code most tests record. */
    private const string CODE = 'invoice.approved';

    /** @var string The digest of the golden subjects' manifest. */
    private const string GOLDEN_DIGEST = '0bee9fea9443d63a556a7fe8d19b18920d8aac7c234e48afc739a4df9380ed4d';

    /** @var string The message a code with a reason and a success is refused with. */
    private const string REASON_WITH_SUCCESS = 'A reason goes with a failure or a denial, not a success.';

    /** @var \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore The store records reach. */
    private FakeAuditStore $fake;

    /**
     * Fake the store.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fake = AuditLog::fake();
    }

    /**
     * Roll back any transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(self::CONNECTION);

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        parent::tearDown();
    }

    /**
     * `record()` returns the record it captured, which is what the store holds.
     *
     * @return void
     */
    public function testRecordReturnsTheCapturedRecord(): void
    {
        $record = AuditLog::record(self::CODE);

        self::assertSame(self::CODE, $record->event);
        self::assertSame(Outcome::SUCCESS->value, $record->outcome);
        self::assertSame([$record], $this->fake->recorded());
    }

    /**
     * The subject and the properties go on the record.
     *
     * @return void
     */
    public function testRecordFillsTheSubjectAndProperties(): void
    {
        $record = AuditLog::record(self::CODE, Reference::of('invoice', '42'), ['amount' => '1200.00']);

        self::assertSame('invoice', $record->subjectType);
        self::assertSame('42', $record->subjectId);
        self::assertSame(['amount' => '1200.00'], $record->properties);
    }

    /**
     * Neither a subject nor properties leaves both empty.
     *
     * @return void
     */
    public function testRecordWithNeitherLeavesBothEmpty(): void
    {
        $record = AuditLog::record(self::CODE);

        self::assertNull($record->subjectType);
        self::assertNull($record->properties);
    }

    /**
     * A failure keeps its reason.
     *
     * @return void
     */
    public function testRecordWithAFailureAndReason(): void
    {
        $record = AuditLog::record(self::CODE, outcome: Outcome::FAILURE, reason: 'card_declined');

        self::assertSame(Outcome::FAILURE->value, $record->outcome);
        self::assertSame('card_declined', $record->reason);
    }

    /**
     * A denial keeps its reason.
     *
     * @return void
     */
    public function testRecordWithADenialAndReason(): void
    {
        $record = AuditLog::record(self::CODE, outcome: Outcome::DENIED, reason: 'policy_refused');

        self::assertSame(Outcome::DENIED->value, $record->outcome);
        self::assertSame('policy_refused', $record->reason);
    }

    /**
     * A failure and a denial need no reason.
     *
     * @return void
     */
    public function testAFailureAndADenialNeedNoReason(): void
    {
        self::assertNull(AuditLog::record(self::CODE, outcome: Outcome::FAILURE)->reason);
        self::assertNull(AuditLog::record(self::CODE, outcome: Outcome::DENIED)->reason);
    }

    /**
     * A reason with a success would have nowhere to go, so it is refused rather
     * than dropped, before anything is built: even an invalid code gets this
     * refusal, and nothing is stored.
     *
     * @return void
     */
    public function testAReasonWithASuccessIsRefused(): void
    {
        try {
            AuditLog::recorder()->record('NOT A CODE', reason: 'card_declined');

            self::fail('Expected the reason to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(self::REASON_WITH_SUCCESS, $exception->getMessage());
        }

        self::assertSame(0, $this->fake->count());
    }

    /**
     * `event()` gives a builder for the code, which writes when it is recorded
     * and not before.
     *
     * @return void
     */
    public function testEventReturnsABuilderThatWritesNothingUntilRecorded(): void
    {
        $pending = AuditLog::event(self::CODE);

        self::assertSame(self::CODE, $pending->snapshot()->code?->value);
        self::assertSame(0, $this->fake->count());

        $record = $pending->record();

        self::assertSame([$record], $this->fake->recorded());
    }

    /**
     * A builder never recorded writes nothing.
     *
     * @return void
     */
    public function testABuilderDroppedWritesNothing(): void
    {
        AuditLog::event(self::CODE)->on(Reference::of('invoice', '42'));

        gc_collect_cycles();

        self::assertSame(0, $this->fake->count());
    }

    /**
     * A builder is recorded once.
     *
     * @return void
     */
    public function testASecondRecordIsALogicError(): void
    {
        $pending = AuditLog::event(self::CODE);

        $pending->record();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A pending record is recorded once, and this one has already been recorded.');

        $pending->record();
    }

    /**
     * Rows of `[call]`: each way of naming a code.
     *
     * @return iterable<string, array{0: \Closure(string): (\SineMacula\Laravel\AuditLog\Records\AuditRecord|\SineMacula\Laravel\AuditLog\Records\PendingRecord)}>
     */
    public static function provideCodePaths(): iterable
    {
        yield from [
            'record'   => [static fn (string $code): AuditRecord => AuditLog::record($code)],
            'event'    => [static fn (string $code): PendingRecord => AuditLog::event($code)],
            'accessed' => [static fn (string $code): PendingRecord => AuditLog::accessed($code, Reference::of('invoice', '42'), 'legal_hold', 'portal')],
        ];
    }

    /**
     * An invalid code is a programming error on every path.
     *
     * @param  \Closure(string): (\SineMacula\Laravel\AuditLog\Records\AuditRecord|\SineMacula\Laravel\AuditLog\Records\PendingRecord)  $call
     * @return void
     */
    #[DataProvider('provideCodePaths')]
    public function testAnInvalidCodeIsRefusedUnderEveryPath(\Closure $call): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An event code must be lower-case dotted segments');

        $call('Invoice Approved');
    }

    /**
     * The package's own prefix is refused on every path.
     *
     * @param  \Closure(string): (\SineMacula\Laravel\AuditLog\Records\AuditRecord|\SineMacula\Laravel\AuditLog\Records\PendingRecord)  $call
     * @return void
     */
    #[DataProvider('provideCodePaths')]
    public function testTheReservedPrefixIsRefused(\Closure $call): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('audit_log.');

        $call('audit_log.something');
    }

    /**
     * The defaults are resolved first, in their order, then each registered
     * contributor, in its order, each one for the capture.
     *
     * @return void
     */
    public function testContributorsRunInOrderDefaultsFirst(): void
    {
        $recorder = self::recorder();

        $recorder->contribute(TenantContributor::class);
        $recorder->contribute(ActorFillingContributor::class);

        $order = [];

        foreach ([OriginContributor::class, RequestContributor::class, ActorContributor::class, TenantContributor::class, ActorFillingContributor::class] as $class) {
            $this->app?->resolving($class, static function () use (&$order, $class): void {
                $order[] = $class;
            });
        }

        $recorder->record(self::CODE);

        self::assertSame([OriginContributor::class, RequestContributor::class, ActorContributor::class, TenantContributor::class, ActorFillingContributor::class], $order);
    }

    /**
     * A default fills the field first, so the ambient actor beats a later
     * contributor's, and that contributor fills what is still a gap.
     *
     * @return void
     */
    public function testADefaultBeatsALaterContributor(): void
    {
        Auth::guard('web')->setUser((new StubAuthUser)->forceFill(['id' => 42]));

        $recorder = self::recorder();

        $recorder->contribute(ActorFillingContributor::class);

        $record = $recorder->record(self::CODE);

        self::assertSame(StubAuthUser::class, $record->actorType);
        self::assertSame('web', $record->guard);
    }

    /**
     * A contributor fills what nothing else gave.
     *
     * @return void
     */
    public function testAnApplicationContributorFillsAGap(): void
    {
        $recorder = self::recorder();

        $recorder->contribute(TenantContributor::class);
        $recorder->contribute(ActorFillingContributor::class);

        $record = $recorder->record(self::CODE);

        self::assertSame(TenantContributor::TYPE, $record->tenantType);
        self::assertSame(TenantContributor::ID, $record->tenantId);
        self::assertSame(ActorFillingContributor::TYPE, $record->actorType);
        self::assertSame(ActorFillingContributor::GUARD, $record->guard);
    }

    /**
     * An explicit value stays, `by(null)` included, whatever a contributor
     * fills.
     *
     * @return void
     */
    public function testAContributorNeverReplacesAnExplicitValue(): void
    {
        $recorder = self::recorder();

        $recorder->contribute(TenantContributor::class);
        $recorder->contribute(ActorFillingContributor::class);

        $record = $recorder->event(self::CODE)->forTenant(Reference::of('organisation', 'explicit'))->by(null)->record();

        self::assertSame('explicit', $record->tenantId);
        self::assertNull($record->actorType);
    }

    /**
     * Of two contributors filling one field, the first registered wins,
     * whichever way round they are registered.
     *
     * @return void
     */
    public function testTheFirstContributorToFillWins(): void
    {
        $other = self::otherTenantContributor();

        $first = self::recorder();

        $first->contribute(TenantContributor::class);
        $first->contribute($other);

        self::assertSame(TenantContributor::ID, $first->record(self::CODE)->tenantId);

        $second = self::recorder();

        $second->contribute($other);
        $second->contribute(TenantContributor::class);

        self::assertSame('organisation-2', $second->record(self::CODE)->tenantId);
    }

    /**
     * A contributor is resolved from the container for every capture, so a
     * worker retains none and a later binding is the one used.
     *
     * @return void
     */
    public function testAContributorIsResolvedPerCapture(): void
    {
        $recorder = self::recorder();

        $recorder->contribute(TenantContributor::class);

        $resolved = 0;

        $this->app?->resolving(TenantContributor::class, static function () use (&$resolved): void {
            $resolved++;
        });

        $recorder->record(self::CODE);
        $recorder->record(self::CODE);

        self::assertSame(2, $resolved);
    }

    /**
     * A contributor's failure propagates, and nothing is stored.
     *
     * @return void
     */
    public function testAThrowingContributorPropagates(): void
    {
        $contributor = new class implements ContextContributor {
            /**
             * Fail.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\Contribution  $contribution
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function contribute(Contribution $contribution): void
            {
                throw new \RuntimeException('The contributor failed.');
            }
        };

        $recorder = self::recorder();

        $recorder->contribute($contributor::class);

        try {
            $recorder->record(self::CODE);

            self::fail('Expected the contributor\'s failure to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The contributor failed.', $exception->getMessage());
        }

        self::assertSame(0, $this->fake->count());
    }

    /**
     * A registered code takes its definition's version and category.
     *
     * @return void
     */
    public function testTheDefinitionsVersionAndCategoryAreUsed(): void
    {
        $recorder = self::recorder();

        $recorder->define(InvoiceActivity::class);

        $record = $recorder->record(InvoiceActivity::APPROVED);

        self::assertSame(2, $record->eventVersion);
        self::assertSame('finance', $record->category);
    }

    /**
     * An unregistered code takes version 1 and the `general` category.
     *
     * @return void
     */
    public function testAnUnregisteredCodeTakesThePermissiveDefault(): void
    {
        $record = AuditLog::record(self::CODE);

        self::assertSame(1, $record->eventVersion);
        self::assertSame('general', $record->category);
    }

    /**
     * With registration required an unregistered code is refused, nothing is
     * consumed and nothing is stored; a registered one is accepted.
     *
     * @return void
     */
    public function testAnUnregisteredCodeIsRefusedWhenRegistrationIsRequired(): void
    {
        app(ConfigRepository::class)->set('audit-log.definitions.require_registered', true);

        $recorder = self::recorder();
        $pending  = $recorder->event(self::CODE);

        try {
            $pending->record();

            self::fail('Expected the code to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('The event code `invoice.approved` is not registered, and unregistered codes are refused.', $exception->getMessage());
        }

        self::assertFalse($pending->isConsumed());
        self::assertSame(0, $this->fake->count());

        $recorder->define(InvoiceActivity::class);

        self::assertSame(2, $pending->record()->eventVersion);
    }

    /**
     * The setting is read on every capture and fails closed.
     *
     * @return void
     */
    public function testAMalformedRequireRegisteredFailsClosed(): void
    {
        app(ConfigRepository::class)->set('audit-log.definitions.require_registered', 'yes');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.definitions.require_registered` must be true or false.');

        AuditLog::record(self::CODE);
    }

    /**
     * The id is a UUID v7 whose time is the clock's.
     *
     * @return void
     */
    public function testTheIdIsAUuid7OfTheClock(): void
    {
        $this->freezeClock('2026-03-04 05:06:07.123');

        $id = AuditLog::record(self::CODE)->id;

        self::assertTrue(Uuid::isValid($id));
        self::assertSame('7', $id[14]);
        self::assertSame((int) (new \DateTimeImmutable('2026-03-04 05:06:07.123 UTC'))->format('Uv'), hexdec(str_replace('-', '', substr($id, 0, 13))));
    }

    /**
     * When the activity occurred is the clock's time, in UTC.
     *
     * @return void
     */
    public function testOccurredAtComesFromTheClock(): void
    {
        $this->freezeClock('2026-03-04 05:06:07.123456');

        self::assertSame('2026-03-04T05:06:07.123456Z', AuditLog::record(self::CODE)->occurredAt);
    }

    /**
     * The source's id and region are the configured ones.
     *
     * @return void
     */
    public function testTheSourceComesFromTheSettings(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.source.id', 'billing-eu');
        $config->set('audit-log.source.region', 'eu-west-1');

        $record = AuditLog::record(self::CODE);

        self::assertSame('billing-eu', $record->sourceId);
        self::assertSame('eu-west-1', $record->sourceRegion);
    }

    /**
     * A malformed source fails closed, and nothing is stored.
     *
     * @return void
     */
    public function testAMalformedSourceFailsClosed(): void
    {
        app(ConfigRepository::class)->set('audit-log.source.id', 42);

        try {
            AuditLog::recorder()->record(self::CODE);

            self::fail('Expected the source to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('`audit-log.source.id` must be from 1 to 64 characters, with no control characters.', $exception->getMessage());
        }

        self::assertSame(0, $this->fake->count());
    }

    /**
     * A record with no timing waits for the transaction to commit.
     *
     * @return void
     */
    public function testExplicitRecordsDefaultToAfterCommit(): void
    {
        DB::connection(self::CONNECTION)->transaction(function (): void {
            AuditLog::record(self::CODE);

            self::assertSame(0, $this->fake->count());
        });

        self::assertSame(1, $this->fake->count());
    }

    /**
     * A fail-closed record with no timing does not wait.
     *
     * @return void
     */
    public function testFailClosedIsWrittenImmediately(): void
    {
        DB::connection(self::CONNECTION)->transaction(function (): void {
            AuditLog::event(self::CODE)->failClosed()->record();

            self::assertSame(1, $this->fake->count());
        });

        self::assertSame(1, $this->fake->count());
    }

    /**
     * A timing that cannot be honoured is refused before anything is consumed,
     * so the same builder records once it can.
     *
     * @return void
     */
    public function testATimingRefusalLeavesTheBuilderUsable(): void
    {
        $pending = AuditLog::event(self::CODE)->transactional();

        try {
            $pending->record();

            self::fail('Expected the timing to be refused.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString('needs a transaction open on the storage connection', $exception->getMessage());
        }

        self::assertFalse($pending->isConsumed());
        self::assertSame(0, $this->fake->count());

        DB::connection(self::CONNECTION)->transaction(static function () use ($pending): void {
            $pending->record();
        });

        self::assertSame(1, $this->fake->count());
    }

    /**
     * A timing refusal comes before any contributor runs.
     *
     * @return void
     */
    public function testATimingRefusalRunsNoContributor(): void
    {
        $resolved = 0;

        $this->app?->resolving(OriginContributor::class, static function () use (&$resolved): void {
            $resolved++;
        });

        try {
            AuditLog::event(self::CODE)->transactional()->record();

            self::fail('Expected the timing to be refused.');
        } catch (\LogicException) {
            self::assertSame(0, $resolved);
        }
    }

    /**
     * Under the `throw` mode a failed write reaches the caller, sanitised.
     *
     * @return void
     */
    public function testAFailedWritePropagates(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        try {
            AuditLog::record(self::CODE);

            self::fail('Expected the failure to propagate.');
        } catch (AuditWriteFailedException $exception) {
            self::assertSame(\RuntimeException::class, $exception->exceptionClass);
            self::assertNull($exception->getPrevious());
        }
    }

    /**
     * In the default mode a failed write does not reach the caller, and the
     * captured record is still returned.
     *
     * @return void
     */
    public function testRecordReturnsTheCapturedRecordWhenTheWriteFails(): void
    {
        $fake = FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $record = AuditLog::record(self::CODE);

        self::assertSame(self::CODE, $record->event);
        self::assertSame(0, $fake->count());
    }

    /**
     * A record made while another is being written is returned as captured, and
     * stored nowhere.
     *
     * @return void
     */
    public function testRecordReturnsTheCapturedRecordWhenRefusedInsideAWrite(): void
    {
        $inner = null;
        $calls = 0;

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);
        app()->instance(AuditStore::class, new CallbackStore(static function () use (&$inner, &$calls): void {
            $calls++;
            $inner = AuditLog::record('invoice.refused');
        }));

        AuditLog::record(self::CODE);

        self::assertSame(1, $calls);
        self::assertInstanceOf(AuditRecord::class, $inner);
        self::assertSame('invoice.refused', $inner->event);
    }

    /**
     * The builder's fail-closed choice reaches the delivery: refused for a
     * store that does not say it is durable, which an ordinary record is not.
     *
     * @return void
     */
    public function testAFailClosedBuilderIsPassedThrough(): void
    {
        $store = new PlainStore;

        app()->instance(AuditStore::class, $store);

        AuditLog::event(self::CODE)->immediately()->record();

        self::assertSame(1, $store->calls());

        try {
            AuditLog::event(self::CODE)->failClosed()->record();

            self::fail('Expected the fail-closed record to be refused.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString('A fail-closed record needs a durable store', $exception->getMessage());
        }

        self::assertSame(1, $store->calls());
    }

    /**
     * A plaintext note reaches the record's properties under the package's own
     * key.
     *
     * @return void
     */
    public function testANoteFlowsThroughToTheRecord(): void
    {
        $record = AuditLog::event(self::CODE)->withNote('Approved by phone.')->record();

        self::assertSame(['_audit' => ['note' => 'Approved by phone.']], $record->properties);
    }

    /**
     * `accessed()` gives a builder of a success on the subject.
     *
     * @return void
     */
    public function testAccessedReturnsABuilderWithTheOutcomeSuccess(): void
    {
        $snapshot = AuditLog::accessed('document.downloaded', Reference::of('document', '7'), 'legal_hold', 'portal')->snapshot();

        self::assertSame('document.downloaded', $snapshot->code?->value);
        self::assertSame(Outcome::SUCCESS, $snapshot->outcome);
        self::assertSame('7', $snapshot->subject?->id);
    }

    /**
     * The purpose goes in the properties and the channel in the context.
     *
     * @return void
     */
    public function testAccessedPutsThePurposeInPropertiesAndTheChannelInContext(): void
    {
        $record = AuditLog::accessed('document.downloaded', Reference::of('document', '7'), 'legal_hold', 'portal')->record();

        self::assertSame(['purpose' => 'legal_hold'], $record->properties);
        self::assertSame('portal', $record->context['channel'] ?? null);
        self::assertArrayNotHasKey('channel', $record->properties);
        self::assertArrayNotHasKey('purpose', $record->context ?? []);
    }

    /**
     * `accessed()` writes nothing by itself.
     *
     * @return void
     */
    public function testAccessedWritesNothingUntilRecorded(): void
    {
        $pending = AuditLog::accessed('document.downloaded', Reference::of('document', '7'), 'legal_hold', 'portal');

        self::assertSame(0, $this->fake->count());

        $pending->record();

        self::assertSame(1, $this->fake->count());
    }

    /**
     * Rows of `[purpose, channel, which is refused]`: malformed codes of each.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideMalformedDisclosureCodes(): iterable
    {
        yield from [
            'empty purpose'      => ['', 'portal', 'A purpose'],
            'upper-case purpose' => ['Legal', 'portal', 'A purpose'],
            'spaced purpose'     => ['legal hold', 'portal', 'A purpose'],
            'empty channel'      => ['legal_hold', '', 'A channel'],
            'upper-case channel' => ['legal_hold', 'Portal', 'A channel'],
            'spaced channel'     => ['legal_hold', 'the portal', 'A channel'],
        ];
    }

    /**
     * Each must be a machine-readable code, and the message names which.
     *
     * @param  string  $purpose
     * @param  string  $channel
     * @param  string  $refused
     * @return void
     */
    #[DataProvider('provideMalformedDisclosureCodes')]
    public function testAccessedRefusesEachMalformedPurposeAndChannel(string $purpose, string $channel, string $refused): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($refused . ' must be a machine-readable code');

        AuditLog::accessed('document.downloaded', Reference::of('document', '7'), $purpose, $channel);
    }

    /**
     * The code, the purpose and the channel may each be a string-backed enum
     * case.
     *
     * @return void
     */
    public function testAccessedTakesEnums(): void
    {
        $record = AuditLog::accessed(DisclosureActivity::DOCUMENT_DOWNLOADED, Reference::of('document', '7'), StubActivity::APPROVED, StubActivity::APPROVED)->record();

        self::assertSame(DisclosureActivity::DOCUMENT_DOWNLOADED->value, $record->event);
        self::assertSame(['purpose' => StubActivity::APPROVED->value], $record->properties);
        self::assertSame(StubActivity::APPROVED->value, $record->context['channel'] ?? null);
    }

    /**
     * A registered definition that retains the purpose is accepted.
     *
     * @return void
     */
    public function testARegisteredDisclosureDefinitionThatRetainsThePurposeIsAccepted(): void
    {
        $recorder = self::recorder();

        $recorder->define(DisclosureActivity::class);

        $record = $recorder->accessed(DisclosureActivity::DOCUMENT_DOWNLOADED, Reference::of('document', '7'), 'legal_hold', 'portal')->record();

        self::assertSame('disclosure', $record->category);
    }

    /**
     * Rows of `[definition]`: a definition of the code handling the purpose any
     * way but keeping it.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Definitions\EventDefinition}>
     */
    public static function provideUnretainingDefinitions(): iterable
    {
        $code = 'report.exported';

        yield from [
            'unlisted fields dropped' => [EventDefinition::for($code)->unlisted(FieldHandling::DROP)],
            'dropped'                 => [EventDefinition::for($code)->unlisted(FieldHandling::RETAIN)->drop('purpose')],
            'redacted'                => [EventDefinition::for($code)->unlisted(FieldHandling::RETAIN)->redact('purpose')],
            'pseudonymised'           => [EventDefinition::for($code)->unlisted(FieldHandling::RETAIN)->pseudonymise('purpose')],
            'encrypted'               => [EventDefinition::for($code)->unlisted(FieldHandling::RETAIN)->encrypt('purpose', owner: KeyOwner::SUBJECT)],
        ];
    }

    /**
     * A disclosure's definition must keep why it was disclosed, however else it
     * would handle the purpose, and the builder writes nothing.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @return void
     */
    #[DataProvider('provideUnretainingDefinitions')]
    public function testARegisteredDisclosureDefinitionThatDoesNotRetainThePurposeIsRefused(EventDefinition $definition): void
    {
        $recorder = self::recorder();

        $recorder->define($definition);

        try {
            $recorder->accessed('report.exported', Reference::of('document', '7'), 'legal_hold', 'portal');

            self::fail('Expected the definition to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('The disclosure code `report.exported` must retain `purpose` in its definition.', $exception->getMessage());
        }

        self::assertSame(0, $this->fake->count());
    }

    /**
     * An enum whose definition says nothing of the purpose is refused too.
     *
     * @return void
     */
    public function testAnEnumDefinitionThatDoesNotRetainThePurposeIsRefused(): void
    {
        $recorder = self::recorder();

        $recorder->define(UnretainedDisclosureActivity::class);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The disclosure code `report.exported` must retain `purpose` in its definition.');

        $recorder->accessed(UnretainedDisclosureActivity::REPORT_EXPORTED, Reference::of('document', '7'), 'legal_hold', 'portal');
    }

    /**
     * An unregistered code retains every field, so it is accepted.
     *
     * @return void
     */
    public function testAnUnregisteredDisclosureCodeIsAccepted(): void
    {
        $record = AuditLog::accessed('report.exported', Reference::of('document', '7'), 'legal_hold', 'portal')->record();

        self::assertSame(['purpose' => 'legal_hold'], $record->properties);
    }

    /**
     * Both an enum of definitions and a single definition are registered.
     *
     * @return void
     */
    public function testDefineRegistersAnEnumAndASingleDefinition(): void
    {
        $recorder = self::recorder();

        $recorder->define(InvoiceActivity::class);
        $recorder->define(EventDefinition::for('user.suspended')->category('accounts')->version(3));

        self::assertSame('finance', $recorder->record(InvoiceActivity::REFUND_FAILED)->category);

        $record = $recorder->record('user.suspended');

        self::assertSame('accounts', $record->category);
        self::assertSame(3, $record->eventVersion);
    }

    /**
     * The application has booted by the time a test runs, so `define()` is
     * refused.
     *
     * @return void
     */
    public function testDefineIsRefusedAfterBoot(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Event definitions are registered while the application boots, and it has already booted.');

        AuditLog::define(InvoiceActivity::class);
    }

    /**
     * The application has booted by the time a test runs, so `contribute()` is
     * refused.
     *
     * @return void
     */
    public function testContributeIsRefusedAfterBoot(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Contributors are registered while the application boots, and it has already booted.');

        AuditLog::contribute(TenantContributor::class);
    }

    /**
     * An identical definition registered again changes nothing.
     *
     * @return void
     */
    public function testAnIdenticalDefinitionRepeatedIsIdempotent(): void
    {
        $recorder = self::recorder();

        $recorder->define(InvoiceActivity::class);
        $recorder->define(InvoiceActivity::class);
        $recorder->define(InvoiceActivity::APPROVED->definition());

        self::assertSame(2, $recorder->record(InvoiceActivity::APPROVED)->eventVersion);
    }

    /**
     * A different definition of a registered code is refused, whichever came
     * first.
     *
     * @return void
     */
    public function testAConflictingDefinitionThrowsInEitherOrder(): void
    {
        $one = EventDefinition::for(self::CODE)->version(1);
        $two = EventDefinition::for(self::CODE)->version(2);

        foreach ([[$one, $two], [$two, $one]] as [$first, $second]) {

            $recorder = self::recorder();

            $recorder->define($first);

            try {
                $recorder->define($second);

                self::fail('Expected the definition to be refused.');
            } catch (\LogicException $exception) {
                self::assertSame('The event code `invoice.approved` is already defined differently; a code has one definition.', $exception->getMessage());
            }
        }
    }

    /**
     * What does not implement the contract cannot be registered.
     *
     * @return void
     */
    public function testContributingAClassThatIsNotAContributorIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`stdClass` is not a class implementing `ContextContributor`.');

        self::recorder()->contribute(\stdClass::class);
    }

    /**
     * Two properties, of these types and no other, so a worker can retain
     * nothing of a request through the recorder: the event mappers and the
     * model watcher, which holds the dispatcher, are resolved for each
     * registration, never held.
     *
     * @return void
     */
    public function testHoldsOnlyRegistrationData(): void
    {
        $properties = [];

        foreach ((new \ReflectionClass(Recorder::class))->getProperties() as $property) {
            $properties[$property->getName()] = (string) $property->getType();
        }

        self::assertSame(['catalogue' => EventCatalogue::class, 'contributors' => ContributorRegistry::class], $properties);
    }

    /**
     * The store is resolved for every capture, so one bound after the recorder
     * was resolved is the one used.
     *
     * @return void
     */
    public function testAFakeBoundAfterTheRecorderIsResolvedIsUsed(): void
    {
        $recorder = app(Recorder::class);
        $late     = AuditLog::fake();

        $recorder->record(self::CODE);

        self::assertSame(0, $this->fake->count());
        self::assertSame(1, $late->count());
    }

    /**
     * Minimising takes a snapshot of its own after the contributors ran: a
     * secret one filled into the context is redacted, and a field encrypted
     * under the actor reaches the encrypter under the actor one filled, though
     * the recorder's first snapshot held neither.
     *
     * @return void
     */
    public function testMinimisingSeesWhatTheContributorsFilled(): void
    {
        $encrypter = self::bindEncrypter(new RecordingFieldEncrypter);
        $recorder  = self::recorder();

        $recorder->define(EventDefinition::for(self::CODE)->encrypt('card', KeyOwner::ACTOR));
        $recorder->contribute(SecretFillingContributor::class);

        $record = $recorder->event(self::CODE)->withProperties(['card' => '4242'])->record();

        self::assertSame(['api_key' => Redactor::MARKER, 'plan' => 'pro'], array_intersect_key($record->context ?? [], ['api_key' => true, 'plan' => true]));
        self::assertSame(SecretFillingContributor::ACTOR_TYPE, $record->actorType);
        self::assertSame(['card' => ['v' => 1, 'k' => 'key_' . SecretFillingContributor::ACTOR_ID, 'c' => base64_encode('"4242"')]], $record->properties);
        self::assertCount(1, $encrypter->calls());
        self::assertSame(SecretFillingContributor::ACTOR_ID, $encrypter->calls()[0][0]->id);
        self::assertSame($record->id, $encrypter->contexts()[0]->entryId);
        self::assertStringNotContainsString(SecretFillingContributor::SECRET, (string) json_encode($record->toArray()));
    }

    /**
     * A registered code stores what its definition retains and drops the rest,
     * counting the removal.
     *
     * @return void
     */
    public function testARegisteredCodeDropsItsUnlistedFields(): void
    {
        $recorder = self::recorder();

        $recorder->define(EventDefinition::for(self::CODE)->retain('amount'));

        $record = $recorder->event(self::CODE)->withProperties(['amount' => '1200.00', 'customer' => 'Alice'])->record();

        self::assertSame(['amount' => '1200.00', '_audit' => ['omitted' => ['count' => 1, 'paths' => ['*']]]], $record->properties);
        self::assertSame([$record], $this->fake->recorded());
    }

    /**
     * A code with no definition keeps every field that is not secret-shaped,
     * and the marker replaces the value of one that is.
     *
     * @return void
     */
    public function testAnUnregisteredCodeRetainsItsFields(): void
    {
        $record = AuditLog::event(self::CODE)->withProperties(['amount' => '1200.00', 'password' => 's3cr3t'])->record();

        self::assertSame(['amount' => '1200.00', 'password' => Redactor::MARKER], $record->properties);
    }

    /**
     * A registered definition's rules apply along with its version and
     * category, from the one definition the capture found.
     *
     * @return void
     */
    public function testARegisteredDefinitionsRulesApplyWithItsVersion(): void
    {
        $recorder = self::recorder();

        $recorder->define(EventDefinition::for(self::CODE)->version(3)->category('finance')->redact('amount'));

        $record = $recorder->event(self::CODE)->withProperties(['amount' => '1200.00'])->record();

        self::assertSame(3, $record->eventVersion);
        self::assertSame('finance', $record->category);
        self::assertSame(['amount' => Redactor::MARKER], $record->properties);
    }

    /**
     * A malformed setting fails the write before anything reaches the store,
     * through either way of recording.
     *
     * @return void
     */
    public function testAMinimiserFailureFailsTheWriteAndStoresNothing(): void
    {
        self::config()->set('audit-log.redaction.ip', 'partial');

        foreach ([static fn (): AuditRecord => AuditLog::record(self::CODE), static fn (): AuditRecord => AuditLog::event(self::CODE)->record()] as $record) {
            try {
                $record();

                self::fail('Expected the setting to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('`audit-log.redaction.ip` must be `full`, `truncate`, `hash`, `drop` or `encrypt`.', $exception->getMessage());
            }
        }

        self::assertSame(0, $this->fake->count());
    }

    /**
     * A minimiser's failure comes before the builder is used up, so the same
     * builder records once the setting is put right.
     *
     * @return void
     */
    public function testAMinimiserFailureLeavesTheBuilderUsable(): void
    {
        self::config()->set('audit-log.redaction.max_bytes', 1);

        $pending = AuditLog::event(self::CODE)->withProperties(['amount' => '1200.00']);

        try {
            $pending->record();

            self::fail('Expected the setting to be refused.');
        } catch (\InvalidArgumentException) {
            self::assertFalse($pending->isConsumed());
        }

        self::config()->set('audit-log.redaction.max_bytes', 16384);

        $record = $pending->record();

        self::assertTrue($pending->isConsumed());
        self::assertSame(['amount' => '1200.00'], $record->properties);
        self::assertSame([$record], $this->fake->recorded());
    }

    /**
     * A failure comes from the capture that met it, and the next capture is
     * judged afresh: the minimiser holds nothing between them.
     *
     * @return void
     */
    public function testEachCaptureBuildsItsOwnMinimiser(): void
    {
        self::assertNotSame(app(RecordMinimiser::class), app(RecordMinimiser::class));

        $encrypter = self::bindEncrypter(new ThrowingFieldEncrypter);

        AuditLog::event(self::CODE)->withNote('First.', Reference::of('user', '1'))->record();
        AuditLog::event(self::CODE)->withNote('Second.', Reference::of('user', '1'))->record();

        self::assertSame(2, $encrypter->calls());
    }

    /**
     * An encrypter bound after the application booted is the one a capture
     * uses, so the package never holds on to its default.
     *
     * @return void
     */
    public function testAFieldEncrypterBoundAfterBootIsUsed(): void
    {
        $recorder = app(Recorder::class);
        $late     = self::bindEncrypter(new RecordingFieldEncrypter);

        $record = $recorder->event(self::CODE)->withNote('Erasable.', Reference::of('user', '1'))->record();

        self::assertSame(['_audit' => ['note' => ['v' => 1, 'k' => 'key_1', 'c' => base64_encode('"Erasable."')]]], $record->properties);
        self::assertCount(1, $late->calls());
    }

    /**
     * An encrypter that throws does not fail the write: the field is dropped
     * and diagnosed, the record is stored, and the failure is reported without
     * the exception the encrypter threw.
     *
     * @return void
     */
    public function testAThrowingEncrypterDoesNotFailTheWrite(): void
    {
        self::bindEncrypter(new ThrowingFieldEncrypter);

        $handler = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $handler);

        $recorder = self::recorder();

        $recorder->define(EventDefinition::for(self::CODE)->encrypt('card', KeyOwner::SUBJECT));

        $record = $recorder->event(self::CODE)->on(Reference::of('invoice', '42'))->withProperties(['card' => '4242'])->record();

        self::assertSame(['_audit' => ['omitted' => ['count' => 1, 'paths' => ['card']]]], $record->properties);
        self::assertSame([$record], $this->fake->recorded());
        self::assertCount(1, $handler->reports());
        self::assertInstanceOf(FieldEncryptionFailedException::class, $handler->reports()[0]);
        self::assertNull($handler->reports()[0]->getPrevious());
    }

    /**
     * An identifier reaches the record as its keyed hash, under the configured
     * key, and is never stored as given.
     *
     * @return void
     */
    public function testWithIdentifierReachesTheRecordHashed(): void
    {
        self::config()->set('audit-log.redaction.key', '0123456789abcdef0123456789abcdef');

        $record = AuditLog::event(self::CODE)->withIdentifier('Alice@Example.COM')->failed('invalid_credentials')->record();

        self::assertSame(['_audit' => ['identifier_hash' => '13f5820b5aa0c097:680a1e05e07bcd260a8f8eda495c167100f4413f08ac4a5d980061e30cd51abf']], $record->properties);
        self::assertStringNotContainsString('example.com', strtolower((string) json_encode($record->toArray())));
    }

    /**
     * The configured IP mode applies to the ambient client's address.
     *
     * @return void
     */
    public function testTheIpModeAppliesToTheFilledAddress(): void
    {
        self::config()->set('audit-log.redaction.ip', 'truncate');

        $pending = AuditLog::event(self::CODE);

        $pending->fillClient('203.0.113.7', null);

        self::assertSame('203.0.113.0', $pending->record()->ip);
    }

    /**
     * `map()` registers the mapper with the event mappers the container binds,
     * which every capture reads.
     *
     * @return void
     */
    public function testMapRegistersTheMapping(): void
    {
        $mappers = $this->bindFreshMappers();

        self::recorder()->map(PortalSignedIn::class, PortalMapper::class, [RenewedPortalSession::class]);

        self::assertTrue($mappers->hasMappings());
        self::assertSame(PortalMapper::class, $mappers->mapperFor(PortalSignedIn::class));
        self::assertNull($mappers->mapperFor(RenewedPortalSession::class));
    }

    /**
     * The first mapping adds the one listener that routes every event to its
     * mapping, and no later one adds another, an identical mapping included.
     *
     * @return void
     */
    public function testTheFirstMapRegistersTheBridgeOnce(): void
    {
        $this->bindFreshMappers();

        $recorder = self::recorder();

        self::assertSame(0, self::bridges(), 'Before any mapping.');

        $recorder->map(PortalSignedIn::class, PortalMapper::class);

        self::assertSame(1, self::bridges(), 'After the first mapping.');

        $recorder->map(PortalSignedIn::class, PortalMapper::class);
        $recorder->map(AccountEvent::class, PortalMapper::class);

        self::assertSame(1, self::bridges(), 'After later mappings.');
    }

    /**
     * A first mapping that is refused maps nothing, so it adds no listener, and
     * the next one that is accepted adds it.
     *
     * @return void
     */
    public function testARefusedFirstMapRegistersNoBridge(): void
    {
        $this->bindFreshMappers();

        $recorder = self::recorder();

        try {
            $recorder->map(PortalSignedIn::class, NotAMapper::class);

            self::fail('Expected the mapper to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(sprintf('`%s` is not a class implementing `EventMapper`.', NotAMapper::class), $exception->getMessage());
        }

        self::assertSame(0, self::bridges());

        $recorder->map(PortalSignedIn::class, PortalMapper::class);

        self::assertSame(1, self::bridges());
    }

    /**
     * The application has booted by the time a test runs, so `map()` is
     * refused, and nothing starts listening.
     *
     * @return void
     */
    public function testMapAfterBootIsRefused(): void
    {
        try {
            AuditLog::recorder()->map(PortalSignedIn::class, PortalMapper::class);

            self::fail('Expected the mapping to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('Event mappers are registered while the application boots, and it has already booted.', $exception->getMessage());
        }

        self::assertFalse(app(MapperRegistry::class)->hasMappings());
        self::assertSame(0, self::bridges());
    }

    /**
     * `capture()` writes the event through its mapper and returns the record
     * the store holds.
     *
     * @return void
     */
    public function testCaptureReturnsTheRecord(): void
    {
        $this->bindFreshMappers();

        $recorder = self::recorder();

        $recorder->map(PortalSignedIn::class, PortalMapper::class);

        $record = $recorder->capture(new PortalSignedIn('7'));

        self::assertInstanceOf(AuditRecord::class, $record);
        self::assertSame(PortalMapper::CODE, $record->event);
        self::assertSame(PortalMapper::SUBJECT_TYPE, $record->subjectType);
        self::assertSame('7', $record->subjectId);
        self::assertSame([$record], $this->fake->recorded());
    }

    /**
     * A captured record does not wait for an open transaction: it is written at
     * once, unlike an explicit record.
     *
     * @return void
     */
    public function testACapturedRecordIsWrittenAtOnce(): void
    {
        $this->bindFreshMappers();

        $recorder = self::recorder();

        $recorder->map(PortalSignedIn::class, PortalMapper::class);

        DB::connection(self::CONNECTION)->transaction(function () use ($recorder): void {
            $recorder->capture(new PortalSignedIn);

            self::assertSame(1, $this->fake->count());
        });

        self::assertSame(1, $this->fake->count());
    }

    /**
     * The same event object is captured once, however often it is offered.
     *
     * @return void
     */
    public function testCaptureWritesAnEventObjectOnce(): void
    {
        $this->bindFreshMappers();

        $recorder = self::recorder();
        $event    = new PortalSignedIn;

        $recorder->map(PortalSignedIn::class, PortalMapper::class);

        self::assertInstanceOf(AuditRecord::class, $recorder->capture($event));
        self::assertNull($recorder->capture($event));
        self::assertSame(1, $this->fake->count());
    }

    /**
     * An event no mapping applies to is not captured, and nothing is written.
     *
     * @return void
     */
    public function testCaptureOfAnUnmappedEventIsNull(): void
    {
        self::assertNull(AuditLog::capture(new PortalSignedIn));
        self::assertNull(AuditLog::capture(new \stdClass));
        self::assertSame(0, $this->fake->count());
    }

    /**
     * `watch()` watches the model with the watcher the container binds, whose
     * definitions go into its catalogue and whose listeners go on the
     * dispatcher.
     *
     * @return void
     */
    public function testWatchRegistersTheModel(): void
    {
        $catalogue = new EventCatalogue;
        $watcher   = new ModelWatcher($catalogue, app(Dispatcher::class));

        $this->app?->instance(ModelWatcher::class, $watcher);

        self::recorder()->watch(PlainLine::class, as: 'line', fields: ['description', 'quantity' => FieldHandling::REDACT]);

        $watch = $watcher->watchFor(PlainLine::class);

        self::assertNotNull($watch);
        self::assertSame('line', $watch->as);
        self::assertSame(['description' => FieldHandling::RETAIN, 'quantity' => FieldHandling::REDACT], $watch->fields);
        self::assertTrue($catalogue->isRegistered(EventCode::of('line.created')));
        self::assertTrue(app(Dispatcher::class)->hasListeners('eloquent.created: ' . PlainLine::class));
    }

    /**
     * The application has booted by the time a test runs, so `watch()` is
     * refused, and the model is not watched.
     *
     * @return void
     */
    public function testWatchAfterBootIsRefused(): void
    {
        try {
            AuditLog::recorder()->watch(PlainLine::class, as: 'line', fields: ['description']);

            self::fail('Expected the watch to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('Models are watched while the application boots, and it has already booted.', $exception->getMessage());
        }

        self::assertNull(app(ModelWatcher::class)->watchFor(PlainLine::class));
        self::assertFalse(app(Dispatcher::class)->hasListeners('eloquent.created: ' . PlainLine::class));
    }

    /**
     * `covering()` gives the builder the manifest of its subjects, each once in
     * canonical order, still to be recorded; recording it seals the manifest as
     * the record's attachment.
     *
     * @return void
     */
    public function testCoveringGivesABuilderCarryingTheManifest(): void
    {
        $pending = AuditLog::event('invoice.voided')->covering(self::goldenSubjects());

        $manifest = $pending->snapshot()->manifest;

        self::assertFalse($pending->isConsumed());
        self::assertNotNull($manifest);
        self::assertSame(3, $manifest->count);
        self::assertSame(self::GOLDEN_DIGEST, $manifest->digest);
        self::assertSame(0, $this->fake->count());

        $record = $pending->record();

        self::assertSame('invoice.voided', $record->event);
        self::assertNotNull($record->attachment);
        self::assertSame($manifest->id, $record->attachment->id);
        self::assertSame(['artifact_id' => $manifest->id, 'kind' => 'bulk', 'digest' => self::GOLDEN_DIGEST, 'count' => 3], $record->properties['_audit']['manifest'] ?? null);
        self::assertSame([$record], $this->fake->recorded());
    }

    /**
     * A model given as a subject is the reference it is stored as.
     *
     * @return void
     */
    public function testCoveringTakesModels(): void
    {
        $document = (new StubDocument)->forceFill(['id' => 'document-1']);

        $manifest = AuditLog::event('document.archived')->covering([$document, Reference::to($document)])->snapshot()->manifest;

        self::assertNotNull($manifest);
        self::assertSame(1, $manifest->count);
        self::assertSame(Manifest::encode([[Reference::to($document)->type, 'document-1']]), $manifest->canonical);
    }

    /**
     * A bound store that keeps no attachment refuses a bulk operation up front,
     * naming the store, before a single subject is read.
     *
     * @return void
     */
    public function testCoveringIsRefusedByAStoreKeepingNoAttachments(): void
    {
        $reads    = new \ArrayObject;
        $subjects = (static function () use ($reads): \Generator {
            $reads->append(true);

            yield Reference::of('invoice', '1');
        })();

        app()->instance(AuditStore::class, new PlainStore);

        try {
            AuditLog::recorder()->event('invoice.voided')->covering($subjects);

            self::fail('Expected the bulk operation to be refused.');
        } catch (\LogicException $exception) {
            $message = 'The store %s does not keep attachments, so a bulk operation cannot be stored there. Bind one that does, such as the database store.';

            self::assertSame(sprintf($message, PlainStore::class), $exception->getMessage());
        }

        self::assertCount(0, $reads);
    }

    /**
     * The bounds are read from the configuration on every call, so a changed
     * setting applies to the next one, and a malformed one is refused by its
     * key.
     *
     * @return void
     */
    public function testCoveringReadsItsLimitsOnEachCall(): void
    {
        $subjects = [Reference::of('invoice', '1'), Reference::of('invoice', '2')];

        self::config()->set('audit-log.capture.bulk.max_members', 1);

        try {
            AuditLog::recorder()->event('invoice.voided')->covering($subjects);

            self::fail('Expected the bulk operation to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A bulk operation names at most 1 subjects, the `audit-log.capture.bulk.max_members` setting.', $exception->getMessage());
        }

        self::config()->set('audit-log.capture.bulk.max_members', 2);

        self::assertSame(2, AuditLog::event('invoice.voided')->covering($subjects)->snapshot()->manifest?->count);

        self::config()->set('audit-log.capture.bulk.max_bytes', 'many');

        try {
            AuditLog::recorder()->event('invoice.voided')->covering($subjects);

            self::fail('Expected the malformed setting to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('`audit-log.capture.bulk.max_bytes` must be an integer from 65536 to 8388608.', $exception->getMessage());
        }
    }

    /**
     * A bulk operation with no subject is refused, never recorded empty.
     *
     * @return void
     */
    public function testCoveringRefusesNoSubjects(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A bulk operation names at least one subject.');

        AuditLog::event('invoice.voided')->covering([]);
    }

    /**
     * A bulk operation's code is held to the rules of every code.
     *
     * @return void
     */
    public function testCoveringRefusesAnInvalidCode(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        AuditLog::event('Invoice Voided')->covering([Reference::of('invoice', '1')]);
    }

    /**
     * A bulk record with no timing waits for the transaction to commit, as any
     * explicit record does.
     *
     * @return void
     */
    public function testCoveringIsWrittenAfterCommitByDefault(): void
    {
        DB::connection(self::CONNECTION)->transaction(function (): void {
            AuditLog::event('invoice.voided')->covering(self::goldenSubjects())->record();

            self::assertSame(0, $this->fake->count());
        });

        self::assertSame(1, $this->fake->count());
        self::assertNotNull($this->fake->recorded()[0]->attachment);
    }

    /**
     * An explicit record runs the pipeline of the recorder that built it: the
     * definitions and the contributors of a recorder of a test's own apply to
     * its records, and not to the application recorder's.
     *
     * @return void
     */
    public function testTheExplicitPipelineIsUnchanged(): void
    {
        $catalogue = new EventCatalogue;
        $recorder  = self::recorder($catalogue);

        $recorder->define(EventDefinition::for(self::CODE)->category('finance')->version(7));
        $recorder->contribute(TenantContributor::class);

        $own         = $recorder->event(self::CODE)->record();
        $application = AuditLog::event(self::CODE)->record();

        self::assertSame([7, 'finance', TenantContributor::ID], [$own->eventVersion, $own->category, $own->tenantId]);
        self::assertSame([1, 'general', null], [$application->eventVersion, $application->category, $application->tenantId]);
    }

    /**
     * The properties and a captured event hold the raw payload, so each is
     * marked sensitive where the recorder takes it.
     *
     * @return void
     */
    public function testTheRecorderPropertiesParameterIsSensitive(): void
    {
        $parameters = [
            new \ReflectionParameter([Recorder::class, 'record'], 'properties'),
            new \ReflectionParameter([Recorder::class, 'write'], 'pending'),
            new \ReflectionParameter([Recorder::class, 'capture'], 'event'),
        ];

        foreach ($parameters as $parameter) {
            self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class), sprintf('`$%s` is not marked sensitive.', $parameter->getName()));
        }
    }

    /**
     * `trail()` resolves a new trail from the current container on each call,
     * so a trail bound there is the one it gives, and two calls never share
     * one.
     *
     * @return void
     */
    public function testTrailResolvesAFreshTrailEachTime(): void
    {
        $recorder = app(Recorder::class);
        $first    = $recorder->trail();

        self::assertNotSame($first, $recorder->trail());

        $this->app?->bind(AuditTrail::class, static fn (): AuditTrail => $first);

        self::assertSame($first, $recorder->trail());
    }

    /**
     * `lifecycle()` resolves a new way into the lifecycle from the current
     * container on each call, so one bound there is the one it gives, and two
     * calls never share one.
     *
     * @return void
     */
    public function testLifecycleResolvesAFreshOneEachTime(): void
    {
        $recorder = app(Recorder::class);
        $first    = $recorder->lifecycle();

        self::assertNotSame($first, $recorder->lifecycle());

        $this->app?->bind(AuditLifecycle::class, static fn (): AuditLifecycle => $first);

        self::assertSame($first, $recorder->lifecycle());
    }

    /**
     * The trail `trail()` gives names no viewer: a terminal call on it is
     * refused before anything is queried or recorded.
     *
     * @return void
     */
    public function testTrailHasNoViewer(): void
    {
        $queries = [];

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        try {
            AuditLog::recorder()->trail()->count();

            self::fail('Expected the read to be refused.');
        } catch (\LogicException $refusal) {
            self::assertSame('A read of the audit trail names its viewer; call visibleTo() first.', $refusal->getMessage());
        }

        self::assertSame([], $queries);
        self::assertSame([], $this->fake->recorded());
    }

    /**
     * Bind the encrypter a capture will use, and return it.
     *
     * @template TEncrypter of \SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter
     *
     * @param  TEncrypter  $encrypter
     * @return TEncrypter
     */
    private static function bindEncrypter(FieldEncrypter $encrypter): FieldEncrypter
    {
        app()->instance(FieldEncrypter::class, $encrypter);

        return $encrypter;
    }

    /**
     * The application's configuration.
     *
     * @return \Illuminate\Config\Repository
     */
    private static function config(): ConfigRepository
    {
        return app(ConfigRepository::class);
    }

    /**
     * A recorder of a test's own, whose registration is not frozen, with the
     * catalogue given or a fresh one.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Definitions\EventCatalogue  $catalogue
     * @return \SineMacula\Laravel\AuditLog\Recorder
     */
    private static function recorder(?EventCatalogue $catalogue = null): Recorder
    {
        return new Recorder($catalogue ?? new EventCatalogue, new ContributorRegistry);
    }

    /**
     * The golden subjects: three invoices, one of them twice, out of order.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Records\Reference>
     */
    private static function goldenSubjects(): array
    {
        return array_map(static fn (string $id): Reference => Reference::of('App\Models\Invoice', $id), ['2', '1', '10', '1']);
    }

    /**
     * How many times the listener that routes mapped events is on the
     * application's dispatcher for every event.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return int
     */
    private static function bridges(): int
    {
        $dispatcher = app(Dispatcher::class);

        self::assertInstanceOf(EventDispatcher::class, $dispatcher);

        $wildcards = (new \ReflectionProperty(EventDispatcher::class, 'wildcards'))->getValue($dispatcher);

        self::assertIsArray($wildcards);

        $listeners = $wildcards['*'] ?? [];

        self::assertIsArray($listeners);

        return count(array_keys($listeners, CaptureMappedEvent::class, true));
    }

    /**
     * Bind event mappers that are not frozen, as the application's are while it
     * boots, and return them.
     *
     * @return \SineMacula\Laravel\AuditLog\Capture\MapperRegistry
     */
    private function bindFreshMappers(): MapperRegistry
    {
        $mappers = new MapperRegistry;

        $this->app?->instance(MapperRegistry::class, $mappers);

        return $mappers;
    }

    /**
     * The class of a contributor filling a different tenant from
     * `TenantContributor`'s.
     *
     * @return class-string<\SineMacula\Laravel\AuditLog\Contracts\ContextContributor>
     */
    private static function otherTenantContributor(): string
    {
        $contributor = new class implements ContextContributor {
            /**
             * Fill the tenant.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\Contribution  $contribution
             * @return void
             *
             * @throws \InvalidArgumentException
             * @throws \LogicException
             */
            #[\Override]
            public function contribute(Contribution $contribution): void
            {
                $contribution->fillTenant(Reference::of('organisation', 'organisation-2'));
            }
        };

        return $contributor::class;
    }

    /**
     * Stop the clock at the instant.
     *
     * @param  string  $at
     * @return void
     */
    private function freezeClock(string $at): void
    {
        $this->app?->instance(Clock::class, FrozenClock::at($at));
    }
}
