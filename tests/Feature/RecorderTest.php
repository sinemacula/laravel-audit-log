<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Ramsey\Uuid\Uuid;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Contributors\ActorContributor;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Contributors\OriginContributor;
use SineMacula\Laravel\AuditLog\Contributors\RequestContributor;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Fixtures\Contributors\ActorFillingContributor;
use Tests\Fixtures\Contributors\TenantContributor;
use Tests\Fixtures\Definitions\Enums\DisclosureActivity;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;
use Tests\Fixtures\Definitions\Enums\UnretainedDisclosureActivity;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;
use Tests\Unit\Stubs\Enums\StubActivity;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * Feature tests for the recorder: what each of its calls does, and the capture
 * pipeline a recorded activity runs: the definition, the timing's checks, the
 * contributors in order, the clock and source, and delivery. Its collaborators
 * come from the current container on every capture, and it holds nothing but
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
     * A failed write reaches the caller.
     *
     * @return void
     */
    public function testAFailedWritePropagates(): void
    {
        $failure = new \RuntimeException('The store is down.');

        FakeAuditStore::failing($failure);

        try {
            AuditLog::record(self::CODE);

            self::fail('Expected the failure to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }
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
     * nothing of a request through the recorder.
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
     * A recorder of a test's own, whose registration is not frozen.
     *
     * @return \SineMacula\Laravel\AuditLog\Recorder
     */
    private static function recorder(): Recorder
    {
        return new Recorder(new EventCatalogue, new ContributorRegistry);
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
