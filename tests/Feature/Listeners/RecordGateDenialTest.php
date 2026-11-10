<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Auth\Access\Events\GateEvaluated;
use Illuminate\Auth\Access\Gate as AccessGate;
use Illuminate\Auth\Access\Response;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher as DispatcherContract;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Capture\CaptureFailedException;
use SineMacula\Laravel\AuditLog\Capture\CaptureSettings;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Capture\GateArguments;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\RecordGateDenial;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;
use Tests\Unit\Stubs\StubDocument;

/**
 * Feature tests for the capture of the Gate's denials: off unless turned on; a
 * denial as the Gate itself reads one; the user the Gate checked as actor, or
 * explicitly no one, and never a guard; the ability cleaned and capped and the
 * arguments as references, class names or the marker; a reason code kept only
 * when allowlisted, and a response's message never read; the abilities
 * selected; every evaluation recorded; and a malformed setting contained, read
 * only for a denial.
 *
 * The provider registers the listener for the Gate's evaluations; most tests
 * invoke it directly with an evaluation of their own, and the rest check
 * through the Gate itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordGateDenial::class)]
final class RecordGateDenialTest extends TestCase
{
    /** @var string The ability most tests check. */
    private const string ABILITY = 'update-invoice';

    /** @var string The type a user is referred to by. */
    private const string USER_TYPE = StubAuthUser::class;

    /** @var \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore The store records reach. */
    private FakeAuditStore $fake;

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> Every `AuditCaptureFailed` heard. */
    private array $failures = [];

    /**
     * Fake the store, bind the reporter, turn Gate capture on, and hear each
     * capture failure.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fake     = AuditLog::fake();
        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        self::config()->set('audit-log.capture.gate.enabled', true);

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $failure): void {
            $this->failures[] = $failure;
        });
    }

    /**
     * With Gate capture off, as it is unless turned on, a denial records
     * nothing, says nothing, and leaves its event for another source.
     *
     * @return void
     */
    public function testCaptureOffRecordsNothing(): void
    {
        self::config()->set('audit-log.capture.gate', []);

        $event = self::denial(false);

        self::listener()->handle($event);

        self::config()->set('audit-log.capture.gate.enabled', false);

        self::listener()->handle(self::denial(false));

        self::assertSame(0, $this->fake->count());
        self::assertFalse(app(CapturedEvents::class)->isClaimed($event));
        $this->assertNothingFailed();
    }

    /**
     * A check the Gate allowed records nothing.
     *
     * @return void
     */
    public function testAnAllowedCheckRecordsNothing(): void
    {
        self::listener()->handle(self::denial(true));

        self::assertSame(0, $this->fake->count());
        $this->assertNothingFailed();
    }

    /**
     * A `false` result is a denial: recorded under the Gate code, denied, with
     * no reason, in the security category.
     *
     * @return void
     */
    public function testFalseIsADenial(): void
    {
        self::listener()->handle(self::denial(false));

        $record = $this->onlyRecord();

        self::assertSame(CapturedActivity::GATE_DENIED->value, $record->event);
        self::assertSame(['denied', null], [$record->outcome, $record->reason]);
        self::assertSame(['security', 1], [$record->category, $record->eventVersion]);
        self::assertSame(['ability' => self::ABILITY, 'arguments' => [], 'argument_count' => 0], $record->properties);
    }

    /**
     * A `null` result, which the Gate reads as a denial, is one.
     *
     * @return void
     */
    public function testNullIsADenial(): void
    {
        self::listener()->handle(self::denial(null));

        self::assertSame('denied', $this->onlyRecord()->outcome);
    }

    /**
     * Rows of `[result]`: falsy results other than `false` and `null`.
     *
     * @return iterable<string, array{0: array<int, int>|int|string}>
     */
    public static function provideFalsyResults(): iterable
    {
        yield from [
            'zero'         => [0],
            'empty string' => [''],
            'string zero'  => ['0'],
            'empty array'  => [[]],
        ];
    }

    /**
     * Any other falsy result is a denial too, as the Gate reads it.
     *
     * @param  array<int, int>|int|string  $result
     * @return void
     *
     * @throws \Illuminate\Auth\Access\AuthorizationException
     */
    #[DataProvider('provideFalsyResults')]
    public function testAnyOtherFalsyResultIsADenial(array|int|string $result): void
    {
        self::listener()->handle(self::evaluation($result));

        self::assertSame('denied', $this->onlyRecord()->outcome);
    }

    /**
     * A denied response is a denial.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\Access\AuthorizationException
     */
    public function testADeniedResponseIsADenial(): void
    {
        self::listener()->handle(self::evaluation(Response::deny()));
        self::listener()->handle(self::evaluation(Response::denyAsNotFound()));

        self::assertSame(['denied', 'denied'], array_map(static fn (AuditRecord $record): string => $record->outcome, $this->fake->recorded()));
    }

    /**
     * An allowed response, and any truthy result, record nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\Access\AuthorizationException
     */
    public function testAnAllowedResponseRecordsNothing(): void
    {
        self::listener()->handle(self::evaluation(Response::allow('Fine.', 'allowed_code')));
        self::listener()->handle(self::evaluation('yes'));
        self::listener()->handle(self::evaluation(new \stdClass));

        self::assertSame(0, $this->fake->count());
        $this->assertNothingFailed();
    }

    /**
     * The actor is the user the Gate checked, and the denial has no subject.
     *
     * @return void
     */
    public function testTheActorIsTheEventsUser(): void
    {
        Auth::guard('web')->setUser(self::user(99));

        self::listener()->handle(self::denial(false, self::user(7)));

        $record = $this->onlyRecord();

        self::assertSame([self::USER_TYPE, '7'], [$record->actorType, $record->actorId]);
        self::assertSame([null, null], [$record->subjectType, $record->subjectId]);
    }

    /**
     * A guest's denial has explicitly no actor, even while a guard holds a
     * user.
     *
     * @return void
     */
    public function testAGuestDenialHasNoActor(): void
    {
        Auth::guard('web')->setUser(self::user(99));

        self::listener()->handle(self::denial(false));
        self::listener()->handle(self::denial(false, new StubAuthUser));

        foreach ($this->fake->recorded() as $record) {
            self::assertSame([null, null], [$record->actorType, $record->actorId]);
        }

        self::assertSame(2, $this->fake->count());
    }

    /**
     * The Gate names no guard, so none is recorded, whatever guard holds a user
     * and whoever the actor is.
     *
     * @return void
     */
    public function testTheGuardStaysEmpty(): void
    {
        Auth::guard('web')->setUser(self::user(99));

        self::listener()->handle(self::denial(false, self::user(7)));
        self::listener()->handle(self::denial(false));

        self::assertSame([null, null], array_map(static fn (AuditRecord $record): ?string => $record->guard, $this->fake->recorded()));
    }

    /**
     * The ability is cleaned of controls and cut to 191 bytes without splitting
     * a character, while the abilities are selected on the ability exactly as
     * the Gate gave it, so excepting its cleaned form excepts nothing.
     *
     * @return void
     */
    public function testTheAbilityIsCleanedAndCapped(): void
    {
        $dirty = "update\ninvoice\u{202E}";
        $long  = str_repeat('a', 190) . 'é';

        self::config()->set('audit-log.capture.gate.except_abilities', [TextSanitizer::clean($dirty)]);

        self::listener()->handle(self::denial(false, null, [], $long));
        self::listener()->handle(self::denial(false, null, [], $dirty));

        [$capped, $cleaned] = $this->fake->recorded();

        self::assertSame(str_repeat('a', 190), $capped->properties['ability'] ?? null);
        self::assertSame(CaptureSettings::ABILITY_MAX_BYTES, strlen(TextSanitizer::clean(str_repeat('a', 300), CaptureSettings::ABILITY_MAX_BYTES)));
        self::assertSame('update invoice', $cleaned->properties['ability'] ?? null);
    }

    /**
     * The arguments are kept as model references, class names or the marker, at
     * most eight, with the count of every one.
     *
     * @return void
     */
    public function testTheArgumentsAreReferencesClassStringsOrTheMarker(): void
    {
        $document = (new StubDocument)->forceFill(['id' => 'doc-1', 'title' => 'Quarterly figures']);

        self::listener()->handle(self::denial(false, null, ['invoice' => $document, StubDocument::class, 'Quarterly figures', 42]));
        self::listener()->handle(self::denial(false, null, array_fill(0, 10, StubDocument::class)));

        [$mixed, $many] = $this->fake->recorded();

        self::assertSame([
            'ability'        => self::ABILITY,
            'arguments'      => [['type' => StubDocument::class, 'id' => 'doc-1'], StubDocument::class, GateArguments::MARKER, GateArguments::MARKER],
            'argument_count' => 4,
        ], $mixed->properties);
        self::assertSame(array_fill(0, 8, StubDocument::class), $many->properties['arguments'] ?? null);
        self::assertSame(10, $many->properties['argument_count'] ?? null);
        self::assertStringNotContainsString('Quarterly', (string) json_encode($mixed->toArray()));
    }

    /**
     * A denied response's code is the reason only when the reason codes list
     * it, as a string or as an integer whose string form is listed; any other
     * code, one that merely looks like a code included, gives no reason.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\Access\AuthorizationException
     */
    public function testAReasonCodeIsKeptOnlyWhenAllowlisted(): void
    {
        self::listener()->handle(self::evaluation(Response::deny('No.', 'insufficient_role')));

        self::config()->set('audit-log.capture.gate.reason_codes', ['insufficient_role', '403']);

        $codes = ['insufficient_role', 403, '403', 'tok_live_abc123', 404, 'Insufficient_Role', 4.03, ['insufficient_role'], null];

        foreach ($codes as $code) {
            self::listener()->handle(self::evaluation(Response::deny('No.', $code)));
        }

        self::assertSame(
            [null, 'insufficient_role', '403', '403', null, null, null, null, null, null],
            array_map(static fn (AuditRecord $record): ?string => $record->reason, $this->fake->recorded()),
        );
        $this->assertNothingFailed();
    }

    /**
     * A result that is not a response has no code, so no reason, whatever the
     * reason codes list.
     *
     * @return void
     */
    public function testOnlyAResponseGivesAReason(): void
    {
        self::config()->set('audit-log.capture.gate.reason_codes', ['insufficient_role']);

        self::listener()->handle(self::denial(false));
        self::listener()->handle(self::denial(null));

        self::assertSame([null, null], array_map(static fn (AuditRecord $record): ?string => $record->reason, $this->fake->recorded()));
    }

    /**
     * Neither the denied response's message nor its string form is ever read,
     * since it is free text.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\Access\AuthorizationException
     */
    public function testTheResponseMessageIsNeverRead(): void
    {
        self::config()->set('audit-log.capture.gate.reason_codes', ['insufficient_role']);

        $response = new class (false, 's3cr3t message', 'insufficient_role') extends Response {
            /**
             * Fail the test: the message is never read.
             *
             * @return never
             */
            #[\Override]
            public function message(): never
            {
                TestCase::fail('The response message was read.');
            }

            /**
             * Fail the test: the response is never cast to a string.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                TestCase::fail('The response was cast to a string.');
            }

            /**
             * Fail the test: the response is never turned into an array.
             *
             * @return never
             */
            #[\Override]
            public function toArray(): never
            {
                TestCase::fail('The response was turned into an array.');
            }
        };

        self::listener()->handle(self::evaluation($response));

        $record = $this->onlyRecord();

        self::assertSame('insufficient_role', $record->reason);
        self::assertStringNotContainsString('s3cr3t', (string) json_encode($record->toArray()));
    }

    /**
     * With only abilities listed, only their denials are recorded, compared
     * exactly as the Gate gave them.
     *
     * @return void
     */
    public function testOnlyAbilitiesSelects(): void
    {
        self::config()->set('audit-log.capture.gate.only_abilities', ['delete-invoice', self::ABILITY]);

        foreach (['delete-invoice', 'view-invoice', self::ABILITY, 'Update-Invoice', ' update-invoice'] as $ability) {
            self::listener()->handle(self::denial(false, null, [], $ability));
        }

        self::assertSame(['delete-invoice', self::ABILITY], array_map(static fn (AuditRecord $record): mixed => $record->properties['ability'] ?? null, $this->fake->recorded()));
        $this->assertNothingFailed();
    }

    /**
     * An excepted ability's denials are never recorded, even when only
     * abilities list it too.
     *
     * @return void
     */
    public function testExceptAbilitiesExcludes(): void
    {
        self::config()->set('audit-log.capture.gate.except_abilities', ['view-invoice']);

        self::listener()->handle(self::denial(false, null, [], 'view-invoice'));
        self::listener()->handle(self::denial(false, null, [], self::ABILITY));

        self::config()->set('audit-log.capture.gate.only_abilities', ['view-invoice']);

        self::listener()->handle(self::denial(false, null, [], 'view-invoice'));

        self::assertSame([self::ABILITY], array_map(static fn (AuditRecord $record): mixed => $record->properties['ability'] ?? null, $this->fake->recorded()));
    }

    /**
     * Every denial the Gate evaluates is recorded, so the same denial twice
     * gives two rows; one event object is still recorded once.
     *
     * @return void
     */
    public function testEveryEvaluationIsRecorded(): void
    {
        $event = self::denial(false, self::user(7));

        self::listener()->handle($event);
        self::listener()->handle($event);
        self::listener()->handle(self::denial(false, self::user(7)));

        self::assertSame(2, $this->fake->count());
    }

    /**
     * Through the Gate itself, every denial is recorded and the check returns
     * its result.
     *
     * @return void
     */
    public function testAGateCheckRecordsEachDenial(): void
    {
        Gate::define(self::ABILITY, static fn (StubAuthUser $user): Response => Response::deny('No.', 'insufficient_role'));

        self::config()->set('audit-log.capture.gate.reason_codes', ['insufficient_role']);

        $gate = Gate::forUser(self::user(7));

        self::assertFalse($gate->allows(self::ABILITY, [StubDocument::class]));
        self::assertTrue($gate->inspect(self::ABILITY, [StubDocument::class])->denied());

        self::assertSame(2, $this->fake->count());

        foreach ($this->fake->recorded() as $record) {
            self::assertSame([self::USER_TYPE, '7', 'insufficient_role'], [$record->actorType, $record->actorId, $record->reason]);
            self::assertSame([StubDocument::class], $record->properties['arguments'] ?? null);
        }
    }

    /**
     * A malformed setting is a contained failure, reported once and dispatched
     * once naming the event, the listener and the refusal, and the Gate's check
     * itself still returns its result.
     *
     * @return void
     */
    public function testAMalformedSettingIsAContainedFailure(): void
    {
        Gate::define(self::ABILITY, static fn (?StubAuthUser $user = null): Response => Response::deny('No.', 'insufficient_role'));

        $settings = [
            'enabled'          => ['yes', true],
            'only_abilities'   => [[], null],
            'except_abilities' => ['view-invoice', []],
            'reason_codes'     => [['Not A Code'], []],
        ];

        foreach ($settings as $setting => [$malformed, $wellFormed]) {
            self::config()->set('audit-log.capture.gate.' . $setting, $malformed);

            self::assertFalse(Gate::forUser(self::user(7))->allows(self::ABILITY), $setting);
            self::assertTrue(Gate::forUser(self::user(7))->inspect(self::ABILITY)->denied(), $setting);

            self::config()->set('audit-log.capture.gate.' . $setting, $wellFormed);
        }

        self::assertSame(0, $this->fake->count());
        self::assertSame(
            array_fill(0, 8, [GateEvaluated::class, RecordGateDenial::class, \InvalidArgumentException::class]),
            array_map(static fn (AuditCaptureFailed $failure): array => [$failure->eventClass, $failure->mapperClass, $failure->exceptionClass], $this->failures),
        );

        foreach ($this->reporter->reports() as $report) {
            self::assertInstanceOf(CaptureFailedException::class, $report);
        }

        self::assertCount(8, $this->reporter->reports());
    }

    /**
     * A check whose result is truthy and not a response is left alone before
     * any setting is read, so even malformed settings record nothing and say
     * nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\Access\AuthorizationException
     */
    public function testAnAllowedCheckReadsNoSetting(): void
    {
        self::config()->set('audit-log.capture.gate', ['enabled' => 'yes', 'only_abilities' => [], 'except_abilities' => 'x', 'reason_codes' => 'x']);

        self::listener()->handle(self::denial(true));
        self::listener()->handle(self::evaluation(new \stdClass));

        self::assertSame(0, $this->fake->count());
        $this->assertNothingFailed();
    }

    /**
     * With Gate capture off, a response is never asked whether it denies, so
     * one that throws when asked records nothing, says nothing, and the Gate's
     * check returns its result.
     *
     * @return void
     */
    public function testAResponseIsNeverAskedWithCaptureOff(): void
    {
        self::config()->set('audit-log.capture.gate.enabled', false);

        $response = self::unanswerableResponse();

        Gate::define(self::ABILITY, static fn (StubAuthUser $user): Response => $response);

        self::assertTrue(Gate::forUser(self::user(7))->allows(self::ABILITY));
        self::assertSame(0, $this->fake->count());
        $this->assertNothingFailed();
    }

    /**
     * With Gate capture on, a response that throws when asked whether it denies
     * is asked inside the capture, so its failure is contained: nothing is
     * recorded, one report and one `AuditCaptureFailed` name the event, the
     * listener and the failure's class, and the Gate's check returns its
     * result.
     *
     * @return void
     */
    public function testAResponseThatCannotSayIsContained(): void
    {
        $response = self::unanswerableResponse();

        Gate::define(self::ABILITY, static fn (StubAuthUser $user): Response => $response);

        self::assertTrue(Gate::forUser(self::user(7))->allows(self::ABILITY));
        self::assertSame(0, $this->fake->count());
        self::assertCount(1, $this->reporter->reports());
        self::assertInstanceOf(CaptureFailedException::class, $this->reporter->reports()[0]);
        self::assertSame([[GateEvaluated::class, RecordGateDenial::class, \RuntimeException::class]], array_map(
            static fn (AuditCaptureFailed $failure): array => [$failure->eventClass, $failure->mapperClass, $failure->exceptionClass],
            $this->failures,
        ));
    }

    /**
     * An ability that is not a string cannot be selected, so its denial is a
     * contained failure.
     *
     * @return void
     */
    public function testAnAbilityThatIsNotAStringIsContained(): void
    {
        self::listener()->handle(new GateEvaluated(null, 42, false, []));

        self::assertSame(0, $this->fake->count());
        self::assertSame([[GateEvaluated::class, RecordGateDenial::class, \TypeError::class]], array_map(
            static fn (AuditCaptureFailed $failure): array => [$failure->eventClass, $failure->mapperClass, $failure->exceptionClass],
            $this->failures,
        ));
    }

    /**
     * Bind the capture state as the provider does, a registry of the test's
     * own, and define the package codes while the application boots.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        app()->instance(MapperRegistry::class, new MapperRegistry);
        app()->scopedIf(CapturedEvents::class);

        app()->booting(static function (Application $app): void {
            $app->make(Recorder::class)->define(CapturedActivity::class);
        });
    }

    /**
     * The one record written.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function onlyRecord(): AuditRecord
    {
        $records = $this->fake->recorded();

        self::assertCount(1, $records);

        return $records[0];
    }

    /**
     * Assert no capture failed: nothing reported and nothing dispatched.
     *
     * @return void
     */
    private function assertNothingFailed(): void
    {
        self::assertSame([], $this->reporter->reports());
        self::assertSame([], $this->failures);
    }

    /**
     * The Gate's evaluation of the ability for the user, with the arguments and
     * the result.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?bool  $result
     * @param  ?\Tests\Unit\Stubs\StubAuthUser  $user
     * @param  array<array-key, mixed>  $arguments
     * @param  string  $ability
     * @return \Illuminate\Auth\Access\Events\GateEvaluated
     */
    private static function denial(?bool $result, ?StubAuthUser $user = null, array $arguments = [], string $ability = self::ABILITY): GateEvaluated
    {
        return new GateEvaluated($user, $ability, $result, $arguments);
    }

    /**
     * The evaluation a Gate of its own dispatches for a guest when the
     * ability's callback gives the result, which the Gate passes on as it is.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $result
     * @return \Illuminate\Auth\Access\Events\GateEvaluated
     *
     * @throws \Illuminate\Auth\Access\AuthorizationException
     */
    private static function evaluation(mixed $result): GateEvaluated
    {
        $container = new Container;
        $events    = new Dispatcher($container);
        $evaluated = null;

        $container->instance(DispatcherContract::class, $events);

        $events->listen(GateEvaluated::class, static function (GateEvaluated $event) use (&$evaluated): void {
            $evaluated = $event;
        });

        (new AccessGate($container, static fn (): null => null))
            ->define(self::ABILITY, static fn (?Authenticatable $user = null): mixed => $result)
            ->raw(self::ABILITY);

        self::assertInstanceOf(GateEvaluated::class, $evaluated);

        return $evaluated;
    }

    /**
     * An allowing response that throws when asked whether it denies.
     *
     * @return \Illuminate\Auth\Access\Response
     */
    private static function unanswerableResponse(): Response
    {
        return new class (true) extends Response {
            /**
             * Fail to say whether the response denies.
             *
             * @return bool
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function denied(): bool
            {
                throw new \RuntimeException('The response cannot say whether it denies.');
            }
        };
    }

    /**
     * The listener, as the dispatcher would make it.
     *
     * @return \SineMacula\Laravel\AuditLog\Listeners\RecordGateDenial
     */
    private static function listener(): RecordGateDenial
    {
        return app(RecordGateDenial::class);
    }

    /**
     * A user of the id, never saved.
     *
     * @param  int  $id
     * @return \Tests\Unit\Stubs\StubAuthUser
     */
    private static function user(int $id): StubAuthUser
    {
        return (new StubAuthUser)->forceFill(['id' => $id]);
    }

    /**
     * The configuration repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private static function config(): ConfigRepository
    {
        return app(ConfigRepository::class);
    }
}
