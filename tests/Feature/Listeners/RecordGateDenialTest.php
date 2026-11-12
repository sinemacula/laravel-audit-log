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
use Tests\Unit\Stubs\Enums\StubNumberedAbility;
use Tests\Unit\Stubs\StubAuthUser;
use Tests\Unit\Stubs\StubDocument;

/**
 * Feature tests for capturing the Gate's denials.
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
     * Fake the store and reporter, enable Gate capture, and hear failures.
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
     * With Gate capture off, a denial records nothing and is left unclaimed.
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
     * A `false` result is a denial in the security category, with no reason.
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
     * A guest's denial has no actor, even while a guard holds a user.
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
     * No guard is recorded, since the Gate names none.
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
     * The ability is cleaned and capped at 191 bytes on a character boundary,
     * while selection uses the raw ability.
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
     * Arguments become references, classes or the marker, up to eight, counted.
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
     * A response code is the reason only when allowlisted, as string or int.
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
     * A result that is not a response gives no reason.
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
     * The denied response's free-text message is never read.
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
     * Only abilities filter denials, compared exactly as the Gate gave them.
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
     * An excepted ability is never recorded, even when only abilities list it.
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
     * Each evaluation is recorded, but one event object only once.
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
     * Through the Gate itself, each denial is recorded and the result returned.
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
     * A malformed setting is contained, and the Gate's check still returns.
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
     * An allowed check reads no setting, so malformed settings stay silent.
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
     * With capture off, a response is never asked whether it denies.
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
     * A response that throws when asked if it denies is a contained failure.
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
     * A non-string ability, such as an int-backed enum, is a contained failure.
     *
     * @return void
     */
    public function testAnAbilityThatIsNotAStringIsContained(): void
    {
        Gate::define(StubNumberedAbility::PUBLISH, static fn (StubAuthUser $user): bool => false);

        self::assertFalse(Gate::forUser(self::user(7))->allows(StubNumberedAbility::PUBLISH));
        self::assertSame(0, $this->fake->count());
        self::assertSame([[GateEvaluated::class, RecordGateDenial::class, \TypeError::class]], array_map(
            static fn (AuditCaptureFailed $failure): array => [$failure->eventClass, $failure->mapperClass, $failure->exceptionClass],
            $this->failures,
        ));
    }

    /**
     * Bind the capture state as the provider does and define the package codes.
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
     * The Gate's evaluation of the ability for the user, arguments and result.
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
     * The evaluation a Gate of its own dispatches for a guest with the result.
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
