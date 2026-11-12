<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Log\Context\Events\ContextDehydrating;
use Illuminate\Log\Context\Repository;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Context;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\HeldActorReader;
use SineMacula\Laravel\AuditLog\Contributors\AmbientActor;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Records\HeldActor;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ActorSnapshot;
use SineMacula\Laravel\AuditLog\Runtime\CarriedContext;
use SineMacula\Laravel\AuditLog\Runtime\ContextSettings;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;
use Tests\Unit\Stubs\StubForeignGuard;
use Tests\Unit\Stubs\StubHeldActorReader;

/**
 * Feature tests for the Context a queued job's payload carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CarryContextIntoJobs::class)]
final class CarryContextIntoJobsTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string A valid W3C trace id. */
    private const string TRACE_ID = '0af7651916cd43dd8448eb211c80319c';

    /** @var list<string> The actor's hidden keys. */
    private const array ACTOR_KEYS = [
        CarriedContext::ACTOR_TYPE, CarriedContext::ACTOR_ID, CarriedContext::ACTOR_GUARD,
        CarriedContext::PRINCIPAL_TYPE, CarriedContext::PRINCIPAL_ID, CarriedContext::TENANT_TYPE, CarriedContext::TENANT_ID, CarriedContext::SESSION,
    ];

    /**
     * Put the application back as the current container.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance($this->app);

        parent::tearDown();
    }

    /**
     * The actor goes on the given copy, never on the scoped repository.
     *
     * @return void
     */
    public function testWritesOnTheRepositoryItIsGiven(): void
    {
        Auth::guard('web')->setUser(self::user());

        $copy = $this->carried();

        self::assertSame('42', $copy->getHidden(CarriedContext::ACTOR_ID));

        foreach (self::ACTOR_KEYS as $key) {
            self::assertNull(Context::getHidden($key), $key);
        }
    }

    /**
     * Dispatching before the first record carries a request id generated now.
     *
     * @return void
     */
    public function testDispatchingBeforeTheFirstRecordCarriesAGeneratedId(): void
    {
        self::assertNull(Context::getHidden(CarriedContext::REQUEST_ID));

        $requestId = $this->carried()->getHidden(CarriedContext::REQUEST_ID);

        self::assertIsString($requestId);
        self::assertNotSame('', $requestId);
    }

    /**
     * The generated id is stored, so the records after the dispatch use it.
     *
     * @return void
     */
    public function testCarriesTheSameIdLaterRecordsUse(): void
    {
        $requestId = $this->carried()->getHidden(CarriedContext::REQUEST_ID);

        self::assertSame(app(RequestIdentity::class)->requestId(), $requestId);
    }

    /**
     * A trace id Context holds goes with the job.
     *
     * @return void
     */
    public function testCarriesTheTraceId(): void
    {
        Context::addHidden(CarriedContext::TRACE_ID, self::TRACE_ID);

        self::assertSame(self::TRACE_ID, $this->carried(new Repository(app(Dispatcher::class)))->getHidden(CarriedContext::TRACE_ID));
    }

    /**
     * No trace id is generated: with none there is no key at all.
     *
     * @return void
     */
    public function testCarriesNoTraceIdWhenThereIsNone(): void
    {
        self::assertArrayNotHasKey(CarriedContext::TRACE_ID, $this->carried()->allHidden());
    }

    /**
     * The ambient actor travels as three strings, never a model.
     *
     * @return void
     */
    public function testCarriesTheActorAsScalars(): void
    {
        Auth::guard('web')->setUser(self::user());

        $hidden = $this->carried()->allHidden();

        self::assertSame(StubAuthUser::class, $hidden[CarriedContext::ACTOR_TYPE]);
        self::assertSame('42', $hidden[CarriedContext::ACTOR_ID]);
        self::assertSame('web', $hidden[CarriedContext::ACTOR_GUARD]);
    }

    /**
     * A reader's held actor travels with its principal, tenant and session.
     *
     * @return void
     */
    public function testCarriesTheReadActorsContext(): void
    {
        $held = new HeldActor(Reference::of('identity', 'id-9'), Reference::of('principal', 'p-1'), Reference::of('tenant', 't-1'), 'session-1');

        Auth::extend('foreign', static fn (): Guard => new StubForeignGuard(holdsUser: true));

        $config = app(ConfigRepository::class);

        $config->set('auth.guards.foreign', ['driver' => 'foreign', 'provider' => 'users']);
        $config->set('audit-log.actor.guards', ['foreign']);

        $this->app?->instance(HeldActorReader::class, new StubHeldActorReader($held));

        $carried = CarriedContext::actor($this->carried());

        self::assertEquals($held, $carried?->held);
        self::assertSame('foreign', $carried?->guard);
    }

    /**
     * With no actor there is no envelope at all.
     *
     * @return void
     */
    public function testNoActorCarriesNoEnvelope(): void
    {
        $hidden = $this->carried()->allHidden();

        foreach (self::ACTOR_KEYS as $key) {
            self::assertArrayNotHasKey($key, $hidden);
        }
    }

    /**
     * Outside a job, the snapshot a sync job left in Context is not sent on.
     *
     * @return void
     */
    public function testALeftBehindEnvelopeIsForgottenOutsideAJob(): void
    {
        $hidden = $this->carried(self::copyHoldingAnActor())->allHidden();

        foreach (self::ACTOR_KEYS as $key) {
            self::assertArrayNotHasKey($key, $hidden);
        }
    }

    /**
     * Inside a job with no ambient actor, the carried actor goes on.
     *
     * @return void
     */
    public function testACarriedEnvelopeIsKeptInsideAJob(): void
    {
        app(ExecutionFrames::class)->enterJob(new \stdClass, 'App\Jobs\SendInvoice', new ActorSnapshot(new HeldActor(Reference::of('user', 'user-7')), 'admin'));

        $hidden = $this->carried()->allHidden();

        self::assertSame('user', $hidden[CarriedContext::ACTOR_TYPE]);
        self::assertSame('user-7', $hidden[CarriedContext::ACTOR_ID]);
        self::assertSame('admin', $hidden[CarriedContext::ACTOR_GUARD]);
    }

    /**
     * The frame's actor beats one a sync job left in Context.
     *
     * @return void
     */
    public function testTheFramesActorReplacesWhatASyncJobLeftInContext(): void
    {
        app(ExecutionFrames::class)->enterJob(new \stdClass, 'App\Jobs\SendInvoice', new ActorSnapshot(new HeldActor(Reference::of('user', 'user-1')), 'web'));

        $hidden = $this->carried(self::copyHoldingAnActor())->allHidden();

        self::assertSame('user-1', $hidden[CarriedContext::ACTOR_ID]);
        self::assertSame('web', $hidden[CarriedContext::ACTOR_GUARD]);
    }

    /**
     * A job that carried no actor sends none, whatever Context holds.
     *
     * @return void
     */
    public function testAJobThatCarriedNoActorSendsNone(): void
    {
        app(ExecutionFrames::class)->enterJob(new \stdClass, 'App\Jobs\SendInvoice');

        self::assertNull($this->carried(self::copyHoldingAnActor())->getHidden(CarriedContext::ACTOR_ID));
    }

    /**
     * A user left on a guard by an earlier job is not carried.
     *
     * @return void
     */
    public function testALeftoverGuardUserIsNotCarried(): void
    {
        $user = self::user();

        Auth::guard('web')->setUser($user);

        app(ExecutionFrames::class)->enterJob(new \stdClass, 'App\Jobs\SendInvoice', new ActorSnapshot(new HeldActor(Reference::of('user', 'user-7')), 'admin'), ['web' => $user]);

        self::assertSame('user-7', $this->carried()->getHidden(CarriedContext::ACTOR_ID));
    }

    /**
     * An ambient actor replaces a carried one, inside a job too.
     *
     * @return void
     */
    public function testTheAmbientActorReplacesACarriedEnvelope(): void
    {
        Auth::guard('web')->setUser(self::user());

        app(ExecutionFrames::class)->enterJob(new \stdClass, 'App\Jobs\SendInvoice', new ActorSnapshot(new HeldActor(Reference::of('user', 'user-7')), 'admin'));

        $hidden = $this->carried(self::copyHoldingAnActor())->allHidden();

        self::assertSame('42', $hidden[CarriedContext::ACTOR_ID]);
        self::assertSame('web', $hidden[CarriedContext::ACTOR_GUARD]);
    }

    /**
     * A malformed setting is reported and the payload is still made.
     *
     * @return void
     */
    public function testAMalformedSettingNeverStopsADispatch(): void
    {
        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report')->once()->with(\Mockery::type(\InvalidArgumentException::class));

        $this->app?->instance(ExceptionHandler::class, $handler);

        app(ConfigRepository::class)->set('audit-log.actor.guards', 'web');

        self::assertIsArray(Context::dehydrate());
    }

    /**
     * A failure drops the copy's actor keys and leaves the rest of it alone.
     *
     * @return void
     */
    public function testAFailureSendsNoStaleEnvelope(): void
    {
        $this->app?->instance(ExceptionHandler::class, \Mockery::spy(ExceptionHandler::class));

        app(ConfigRepository::class)->set('audit-log.actor.guards', 'web');
        app(ExecutionFrames::class)->enterJob(new \stdClass, 'App\Jobs\SendInvoice');

        $copy = self::copyHoldingAnActor();

        $copy->addHidden('application.key', 'kept');

        $hidden = $this->carried($copy)->allHidden();

        foreach (self::ACTOR_KEYS as $key) {
            self::assertArrayNotHasKey($key, $hidden);
        }

        self::assertSame('kept', $hidden['application.key']);
        self::assertArrayHasKey(CarriedContext::REQUEST_ID, $hidden);
    }

    /**
     * An unreferenceable user is no actor, and nothing is reported.
     *
     * @return void
     */
    public function testAnUnreferenceableUserNeverStopsADispatch(): void
    {
        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldNotReceive('report');

        $this->app?->instance(ExceptionHandler::class, $handler);

        Auth::guard('web')->setUser(new StubAuthUser);

        $hidden = $this->carried(self::copyHoldingAnActor())->allHidden();

        self::assertArrayHasKey(CarriedContext::REQUEST_ID, $hidden);
        self::assertArrayNotHasKey(CarriedContext::ACTOR_ID, $hidden);
    }

    /**
     * A reporter that fails too changes nothing for the caller.
     *
     * @return void
     */
    public function testAThrowingReporterNeverStopsADispatch(): void
    {
        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report')->once()->andThrow(new \RuntimeException('The reporter is down.'));

        $this->app?->instance(ExceptionHandler::class, $handler);

        app(ConfigRepository::class)->set('audit-log.actor.guards', 'web');

        $copy = self::copyHoldingAnActor();

        $this->carried($copy);

        self::assertArrayNotHasKey(CarriedContext::ACTOR_ID, $copy->allHidden());
    }

    /**
     * A handler dispatching from its report is called once, and the nested
     * dispatch still makes a payload.
     *
     * @return void
     */
    public function testAHandlerThatDispatchesFromItsReportDoesNotRecurse(): void
    {
        $reports = 0;

        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report')->andReturnUsing(static function () use (&$reports): void {
            $reports++;

            self::assertLessThan(3, $reports, 'The report recursed.');
            self::assertIsArray(Context::dehydrate(), 'The report\'s own dispatch still makes a payload.');
        });

        $this->app?->instance(ExceptionHandler::class, $handler);

        app(ConfigRepository::class)->set('audit-log.actor.guards', 'web');

        $this->carried(self::copyHoldingAnActor());

        self::assertSame(1, $reports);
    }

    /**
     * The nested dispatch's copy loses its actor keys too, unreported.
     *
     * @return void
     */
    public function testANestedFailureStillSendsNoStaleEnvelope(): void
    {
        $nested = self::copyHoldingAnActor();

        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report')->once()->andReturnUsing(function () use ($nested): void {
            $this->carried($nested);
        });

        $this->app?->instance(ExceptionHandler::class, $handler);

        app(ConfigRepository::class)->set('audit-log.actor.guards', 'web');

        $this->carried(self::copyHoldingAnActor());

        self::assertArrayNotHasKey(CarriedContext::ACTOR_ID, $nested->allHidden());
    }

    /**
     * State is read from the current container on every event, for Octane.
     *
     * @return void
     */
    public function testUsesTheCurrentContainer(): void
    {
        $events  = app(Dispatcher::class);
        $context = new Repository($events);
        $frames  = new ExecutionFrames;
        $copy    = new Repository($events);
        $sandbox = new Container;

        $sandbox->instance(RequestIdentity::class, new RequestIdentity($context, $frames, new ContextSettings(app(ConfigRepository::class)), app(Clock::class)));
        $sandbox->instance(AmbientActor::class, app(AmbientActor::class));
        $sandbox->instance(ExecutionFrames::class, $frames);

        Container::setInstance($sandbox);

        (new CarryContextIntoJobs)(new ContextDehydrating($copy));

        self::assertIsString($copy->getHidden(CarriedContext::REQUEST_ID));
        self::assertSame($context->getHidden(CarriedContext::REQUEST_ID), $copy->getHidden(CarriedContext::REQUEST_ID));
        self::assertNull(Context::getHidden(CarriedContext::REQUEST_ID));
    }

    /**
     * A failure is reported to the current container's handler.
     *
     * @return void
     */
    public function testAFailureIsReportedToTheCurrentContainer(): void
    {
        $booted  = \Mockery::mock(ExceptionHandler::class);
        $current = \Mockery::mock(ExceptionHandler::class);
        $copy    = new Repository(app(Dispatcher::class));
        $sandbox = new Container;

        $this->app?->instance(ExceptionHandler::class, $booted);
        $sandbox->instance(ExceptionHandler::class, $current);

        $booted->shouldNotReceive('report');
        $current->shouldReceive('report')->once();

        Container::setInstance($sandbox);

        (new CarryContextIntoJobs)(new ContextDehydrating($copy));
    }

    /**
     * A user with a key, which is never saved.
     *
     * @return \Tests\Unit\Stubs\StubAuthUser
     */
    private static function user(): StubAuthUser
    {
        return (new StubAuthUser)->forceFill(['id' => 42]);
    }

    /**
     * A copy of Context holding a snapshot, as a sync job leaves behind.
     *
     * @return \Illuminate\Log\Context\Repository
     */
    private static function copyHoldingAnActor(): Repository
    {
        $copy = new Repository(app(Dispatcher::class));

        CarriedContext::carryActor($copy, new ActorSnapshot(new HeldActor(Reference::of('user', 'user-7')), 'admin'));

        return $copy;
    }

    /**
     * The copy, or an empty one, after the listener has handled its event.
     *
     * @param  ?\Illuminate\Log\Context\Repository  $copy
     * @return \Illuminate\Log\Context\Repository
     */
    private function carried(?Repository $copy = null): Repository
    {
        $copy ??= new Repository(app(Dispatcher::class));

        (new CarryContextIntoJobs)(new ContextDehydrating($copy));

        return $copy;
    }
}
