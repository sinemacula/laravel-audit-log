<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane;

use Illuminate\Auth\Access\Events\GateEvaluated;
use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\OtherDeviceLogout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\PasswordResetLinkSent;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Log\Context\Events\ContextDehydrating;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Capture\ModelWatcher;
use SineMacula\Laravel\AuditLog\Contributors\ActorContributor;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Contributors\OriginContributor;
use SineMacula\Laravel\AuditLog\Contributors\RequestContributor;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Http\Middleware\EnterHttpFrame;
use SineMacula\Laravel\AuditLog\Listeners\CaptureMappedEvent;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Listeners\RecordGateDenial;
use SineMacula\Laravel\AuditLog\Listeners\RecordLaravelAuthEvent;
use SineMacula\Laravel\AuditLog\Listeners\RecordModelChange;
use SineMacula\Laravel\AuditLog\Listeners\TrackCommandFrames;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use Tests\Concerns\CreatesWatchedModels;
use Tests\Concerns\ServesRequestsThroughOctane;
use Tests\Fixtures\Capture\Events\AccountEvent;
use Tests\Fixtures\Capture\Events\PortalSignedIn;
use Tests\Fixtures\Capture\Events\SignedInToPortal;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Capture\Models\PlainLine;
use Tests\Fixtures\Capture\Models\WatchedInvoice;
use Tests\Fixtures\Contributors\ActorFillingContributor;
use Tests\Fixtures\Contributors\TenantContributor;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * End-to-end tests for what an application registers while it boots, served by
 * one Laravel Octane worker: the definitions, contributors, event mappers and
 * watched models serve every request, a request cannot add to them, what a
 * request captured dies with it, and the listeners and the middleware that
 * track and capture each request are registered once for the worker's whole
 * life.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Recorder::class)]
#[CoversClass(EventCatalogue::class)]
#[CoversClass(ContributorRegistry::class)]
#[CoversClass(MapperRegistry::class)]
#[CoversClass(ModelWatcher::class)]
#[CoversClass(AuditLogServiceProvider::class)]
final class RegistrationRequestsTest extends TestCase
{
    use CreatesWatchedModels, ServesRequestsThroughOctane;

    /** @var string The message a definition is refused with once the application has booted. */
    private const string DEFINE_REFUSAL = 'Event definitions are registered while the application boots, and it has already booted.';

    /** @var string The message a contributor is refused with once the application has booted. */
    private const string CONTRIBUTE_REFUSAL = 'Contributors are registered while the application boots, and it has already booted.';

    /** @var string A code no definition was registered for. */
    private const string UNREGISTERED_CODE = 'invoice.unregistered';

    /** @var string The message an unregistered code is refused with while registration is required. */
    private const string UNREGISTERED_REFUSAL = 'The event code `invoice.unregistered` is not registered, and unregistered codes are refused.';

    /** @var string The message a mapping is refused with once the application has booted. */
    private const string MAP_REFUSAL = 'Event mappers are registered while the application boots, and it has already booted.';

    /** @var string The message a watch is refused with once the application has booted. */
    private const string WATCH_REFUSAL = 'Models are watched while the application boots, and it has already booted.';

    /** @var string The segment the watched lines' changes are stored under. */
    private const string LINE_SEGMENT = 'line';

    /** @var string A code a request tries to define. */
    private const string LATE_CODE = 'invoice.defined_late';

    /** @var list<\SineMacula\Laravel\AuditLog\Definitions\EventCatalogue> The catalogue each request resolved, in order. */
    private array $catalogues = [];

    /** @var list<\SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry> The contributors each request resolved, in order. */
    private array $registries = [];

    /** @var list<\Illuminate\Events\Dispatcher> The dispatcher each request resolved, in order. */
    private array $dispatchers = [];

    /** @var list<\SineMacula\Laravel\AuditLog\Capture\CapturedEvents> The capture state each request resolved, in order. */
    private array $captured = [];

    /** @var ?\Tests\Fixtures\Capture\Events\PortalSignedIn One event object every request dispatches. */
    private ?PortalSignedIn $shared = null;

    /**
     * Add the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Route::get('/record', static fn (): array => AuditLog::record(InvoiceActivity::APPROVED)->toArray());

        Route::get('/record/unregistered', static fn (): array => AuditLog::record(self::UNREGISTERED_CODE)->toArray());

        Route::get('/define', static function (): array {
            try {
                AuditLog::define(EventDefinition::for(self::LATE_CODE)->category('finance'));
            } catch (\LogicException $exception) { // @phpstan-ignore catch.neverThrown
                return ['refused' => $exception->getMessage()];
            }

            return ['refused' => null];
        });

        Route::get('/contribute', static function (): array {
            try {
                AuditLog::contribute(ActorFillingContributor::class);
            } catch (\LogicException $exception) { // @phpstan-ignore catch.neverThrown
                return ['refused' => $exception->getMessage()];
            }

            return ['refused' => null];
        });

        Route::get('/strict', static function (): array {
            app(ConfigRepository::class)->set('audit-log.definitions.require_registered', true);

            try {
                AuditLog::record(self::UNREGISTERED_CODE);
            } catch (\InvalidArgumentException $exception) { // @phpstan-ignore catch.neverThrown
                return ['refused' => $exception->getMessage()];
            }

            return ['refused' => null];
        });

        $this->addCaptureRoutes();

        Route::get('/resolve', function (): array {
            $this->catalogues[] = app(EventCatalogue::class);
            $this->registries[] = app(ContributorRegistry::class);

            $dispatcher = app('events');

            self::assertInstanceOf(Dispatcher::class, $dispatcher);

            $this->dispatchers[] = $dispatcher;

            return ['resolved' => true];
        });
    }

    /**
     * A definition registered at boot gives its version and its category to
     * every request's record.
     *
     * @return void
     */
    public function testDefinitionsRegisteredAtBootServeEveryRequest(): void
    {
        $this->bootOctaneWorker();

        foreach ([1, 2, 3] as $request) {
            $response = $this->serve(self::octaneRequest('GET', '/record'));

            self::assertSame(InvoiceActivity::APPROVED->value, $response->json('event'), "Request {$request}'s code.");
            self::assertSame(2, $response->json('event_version'), "Request {$request}'s version.");
            self::assertSame('finance', $response->json('category'), "Request {$request}'s category.");
        }
    }

    /**
     * A contributor registered at boot fills every request's record, and it
     * follows the defaults, each once, however many requests have been served.
     *
     * @return void
     */
    public function testContributorsRegisteredAtBootServeEveryRequest(): void
    {
        $this->bootOctaneWorker();

        foreach ([1, 2, 3] as $request) {
            $response = $this->serve(self::octaneRequest('GET', '/record'));

            self::assertSame(TenantContributor::TYPE, $response->json('tenant_type'), "Request {$request}'s tenant type.");
            self::assertSame(TenantContributor::ID, $response->json('tenant_id'), "Request {$request}'s tenant id.");
        }

        self::assertSame(
            [OriginContributor::class, RequestContributor::class, ActorContributor::class, TenantContributor::class],
            app(ContributorRegistry::class)->classes(),
        );
    }

    /**
     * A definition offered in a request is refused in every request, however
     * many came before, and the catalogue does not take it.
     *
     * @return void
     */
    public function testDefineInARequestIsRefused(): void
    {
        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('GET', '/define'))->assertExactJson(['refused' => self::DEFINE_REFUSAL]);
        $this->serve(self::octaneRequest('GET', '/define'))->assertExactJson(['refused' => self::DEFINE_REFUSAL]);

        self::assertFalse(app(EventCatalogue::class)->isRegistered(EventCode::of(self::LATE_CODE)));
        self::assertTrue(app(EventCatalogue::class)->isRegistered(EventCode::of(InvoiceActivity::APPROVED)));
    }

    /**
     * A contributor offered in a request is refused in every request, however
     * many came before, and no later record is filled by it.
     *
     * @return void
     */
    public function testContributeInARequestIsRefused(): void
    {
        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('GET', '/contribute'))->assertExactJson(['refused' => self::CONTRIBUTE_REFUSAL]);
        $this->serve(self::octaneRequest('GET', '/contribute'))->assertExactJson(['refused' => self::CONTRIBUTE_REFUSAL]);

        self::assertNotContains(ActorFillingContributor::class, app(ContributorRegistry::class)->classes());

        self::assertNull($this->serve(self::octaneRequest('GET', '/record'))->assertOk()->json('actor_id'));
    }

    /**
     * Every request sees the one catalogue, the one list of contributors and
     * the one dispatcher the booted application holds.
     *
     * @return void
     */
    public function testEveryRequestResolvesTheRegistrationOfTheWorker(): void
    {
        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('GET', '/resolve'))->assertOk();
        $this->serve(self::octaneRequest('GET', '/resolve'))->assertOk();

        self::assertCount(2, $this->catalogues);

        foreach ([0, 1] as $request) {
            self::assertSame(app(EventCatalogue::class), $this->catalogues[$request]);
            self::assertSame(app(ContributorRegistry::class), $this->registries[$request]);
            self::assertSame(app('events'), $this->dispatchers[$request]);
        }
    }

    /**
     * A mapper registered at boot captures the mapped event in every request,
     * one row each, however many requests have been served.
     *
     * @return void
     */
    public function testMappersRegisteredAtBootServeEveryRequest(): void
    {
        $this->bootOctaneWorker();

        foreach ([1, 2, 3] as $request) {
            $this->serve(self::octaneRequest('GET', '/capture'))->assertOk();

            self::assertSame($request, $this->rowsOf(PortalMapper::CODE), "Rows after request {$request}.");
        }
    }

    /**
     * A model watched at boot has its creation recorded in every request, one
     * row each, however many requests have been served.
     *
     * @return void
     */
    public function testWatchesRegisteredAtBootServeEveryRequest(): void
    {
        $this->bootOctaneWorker();

        foreach ([1, 2, 3] as $request) {
            $this->serve(self::octaneRequest('GET', '/line'))->assertOk();

            self::assertSame($request, $this->rowsOf(self::LINE_SEGMENT . '.created'), "Rows after request {$request}.");
        }
    }

    /**
     * A mapping offered in a request is refused in every request, however many
     * came before, and the mappers do not take it.
     *
     * @return void
     */
    public function testMapInARequestIsRefused(): void
    {
        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('GET', '/map'))->assertExactJson(['refused' => self::MAP_REFUSAL]);
        $this->serve(self::octaneRequest('GET', '/map'))->assertExactJson(['refused' => self::MAP_REFUSAL]);

        self::assertNull(app(MapperRegistry::class)->mapperFor(SignedInToPortal::class));
        self::assertSame(PortalMapper::class, app(MapperRegistry::class)->mapperFor(PortalSignedIn::class));
    }

    /**
     * A watch offered in a request is refused in every request, however many
     * came before, and the watcher does not take it.
     *
     * @return void
     */
    public function testWatchInARequestIsRefused(): void
    {
        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('GET', '/watch'))->assertExactJson(['refused' => self::WATCH_REFUSAL]);
        $this->serve(self::octaneRequest('GET', '/watch'))->assertExactJson(['refused' => self::WATCH_REFUSAL]);

        self::assertNull(app(ModelWatcher::class)->watchFor(WatchedInvoice::class));
        self::assertSame(self::LINE_SEGMENT, app(ModelWatcher::class)->watchFor(PlainLine::class)?->as);
    }

    /**
     * What a request has captured dies with it: each request has capture state
     * of its own, so one event object dispatched in every request is claimed in
     * each and recorded once per request.
     *
     * @return void
     */
    public function testCapturedEventsDoNotOutliveTheirRequest(): void
    {
        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('GET', '/capture/shared'))->assertExactJson(['claimed' => true]);
        $this->serve(self::octaneRequest('GET', '/capture/shared'))->assertExactJson(['claimed' => true]);

        self::assertCount(2, $this->captured);
        self::assertNotSame($this->captured[0], $this->captured[1]);
        self::assertSame(2, $this->rowsOf(PortalMapper::CODE));
    }

    /**
     * A capture setting a request changes reaches that request's capture and no
     * later one: the capture listeners are built for each event from the
     * request's own container, never from the worker's.
     *
     * @return void
     */
    public function testACaptureSettingChangedInOneRequestDoesNotReachTheNext(): void
    {
        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('GET', '/sign-in', ['except' => 'web']))->assertOk();

        self::assertSame(0, $this->rowsOf(CapturedActivity::SIGNED_IN->value), 'The excluded guard was recorded.');

        $this->serve(self::octaneRequest('GET', '/sign-in'))->assertOk();

        self::assertSame(1, $this->rowsOf(CapturedActivity::SIGNED_IN->value), 'The next request kept the exclusion.');
    }

    /**
     * Rows of `[event, the listener the package gives it]`: every event the
     * package listens for.
     *
     * @return iterable<string, array{0: class-string, 1: class-string}>
     */
    public static function provideListeners(): iterable
    {
        yield from [
            'a command starting'     => [CommandStarting::class, TrackCommandFrames::class],
            'a command finishing'    => [CommandFinished::class, TrackCommandFrames::class],
            'a job processing'       => [JobProcessing::class, TrackJobFrames::class],
            'a job processed'        => [JobProcessed::class, TrackJobFrames::class],
            'a job failed'           => [JobFailed::class, TrackJobFrames::class],
            'a job exception'        => [JobExceptionOccurred::class, TrackJobFrames::class],
            'Context being prepared' => [ContextDehydrating::class, CarryContextIntoJobs::class],
            'a sign-in'              => [Login::class, RecordLaravelAuthEvent::class],
            'a failed sign-in'       => [Failed::class, RecordLaravelAuthEvent::class],
            'a lockout'              => [Lockout::class, RecordLaravelAuthEvent::class],
            'a sign-out'             => [Logout::class, RecordLaravelAuthEvent::class],
            'a device sign-out'      => [CurrentDeviceLogout::class, RecordLaravelAuthEvent::class],
            'other devices out'      => [OtherDeviceLogout::class, RecordLaravelAuthEvent::class],
            'a registration'         => [Registered::class, RecordLaravelAuthEvent::class],
            'a verification'         => [Verified::class, RecordLaravelAuthEvent::class],
            'a password reset'       => [PasswordReset::class, RecordLaravelAuthEvent::class],
            'a reset link sent'      => [PasswordResetLinkSent::class, RecordLaravelAuthEvent::class],
            'a Gate evaluation'      => [GateEvaluated::class, RecordGateDenial::class],
        ];
    }

    /**
     * Each listener is on the worker's one dispatcher once, however many
     * requests have been served: a request registers nothing.
     *
     * @param  class-string  $event
     * @param  class-string  $listener
     * @return void
     */
    #[DataProvider('provideListeners')]
    public function testTheListenersAreRegisteredOncePerWorker(string $event, string $listener): void
    {
        $this->bootOctaneWorker();

        self::assertSame(1, self::timesListening($event, $listener), 'Before any request.');

        $this->serve(self::octaneRequest('GET', '/record'))->assertOk();
        $this->serve(self::octaneRequest('GET', '/record'))->assertOk();
        $this->serve(self::octaneRequest('GET', '/record'))->assertOk();

        self::assertSame(1, self::timesListening($event, $listener), 'After three requests.');
    }

    /**
     * The listener that routes mapped events, which the mapping at boot added,
     * is on the worker's one dispatcher once, however many requests have been
     * served, and so is each watched model's.
     *
     * @return void
     */
    public function testTheCaptureListenersAreRegisteredOncePerWorker(): void
    {
        $this->bootOctaneWorker();

        foreach (['Before any request.', 'After three requests.'] as $when) {
            self::assertSame(1, self::timesRouting(), $when);
            self::assertSame(1, self::timesListening('eloquent.created: ' . PlainLine::class, [RecordModelChange::class, 'created']), $when);

            $this->serve(self::octaneRequest('GET', '/capture'))->assertOk();
            $this->serve(self::octaneRequest('GET', '/line'))->assertOk();
            $this->serve(self::octaneRequest('GET', '/record'))->assertOk();
        }
    }

    /**
     * The middleware that enters a request's frame is on the HTTP kernel once,
     * first, however many requests have been served.
     *
     * @return void
     */
    public function testTheFrameMiddlewareIsOnTheKernelOnce(): void
    {
        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('GET', '/record'))->assertOk();
        $this->serve(self::octaneRequest('GET', '/record'))->assertOk();
        $this->serve(self::octaneRequest('GET', '/record'))->assertOk();

        $kernel = app(HttpKernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);

        $middleware = $kernel->getGlobalMiddleware();

        self::assertSame(EnterHttpFrame::class, $middleware[0] ?? null);
        self::assertCount(1, array_keys($middleware, EnterHttpFrame::class, true));
    }

    /**
     * A setting a request changes reaches its own capture and no later one: the
     * requirement to register is read per capture from the request's
     * configuration, never kept on the recorder or the catalogue.
     *
     * @return void
     */
    public function testRequiringRegistrationInOneRequestDoesNotReachTheNext(): void
    {
        $this->bootOctaneWorker();

        $this->serve(self::octaneRequest('GET', '/strict'))->assertExactJson(['refused' => self::UNREGISTERED_REFUSAL]);

        $this->serve(self::octaneRequest('GET', '/record/unregistered'))->assertOk()->assertJsonPath('event', self::UNREGISTERED_CODE);
    }

    /**
     * Register a definition, a contributor, an event mapper and a watched model
     * while the application boots, as an application's own provider would.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        self::assertInstanceOf(Application::class, $app);

        $app->booting(static function (Application $app): void {
            $recorder = $app->make(Recorder::class);

            $recorder->define(InvoiceActivity::class);
            $recorder->contribute(TenantContributor::class);
            $recorder->map(PortalSignedIn::class, PortalMapper::class);
            $recorder->watch(PlainLine::class, as: self::LINE_SEGMENT, fields: ['description']);
        });
    }

    /**
     * Add the routes that capture, and that try to map and watch.
     *
     * @return void
     */
    private function addCaptureRoutes(): void
    {
        Route::get('/capture', static function (): array {
            Event::dispatch(new PortalSignedIn);

            return ['dispatched' => true];
        });

        Route::get('/capture/shared', function (): array {
            $this->captured[] = app(CapturedEvents::class);

            Event::dispatch($this->shared ??= new PortalSignedIn);

            return ['claimed' => app(CapturedEvents::class)->isClaimed($this->shared)];
        });

        Route::get('/sign-in', static function (): array {
            if (request()->query('except') !== null) {
                app(ConfigRepository::class)->set('audit-log.capture.laravel.except_guards', ['web']);
            }

            Event::dispatch(new Login('web', (new StubAuthUser)->forceFill(['id' => 7]), false));

            return ['dispatched' => true];
        });

        Route::get('/line', static function (): array {
            PlainLine::query()->create(['description' => 'A line']);

            return ['created' => true];
        });

        Route::get('/map', static function (): array {
            try {
                AuditLog::map(AccountEvent::class, PortalMapper::class);
            } catch (\LogicException $exception) { // @phpstan-ignore catch.neverThrown
                return ['refused' => $exception->getMessage()];
            }

            return ['refused' => null];
        });

        Route::get('/watch', static function (): array {
            try {
                AuditLog::watch(WatchedInvoice::class, as: 'invoice', fields: ['number']);
            } catch (\LogicException $exception) { // @phpstan-ignore catch.neverThrown
                return ['refused' => $exception->getMessage()];
            }

            return ['refused' => null];
        });
    }

    /**
     * How many times the listener is on the application's dispatcher for the
     * event.
     *
     * @param  string  $event
     * @param  array{0: class-string, 1: string}|class-string  $listener
     * @return int
     */
    private static function timesListening(string $event, array|string $listener): int
    {
        $dispatcher = app('events');

        self::assertInstanceOf(Dispatcher::class, $dispatcher);

        return count(array_keys(self::listenersFor($dispatcher->getRawListeners(), $event), $listener, true));
    }

    /**
     * How many times the listener that routes mapped events is on the
     * application's dispatcher for every event.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return int
     */
    private static function timesRouting(): int
    {
        $dispatcher = app('events');

        self::assertInstanceOf(Dispatcher::class, $dispatcher);

        $wildcards = (new \ReflectionProperty(Dispatcher::class, 'wildcards'))->getValue($dispatcher);

        self::assertIsArray($wildcards);

        $listeners = $wildcards['*'] ?? [];

        self::assertIsArray($listeners);

        return count(array_keys($listeners, CaptureMappedEvent::class, true));
    }

    /**
     * How many entries hold the code.
     *
     * @param  string  $code
     * @return int
     */
    private function rowsOf(string $code): int
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('event', $code)->count();
    }
}
