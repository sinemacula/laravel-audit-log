<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane;

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
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Contributors\ActorContributor;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Contributors\OriginContributor;
use SineMacula\Laravel\AuditLog\Contributors\RequestContributor;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Http\Middleware\EnterHttpFrame;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Listeners\TrackCommandFrames;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use Tests\Concerns\ServesRequestsThroughOctane;
use Tests\Fixtures\Contributors\ActorFillingContributor;
use Tests\Fixtures\Contributors\TenantContributor;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;
use Tests\TestCase;

/**
 * End-to-end tests for what an application registers while it boots, served by
 * one Laravel Octane worker: the definitions and contributors serve every
 * request, a request cannot add to them, and the listeners and the middleware
 * that track each request are registered once for the worker's whole life.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Recorder::class)]
#[CoversClass(EventCatalogue::class)]
#[CoversClass(ContributorRegistry::class)]
#[CoversClass(AuditLogServiceProvider::class)]
final class RegistrationRequestsTest extends TestCase
{
    use ServesRequestsThroughOctane;

    /** @var string The message a definition is refused with once the application has booted. */
    private const string DEFINE_REFUSAL = 'Event definitions are registered while the application boots, and it has already booted.';

    /** @var string The message a contributor is refused with once the application has booted. */
    private const string CONTRIBUTE_REFUSAL = 'Contributors are registered while the application boots, and it has already booted.';

    /** @var string A code no definition was registered for. */
    private const string UNREGISTERED_CODE = 'invoice.unregistered';

    /** @var string The message an unregistered code is refused with while registration is required. */
    private const string UNREGISTERED_REFUSAL = 'The event code `invoice.unregistered` is not registered, and unregistered codes are refused.';

    /** @var string A code a request tries to define. */
    private const string LATE_CODE = 'invoice.defined_late';

    /** @var list<\SineMacula\Laravel\AuditLog\Definitions\EventCatalogue> The catalogue each request resolved, in order. */
    private array $catalogues = [];

    /** @var list<\SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry> The contributors each request resolved, in order. */
    private array $registries = [];

    /** @var list<\Illuminate\Events\Dispatcher> The dispatcher each request resolved, in order. */
    private array $dispatchers = [];

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
     * Register a definition and a contributor while the application boots, as
     * an application's own provider would.
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
        });
    }

    /**
     * How many times the listener is on the application's dispatcher for the
     * event.
     *
     * @param  class-string  $event
     * @param  class-string  $listener
     * @return int
     */
    private static function timesListening(string $event, string $listener): int
    {
        $dispatcher = app('events');

        self::assertInstanceOf(Dispatcher::class, $dispatcher);

        return count(array_keys($dispatcher->getRawListeners()[$event] ?? [], $listener, true));
    }
}
