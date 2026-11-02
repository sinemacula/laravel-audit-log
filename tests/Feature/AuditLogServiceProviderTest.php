<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Application as ConsoleApplication;
use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Foundation\Application;
use Illuminate\Log\Context\Events\ContextDehydrating;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Illuminate\View\FileViewFinder;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Http\Middleware\EnterHttpFrame;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Listeners\TrackCommandFrames;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Support\SystemClock;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Fixtures\Contributors\TenantContributor;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;
use Tests\TestCase;

/**
 * Feature tests for the package AuditLogServiceProvider: the configuration it
 * merges, the defaults it binds, the files it publishes under each tag, the
 * migrations it never loads, the command it registers in the console only, the
 * listeners and middleware it adds, and that it freezes registration at boot.
 *
 * The class runs no migration of its own, so the migrator's paths are what the
 * provider leaves there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLogServiceProvider::class)]
final class AuditLogServiceProviderTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The tag the configuration file is published under. */
    private const string CONFIG_TAG = 'audit-log-config';

    /** @var string The tag the migrations are published under. */
    private const string MIGRATIONS_TAG = 'audit-log-migrations';

    /**
     * The shipped configuration is merged under the package's key.
     *
     * @return void
     */
    public function testShippedConfigurationIsMerged(): void
    {
        $config = app(ConfigRepository::class);

        self::assertSame('audit-log', AuditLogServiceProvider::CONFIG);
        self::assertTrue($config->has('audit-log.storage'));
        self::assertNull($config->get('audit-log.storage.connection'));
    }

    /**
     * A value the application configures wins over the shipped default.
     *
     * @return void
     */
    public function testApplicationConfigurationWinsOverTheShippedDefault(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log', ['storage' => ['connection' => 'audit']]);

        (new AuditLogServiceProvider($this->app))->register();

        self::assertSame('audit', $config->get('audit-log.storage.connection'));
    }

    /**
     * The configuration file is published to the application's config directory
     * under the package's tag.
     *
     * @return void
     */
    public function testConfigurationIsPublishedUnderItsTag(): void
    {
        $paths = ServiceProvider::pathsToPublish(AuditLogServiceProvider::class, self::CONFIG_TAG);

        self::assertCount(1, $paths);
        self::assertSame(realpath(__DIR__ . '/../../config/audit-log.php'), realpath((string) array_key_first($paths)));
        self::assertSame(config_path('audit-log.php'), array_values($paths)[0]);
        self::assertContains(self::CONFIG_TAG, ServiceProvider::publishableGroups());
    }

    /**
     * Outside the console the provider registers nothing for publishing.
     *
     * @return void
     */
    public function testNothingIsPublishedOutsideTheConsole(): void
    {
        $this->forgetPublishing();

        $running = new \ReflectionProperty($this->app, 'isRunningInConsole');
        $running->setValue($this->app, false);

        (new AuditLogServiceProvider($this->app))->boot();

        self::assertSame([], ServiceProvider::pathsToPublish(AuditLogServiceProvider::class));
    }

    /**
     * The migrations tag publishes every shipped migration, from the package to
     * the application's migrations, under its own file name.
     *
     * @return void
     */
    public function testTheMigrationsArePublishedUnderTheirTag(): void
    {
        $source = dirname(__DIR__, 2) . '/database/migrations/';
        $paths  = [];

        foreach (ServiceProvider::pathsToPublish(AuditLogServiceProvider::class, self::MIGRATIONS_TAG) as $from => $to) {
            $paths[(string) realpath($from)] = $to;
        }

        $shipped = array_map(static fn (string $file): string => basename($file), glob($source . '*.php') ?: []);

        self::assertSame(['2026_11_02_000000_create_audit_log_entries_table.php'], $shipped);
        self::assertSame([
            (string) realpath($source . '2026_11_02_000000_create_audit_log_entries_table.php') => database_path('migrations/2026_11_02_000000_create_audit_log_entries_table.php'),
        ], $paths);
        self::assertContains(self::MIGRATIONS_TAG, ServiceProvider::publishableGroups());
    }

    /**
     * The provider never loads the migrations from the package: the class runs
     * none of its own, so the migrator knows no path, and the application runs
     * only what it published.
     *
     * @return void
     */
    public function testTheMigrationsAreNeverLoadedAutomatically(): void
    {
        $migrator = $this->app?->make('migrator');

        assert($migrator instanceof Migrator);

        self::assertSame([], $migrator->paths());
    }

    /**
     * The check is registered as an Artisan command when the application runs
     * in the console.
     *
     * @return void
     */
    public function testTheCheckCommandIsRegistered(): void
    {
        self::assertArrayHasKey('audit-log:check', Artisan::all());
        self::assertInstanceOf(CheckCommand::class, Artisan::all()['audit-log:check']);
    }

    /**
     * Outside the console no command is registered.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testNoCommandIsRegisteredOutsideTheConsole(): void
    {
        $app = \Mockery::mock(Application::class)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturnFalse();

        $bootstrappers = new \ReflectionProperty(ConsoleApplication::class, 'bootstrappers');
        $before        = $bootstrappers->getValue();

        (new \ReflectionMethod(AuditLogServiceProvider::class, 'registerCommands'))->invoke(new AuditLogServiceProvider($app));

        self::assertSame($before, $bootstrappers->getValue());
    }

    /**
     * Rows of `[abstract, the default it resolves to]`: every abstract the
     * package's provider binds.
     *
     * @return iterable<string, array{0: class-string, 1: class-string}>
     */
    public static function provideDefaults(): iterable
    {
        yield from [
            'the clock'              => [Clock::class, SystemClock::class],
            'the integrity settings' => [IntegritySettings::class, IntegritySettings::class],
            'the key ring'           => [KeyRing::class, KeyRing::class],
            'the store'              => [AuditStore::class, DatabaseAuditStore::class],
            'the catalogue'          => [EventCatalogue::class, EventCatalogue::class],
            'the contributors'       => [ContributorRegistry::class, ContributorRegistry::class],
            'the recorder'           => [Recorder::class, Recorder::class],
            'the frames'             => [ExecutionFrames::class, ExecutionFrames::class],
            'the request identity'   => [RequestIdentity::class, RequestIdentity::class],
        ];
    }

    /**
     * Each abstract resolves to its default, once per application.
     *
     * @param  class-string  $abstract
     * @param  class-string  $default
     * @return void
     */
    #[DataProvider('provideDefaults')]
    public function testTheDefaultsAreBound(string $abstract, string $default): void
    {
        $resolved = app($abstract);

        self::assertInstanceOf($default, $resolved);
        self::assertSame($resolved, app($abstract));
    }

    /**
     * The recorder is one object for the application's life.
     *
     * @return void
     */
    public function testTheRecorderIsASingleton(): void
    {
        self::assertSame(app(Recorder::class), app(Recorder::class));
    }

    /**
     * The runtime state dies with its scope: forgetting scoped instances gives
     * new frames and a new identity, as Octane and a queue worker do.
     *
     * @return void
     */
    public function testTheRuntimeStateIsScoped(): void
    {
        $frames   = app(ExecutionFrames::class);
        $identity = app(RequestIdentity::class);
        $latch    = app(ReportLatch::class);

        self::assertSame($latch, app(ReportLatch::class));

        $this->app?->forgetScopedInstances();

        self::assertNotSame($frames, app(ExecutionFrames::class));
        self::assertNotSame($identity, app(RequestIdentity::class));
        self::assertNotSame($latch, app(ReportLatch::class));
    }

    /**
     * The recorder and what it holds outlive the scope.
     *
     * @return void
     */
    public function testTheRecorderSurvivesForgettingScopedInstances(): void
    {
        $recorder     = app(Recorder::class);
        $catalogue    = app(EventCatalogue::class);
        $contributors = app(ContributorRegistry::class);

        $this->app?->forgetScopedInstances();

        self::assertSame($recorder, app(Recorder::class));
        self::assertSame($catalogue, app(EventCatalogue::class));
        self::assertSame($contributors, app(ContributorRegistry::class));
    }

    /**
     * Rows of `[event, listener]`: every event the provider listens to.
     *
     * @return iterable<string, array{0: class-string, 1: class-string}>
     */
    public static function provideListeners(): iterable
    {
        yield from [
            'a command starting' => [CommandStarting::class, TrackCommandFrames::class],
            'a command finished' => [CommandFinished::class, TrackCommandFrames::class],
            'a job processing'   => [JobProcessing::class, TrackJobFrames::class],
            'a job processed'    => [JobProcessed::class, TrackJobFrames::class],
            'a job failed'       => [JobFailed::class, TrackJobFrames::class],
            'a job exception'    => [JobExceptionOccurred::class, TrackJobFrames::class],
            'context dehydrated' => [ContextDehydrating::class, CarryContextIntoJobs::class],
        ];
    }

    /**
     * Each event has the package's listener, registered once however it is
     * read, so a frame is entered once and a job carries one envelope.
     *
     * @param  class-string  $event
     * @param  class-string  $listener
     * @return void
     */
    #[DataProvider('provideListeners')]
    public function testListenersRegisterOnce(string $event, string $listener): void
    {
        self::assertSame([$listener], array_values(array_filter(
            Event::getRawListeners()[$event] ?? [],
            static fn (mixed $registered): bool => is_string($registered) && str_starts_with($registered, 'SineMacula\\'),
        )));
    }

    /**
     * The middleware is at the head of the kernel's global stack, once, so a
     * record in any other global middleware has its request.
     *
     * @return void
     */
    public function testTheHttpFrameMiddlewareIsFirstAndOnce(): void
    {
        $kernel = app(HttpKernel::class);

        $middleware = $kernel->getGlobalMiddleware();

        self::assertSame(EnterHttpFrame::class, $middleware[0] ?? null);
        self::assertCount(1, array_keys($middleware, EnterHttpFrame::class, true));

        $this->app?->register(new AuditLogServiceProvider($this->app), true);

        self::assertCount(1, array_keys($kernel->getGlobalMiddleware(), EnterHttpFrame::class, true));
    }

    /**
     * The provider adds no route and no view path. Serving local files is off,
     * because the framework then adds its own routes for them, on whichever
     * version's skeleton turns it on.
     *
     * @return void
     */
    #[DefineEnvironment('withoutServedFiles')]
    public function testRoutesAndViewsAreUnchanged(): void
    {
        $finder = app('view')->getFinder();

        assert($finder instanceof FileViewFinder);

        $paths = $finder->getPaths();

        foreach ($finder->getHints() as $hinted) {
            $paths = [...$paths, ...$hinted];
        }

        $source = (string) realpath(__DIR__ . '/../../src');

        self::assertCount(0, Route::getRoutes());
        self::assertArrayNotHasKey('audit-log', $finder->getHints());

        foreach ($paths as $path) {
            self::assertStringStartsNotWith($source, (string) realpath($path));
        }
    }

    /**
     * Once the application has booted, both lists refuse more.
     *
     * @return void
     */
    public function testRegistrationIsFrozenOnceBooted(): void
    {
        self::assertTrue(app(EventCatalogue::class)->isFrozen());
        self::assertTrue(app(ContributorRegistry::class)->isFrozen());
    }

    /**
     * Definitions and contributors registered from a provider's `boot()` are
     * accepted and kept.
     *
     * @return void
     */
    #[DefineEnvironment('registerInAProvidersBoot')]
    public function testRegistrationInAProvidersBootIsAccepted(): void
    {
        FakeAuditStore::fake();

        self::assertTrue(app(EventCatalogue::class)->isFrozen());
        self::assertSame('finance', app(Recorder::class)->record(InvoiceActivity::APPROVED)->category);
        self::assertContains(TenantContributor::class, app(ContributorRegistry::class)->classes());
    }

    /**
     * Booting reads no setting that could stop it: an application with every
     * new setting malformed boots and is frozen, and `audit-log:check` can
     * report the settings.
     *
     * @return void
     */
    #[DefineEnvironment('malformEverySetting')]
    public function testAMalformedSettingDoesNotStopBoot(): void
    {
        self::assertTrue($this->app?->isBooted());
        self::assertTrue(app(EventCatalogue::class)->isFrozen());
        self::assertSame(1, Artisan::call('audit-log:check'));
    }

    /**
     * Register an enum and a contributor from another provider's `boot()`,
     * which runs before the application has finished booting.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function registerInAProvidersBoot(Application $app): void
    {
        $app->register(new class ($app) extends ServiceProvider {
            /**
             * Register with the recorder.
             *
             * @return void
             */
            public function boot(): void
            {
                $recorder = $this->app->make(Recorder::class);

                $recorder->define(InvoiceActivity::class);
                $recorder->contribute(TenantContributor::class);
            }
        });
    }

    /**
     * Give each setting the provider could trip over a malformed value.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function malformEverySetting(Application $app): void
    {
        $app->make(ConfigRepository::class)->set([
            'audit-log.actor.guards'                   => 'web',
            'audit-log.context.trust_request_id'       => 'yes',
            'audit-log.context.request_id_header'      => 'X Request',
            'audit-log.context.trust_traceparent'      => 'yes',
            'audit-log.definitions.require_registered' => 'yes',
            'audit-log.source.id'                      => 42,
            'audit-log.source.region'                  => 42,
        ]);
    }

    /**
     * Run no migration, so the migrator holds only what the provider gives it.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        // The provider must load no migration, which the class checks, so
        // nothing else loads one
    }

    /**
     * Stop the framework serving the local disk, which adds routes of its own.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function withoutServedFiles(Application $app): void
    {
        $app->make(ConfigRepository::class)->set('filesystems.disks.local.serve', false);
    }

    /**
     * Forget every path the package's provider registered for publishing.
     *
     * @return void
     */
    private function forgetPublishing(): void
    {
        foreach (['publishes', 'publishGroups'] as $property) {
            $paths = new \ReflectionProperty(ServiceProvider::class, $property);

            /** @var array<string, array<string, string>> $value */
            $value = $paths->getValue();

            unset($value[AuditLogServiceProvider::class], $value[self::CONFIG_TAG], $value[self::MIGRATIONS_TAG]);

            $paths->setValue(null, $value);
        }
    }
}
