<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Application as ConsoleApplication;
use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Console\Scheduling\Event as ScheduledEvent;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Database\Events\TransactionCommitting;
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
use SineMacula\Laravel\AuditLog\Console\DrainCommand;
use SineMacula\Laravel\AuditLog\Console\ReplayCommand;
use SineMacula\Laravel\AuditLog\Console\SealCommand;
use SineMacula\Laravel\AuditLog\Console\VerifyCommand;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Delivery\CommitQueue;
use SineMacula\Laravel\AuditLog\Http\Middleware\EnterHttpFrame;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Listeners\TrackCommandFrames;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Support\SystemClock;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Fixtures\Contributors\TenantContributor;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;
use Tests\TestCase;

/**
 * Feature tests for the package AuditLogServiceProvider: the configuration it
 * merges, the defaults it binds, the files it publishes under each tag, the
 * migrations it never loads, the commands it registers and the runs it
 * schedules in the console only, the listeners and middleware it adds, and that
 * it freezes registration at boot.
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

    /** @var list<string> File names of every shipped migration, in the order they run. */
    private const array SHIPPED_MIGRATIONS = [
        '2026_11_02_000000_create_audit_log_entries_table.php',
        '2026_11_02_000100_create_audit_log_outbox_table.php',
        '2026_11_02_000200_create_audit_log_deliveries_table.php',
        '2026_11_02_000300_create_audit_log_checkpoints_table.php',
        '2026_11_02_000400_create_audit_log_checkpoint_members_table.php',
        '2026_11_02_000500_create_audit_log_integrity_state_table.php',
    ];

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

        $expected = [];

        foreach (self::SHIPPED_MIGRATIONS as $file) {
            $expected[(string) realpath($source . $file)] = database_path('migrations/' . $file);
        }

        self::assertSame(self::SHIPPED_MIGRATIONS, $shipped);
        self::assertSame($expected, $paths);
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
     * Running in the console, as a test does, the drain command is there.
     *
     * @return void
     */
    public function testTheDrainCommandIsRegistered(): void
    {
        self::assertArrayHasKey('audit-log:drain', Artisan::all());
        self::assertInstanceOf(DrainCommand::class, Artisan::all()['audit-log:drain']);
    }

    /**
     * Running in the console, as a test does, the replay command is there.
     *
     * @return void
     */
    public function testTheReplayCommandIsRegistered(): void
    {
        self::assertArrayHasKey('audit-log:replay', Artisan::all());
        self::assertInstanceOf(ReplayCommand::class, Artisan::all()['audit-log:replay']);
    }

    /**
     * Running in the console, as a test does, the seal command is there.
     *
     * @return void
     */
    public function testTheSealCommandIsRegistered(): void
    {
        self::assertArrayHasKey('audit-log:seal', Artisan::all());
        self::assertInstanceOf(SealCommand::class, Artisan::all()['audit-log:seal']);
    }

    /**
     * Running in the console, as a test does, the verify command is there.
     *
     * @return void
     */
    public function testTheVerifyCommandIsRegistered(): void
    {
        self::assertArrayHasKey('audit-log:verify', Artisan::all());
        self::assertInstanceOf(VerifyCommand::class, Artisan::all()['audit-log:verify']);
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
            'the field encrypter'    => [FieldEncrypter::class, NoFieldEncrypter::class],
            'the prune ledger'       => [PruneLedger::class, NullPruneLedger::class],
            'the catalogue'          => [EventCatalogue::class, EventCatalogue::class],
            'the contributors'       => [ContributorRegistry::class, ContributorRegistry::class],
            'the recorder'           => [Recorder::class, Recorder::class],
            'the frames'             => [ExecutionFrames::class, ExecutionFrames::class],
            'the request identity'   => [RequestIdentity::class, RequestIdentity::class],
            'the write guard'        => [WriteGuard::class, WriteGuard::class],
            'the commit queue'       => [CommitQueue::class, CommitQueue::class],
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
     * The anchor is the null anchor when none is configured, made afresh on
     * each resolution, so a changed setting takes effect on the next one.
     *
     * @return void
     */
    public function testTheAnchorIsTheNullAnchorResolvedAfreshEachTime(): void
    {
        $anchor = app(CheckpointAnchor::class);

        self::assertInstanceOf(NullAnchor::class, $anchor);
        self::assertNotSame($anchor, app(CheckpointAnchor::class));
    }

    /**
     * The anchor follows the settings from one resolution to the next, and a
     * malformed driver fails closed when the anchor is resolved, not before.
     *
     * @return void
     */
    public function testTheAnchorReadsTheSettingsOnEachResolution(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.anchor.driver', null);

        self::assertInstanceOf(NullAnchor::class, app(CheckpointAnchor::class));

        app(ConfigRepository::class)->set('audit-log.integrity.anchor.driver', 's3');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.integrity.anchor.driver` must be `null` or `disk`.');

        app(CheckpointAnchor::class);
    }

    /**
     * Running in the console, the application's schedule holds sealing every
     * five minutes, the sweep and the strict verification daily, and nothing
     * else of the package's.
     *
     * @return void
     */
    public function testTheScheduleHoldsTheThreeRuns(): void
    {
        self::assertSame([
            'audit-log:seal'                          => '*/5 * * * *',
            'audit-log:seal --sweep'                  => '15 3 * * *',
            'audit-log:verify --strict --sweep-first' => '45 3 * * *',
        ], self::packageRuns(app(Schedule::class)));
    }

    /**
     * Outside the console the provider schedules nothing: it adds no callback
     * for when the schedule is resolved.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testNothingIsScheduledOutsideTheConsole(): void
    {
        $app = $this->app;

        assert($app instanceof Application);

        $callbacks = new \ReflectionProperty(Container::class, 'afterResolvingCallbacks');
        $before    = $callbacks->getValue($app);
        $running   = new \ReflectionProperty($app, 'isRunningInConsole');

        $running->setValue($app, false);

        (new \ReflectionMethod(AuditLogServiceProvider::class, 'registerSchedule'))->invoke(new AuditLogServiceProvider($app));

        self::assertSame($before, $callbacks->getValue($app));

        $running->setValue($app, true);

        (new \ReflectionMethod(AuditLogServiceProvider::class, 'registerSchedule'))->invoke(new AuditLogServiceProvider($app));

        self::assertNotSame($before, $callbacks->getValue($app));
    }

    /**
     * A schedule resolved before the provider boots is given the runs at once.
     *
     * @return void
     */
    public function testAScheduleResolvedEarlierIsGivenTheRuns(): void
    {
        $app = $this->app;

        assert($app instanceof Application);

        $schedule = new Schedule;

        $app->instance(Schedule::class, $schedule);

        (new \ReflectionMethod(AuditLogServiceProvider::class, 'registerSchedule'))->invoke(new AuditLogServiceProvider($app));

        self::assertSame(['audit-log:seal', 'audit-log:seal --sweep', 'audit-log:verify --strict --sweep-first'], array_keys(self::packageRuns($schedule)));
    }

    /**
     * A malformed schedule stops neither boot nor the schedule: the application
     * boots, its schedule resolves with the other two runs, and the malformed
     * setting is reported by its key.
     *
     * @return void
     */
    #[DefineEnvironment('malformTheSealSchedule')]
    public function testAMalformedScheduleDoesNotStopBoot(): void
    {
        $reported = [];
        $handler  = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report')->andReturnUsing(static function (\Throwable $exception) use (&$reported): void {
            $reported[] = $exception->getMessage();
        });

        $this->app?->instance(ExceptionHandler::class, $handler);
        $this->app?->forgetInstance(Schedule::class);

        self::assertTrue($this->app?->isBooted());
        self::assertSame(['audit-log:seal --sweep', 'audit-log:verify --strict --sweep-first'], array_keys(self::packageRuns(app(Schedule::class))));
        self::assertSame(['`audit-log.integrity.seal.schedule` must be a cron expression, or null or empty to schedule nothing.'], $reported);
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
        $guard    = app(WriteGuard::class);
        $queue    = app(CommitQueue::class);

        self::assertSame($latch, app(ReportLatch::class));

        $this->app?->forgetScopedInstances();

        self::assertNotSame($frames, app(ExecutionFrames::class));
        self::assertNotSame($identity, app(RequestIdentity::class));
        self::assertNotSame($latch, app(ReportLatch::class));
        self::assertNotSame($guard, app(WriteGuard::class));
        self::assertNotSame($queue, app(CommitQueue::class));
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
     * The commit queue's probe hears each commit about to happen, once, so an
     * aborted PostgreSQL transaction is caught before its callbacks run.
     *
     * @return void
     */
    public function testTheCommitProbeListensOnce(): void
    {
        self::assertSame([[CommitQueue::class, 'probe']], array_values(array_filter(
            Event::getRawListeners()[TransactionCommitting::class] ?? [],
            static fn (mixed $registered): bool => is_array($registered) && is_string($registered[0] ?? null) && str_starts_with($registered[0], 'SineMacula\\'),
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
            'audit-log.integrity.log_id'               => '../escape',
            'audit-log.integrity.checkpoints_table'    => 'Seals',
            'audit-log.integrity.seal.schedule'        => 'often',
            'audit-log.integrity.seal.batch'           => 'many',
            'audit-log.integrity.anchor.driver'        => 's3',
            'audit-log.integrity.anchor.path'          => '../anchors',
        ]);
    }

    /**
     * Give the sealing schedule a value that is not a cron expression.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function malformTheSealSchedule(Application $app): void
    {
        $app->make(ConfigRepository::class)->set('audit-log.integrity.seal.schedule', 'every five minutes');
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
     * The package's runs on the schedule, each command after `artisan` with its
     * cron expression.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return array<string, string>
     */
    private static function packageRuns(Schedule $schedule): array
    {
        $runs = [];

        foreach ($schedule->events() as $event) {

            $command = self::commandOf($event);

            if ($command === null) {
                continue;
            }

            $runs[$command] = $event->expression;
        }

        return $runs;
    }

    /**
     * The package command a scheduled event runs, as it follows `artisan`, or
     * `null` for any other event.
     *
     * @param  \Illuminate\Console\Scheduling\Event  $event
     * @return ?string
     */
    private static function commandOf(ScheduledEvent $event): ?string
    {
        return preg_match('/\'artisan\' (audit-log:.+)\z/', (string) $event->command, $matches) === 1 ? $matches[1] : null;
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
