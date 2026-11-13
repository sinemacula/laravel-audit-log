<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\Access\Events\GateEvaluated;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\OtherDeviceLogout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\PasswordResetLinkSent;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Validated;
use Illuminate\Auth\Events\Verified;
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
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Events\Dispatcher;
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
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Capture\ModelWatcher;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use SineMacula\Laravel\AuditLog\Console\DrainCommand;
use SineMacula\Laravel\AuditLog\Console\EraseCommand;
use SineMacula\Laravel\AuditLog\Console\ExportCommand;
use SineMacula\Laravel\AuditLog\Console\HoldCommand;
use SineMacula\Laravel\AuditLog\Console\HoldsCommand;
use SineMacula\Laravel\AuditLog\Console\ImportCommand;
use SineMacula\Laravel\AuditLog\Console\KeysCommand;
use SineMacula\Laravel\AuditLog\Console\PruneCommand;
use SineMacula\Laravel\AuditLog\Console\ReconcileCommand;
use SineMacula\Laravel\AuditLog\Console\ReinstateCommand;
use SineMacula\Laravel\AuditLog\Console\ReleaseCommand;
use SineMacula\Laravel\AuditLog\Console\ReplayCommand;
use SineMacula\Laravel\AuditLog\Console\RewrapCommand;
use SineMacula\Laravel\AuditLog\Console\SealCommand;
use SineMacula\Laravel\AuditLog\Console\VerifyCommand;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\CommitQueue;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Http\Middleware\EnterHttpFrame;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalPruneLedger;
use SineMacula\Laravel\AuditLog\Listeners\CaptureMappedEvent;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Listeners\RecordGateDenial;
use SineMacula\Laravel\AuditLog\Listeners\RecordLaravelAuthEvent;
use SineMacula\Laravel\AuditLog\Listeners\RecordModelChange;
use SineMacula\Laravel\AuditLog\Listeners\TrackCommandFrames;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SealedFieldReader;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Describer;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\ReadGuard;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Support\SystemClock;
use SineMacula\Laravel\AuditLog\Support\UuidV7;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Fixtures\Capture\Events\PortalSignedIn;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Capture\Models\PlainLine;
use Tests\Fixtures\Contributors\TenantContributor;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;
use Tests\Fixtures\Querying\ClosurePolicy;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * Feature tests for the package's service provider. The class runs no
 * migration, so the migrator holds only what the provider leaves.
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

    /** @var string The tag the translations are published under. */
    private const string LANG_TAG = 'audit-log-lang';

    /** @var list<string> File names of every shipped migration, in the order they run. */
    private const array SHIPPED_MIGRATIONS = [
        '2026_11_02_000000_create_audit_log_entries_table.php',
        '2026_11_02_000100_create_audit_log_outbox_table.php',
        '2026_11_02_000200_create_audit_log_deliveries_table.php',
        '2026_11_02_000300_create_audit_log_checkpoints_table.php',
        '2026_11_02_000400_create_audit_log_checkpoint_members_table.php',
        '2026_11_02_000500_create_audit_log_integrity_state_table.php',
        '2026_11_02_000600_create_audit_log_artifacts_table.php',
        '2026_11_02_000700_create_audit_log_lifecycle_table.php',
        '2026_11_02_000800_create_audit_log_holds_table.php',
        '2026_11_02_000900_create_audit_log_lifecycle_lock_table.php',
        '2026_11_02_001000_create_audit_log_import_batches_table.php',
        '2026_11_02_001100_create_audit_log_subject_keys_table.php',
        '2026_11_02_001200_create_audit_log_owner_erasures_table.php',
        '2026_11_02_001300_create_audit_log_key_uses_table.php',
    ];

    /** @var array<string, class-string> Each command the provider registers, by name, with its class. */
    private const array COMMANDS = [
        'audit-log:check'     => CheckCommand::class,
        'audit-log:drain'     => DrainCommand::class,
        'audit-log:erase'     => EraseCommand::class,
        'audit-log:export'    => ExportCommand::class,
        'audit-log:hold'      => HoldCommand::class,
        'audit-log:holds'     => HoldsCommand::class,
        'audit-log:import'    => ImportCommand::class,
        'audit-log:keys'      => KeysCommand::class,
        'audit-log:prune'     => PruneCommand::class,
        'audit-log:reconcile' => ReconcileCommand::class,
        'audit-log:reinstate' => ReinstateCommand::class,
        'audit-log:release'   => ReleaseCommand::class,
        'audit-log:replay'    => ReplayCommand::class,
        'audit-log:rewrap'    => RewrapCommand::class,
        'audit-log:seal'      => SealCommand::class,
        'audit-log:verify'    => VerifyCommand::class,
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

        $this->provider()->register();

        self::assertSame('audit', $config->get('audit-log.storage.connection'));
    }

    /**
     * The configuration file is published under the package's tag.
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

        $running = new \ReflectionProperty(Application::class, 'isRunningInConsole');
        $running->setValue($this->app, false);

        $this->provider()->boot();

        self::assertSame([], ServiceProvider::pathsToPublish(AuditLogServiceProvider::class));
    }

    /**
     * The migrations tag publishes every shipped migration under its own name.
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
     * The provider publishes exactly the shipped migrations, in run order.
     *
     * @return void
     */
    public function testTheMigrationsAreEveryShippedMigration(): void
    {
        $published = (new \ReflectionClassConstant(AuditLogServiceProvider::class, 'MIGRATIONS'))->getValue();
        $shipped   = array_map(basename(...), glob(dirname(__DIR__, 2) . '/database/migrations/*.php') ?: []);

        sort($shipped, SORT_STRING);

        self::assertSame(self::SHIPPED_MIGRATIONS, $published);
        self::assertSame($shipped, $published);
    }

    /**
     * The provider never loads the package's migrations.
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
     * Rows of `[name, class]`: each command the provider registers.
     *
     * @return iterable<string, array{0: string, 1: class-string}>
     */
    public static function provideCommands(): iterable
    {
        foreach (self::COMMANDS as $name => $class) {
            yield $name => [$name, $class];
        }
    }

    /**
     * Each command is registered in the console as its own class.
     *
     * @param  string  $name
     * @param  class-string  $class
     * @return void
     */
    #[DataProvider('provideCommands')]
    public function testEachCommandIsRegistered(string $name, string $class): void
    {
        self::assertArrayHasKey($name, Artisan::all());
        self::assertInstanceOf($class, Artisan::all()[$name]);
    }

    /**
     * The package registers exactly its sixteen commands under its prefix.
     *
     * @return void
     */
    public function testThePackageRegistersExactlyItsSixteenCommands(): void
    {
        $names = array_values(array_filter(array_keys(Artisan::all()), static fn (string $name): bool => str_starts_with($name, 'audit-log:')));

        sort($names, SORT_STRING);

        self::assertSame([
            'audit-log:check',
            'audit-log:drain',
            'audit-log:erase',
            'audit-log:export',
            'audit-log:hold',
            'audit-log:holds',
            'audit-log:import',
            'audit-log:keys',
            'audit-log:prune',
            'audit-log:reconcile',
            'audit-log:reinstate',
            'audit-log:release',
            'audit-log:replay',
            'audit-log:rewrap',
            'audit-log:seal',
            'audit-log:verify',
        ], $names);
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
     * Rows of `[abstract, the default it resolves to]` for each shared binding.
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
            'the key wrapper'        => [KeyWrapper::class, LocalKeyWrapper::class],
            'the retention policy'   => [RetentionPolicy::class, ConfiguredRetentionPolicy::class],
            'the prune ledger'       => [PruneLedger::class, JournalPruneLedger::class],
            'the access policy'      => [AuditAccessPolicy::class, DenyAllPolicy::class],
            'the catalogue'          => [EventCatalogue::class, EventCatalogue::class],
            'the contributors'       => [ContributorRegistry::class, ContributorRegistry::class],
            'the event mappers'      => [MapperRegistry::class, MapperRegistry::class],
            'the model watcher'      => [ModelWatcher::class, ModelWatcher::class],
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
     * The field encrypter and reader are new per resolution, so no data key
     * outlives its use.
     *
     * @return void
     */
    public function testTheEncrypterAndReaderAreBoundAfreshPerResolution(): void
    {
        $app = $this->app;

        assert($app !== null);

        $encrypter = app(FieldEncrypter::class);
        $reader    = app(FieldReader::class);

        self::assertInstanceOf(SubjectKeyEncrypter::class, $encrypter);
        self::assertInstanceOf(SubjectKeyFieldReader::class, $reader);
        self::assertNotSame($encrypter, app(FieldEncrypter::class));
        self::assertNotSame($reader, app(FieldReader::class));
        self::assertFalse($app->isShared(FieldEncrypter::class));
        self::assertFalse($app->isShared(FieldReader::class));
    }

    /**
     * The key wrapper is shared, as it holds no key and reads the ring on every
     * wrap.
     *
     * @return void
     */
    public function testTheWrapperIsBound(): void
    {
        $wrapper = app(KeyWrapper::class);

        self::assertInstanceOf(LocalKeyWrapper::class, $wrapper);
        self::assertSame($wrapper, app(KeyWrapper::class));
        self::assertTrue($this->app?->isShared(KeyWrapper::class));
        self::assertStringStartsWith('d-', $wrapper->currentKeyId());

        $config = app(ConfigRepository::class);

        $config->set('audit-log.privacy.keys', ['w2026' => str_repeat('w', 32)]);
        $config->set('audit-log.privacy.current', 'w2026');

        self::assertSame('w2026', $wrapper->currentKeyId());
    }

    /**
     * A `NoFieldEncrypter` bound before the provider registers is kept.
     *
     * @return void
     */
    public function testAnEncrypterBoundEarlierIsKept(): void
    {
        $this->app?->bind(FieldEncrypter::class, NoFieldEncrypter::class);

        $this->provider()->register();

        self::assertInstanceOf(NoFieldEncrypter::class, app(FieldEncrypter::class));
    }

    /**
     * The anchor is the null anchor by default, made afresh on each resolution.
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
     * The anchor follows the settings and fails closed when resolved.
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
     * The schedule holds sealing, the sweep and verification; shipped retention
     * schedules no prune.
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
     * Retention shorter than forever also schedules the daily prune.
     *
     * @return void
     */
    #[DefineEnvironment('keepSecurityForAYear')]
    public function testTheScheduleHoldsThePruneOnceRetentionKeepsLess(): void
    {
        self::assertSame([
            'audit-log:seal'                          => '*/5 * * * *',
            'audit-log:seal --sweep'                  => '15 3 * * *',
            'audit-log:verify --strict --sweep-first' => '45 3 * * *',
            'audit-log:prune'                         => '30 3 * * *',
        ], self::packageRuns(app(Schedule::class)));
    }

    /**
     * Outside the console the provider schedules nothing.
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
     * A malformed schedule stops neither boot nor the other runs, and is
     * reported.
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
     * The trail and the describer are new per resolution.
     *
     * @return void
     */
    public function testTheReadPathIsNeverShared(): void
    {
        self::assertNotSame(app(AuditTrail::class), app(AuditTrail::class));
        self::assertNotSame(app(Describer::class), app(Describer::class));
    }

    /**
     * A policy and field reader bound before the provider registers are kept.
     *
     * @return void
     */
    public function testAnEarlierPolicyAndFieldReaderAreKept(): void
    {
        $policy = new DenyAllPolicy;
        $reader = new SealedFieldReader;

        $this->app?->instance(AuditAccessPolicy::class, $policy);
        $this->app?->instance(FieldReader::class, $reader);

        $this->provider()->register();

        self::assertSame($policy, app(AuditAccessPolicy::class));
        self::assertSame($reader, app(FieldReader::class));
    }

    /**
     * isPackageDefault() is true only while the contract resolves to the
     * package's default.
     *
     * @return void
     */
    public function testIsPackageDefaultTellsThePackagesDefaultFromAnyOther(): void
    {
        $app = $this->app;

        self::assertInstanceOf(Container::class, $app);
        self::assertTrue(AuditLogServiceProvider::isPackageDefault($app, AuditAccessPolicy::class));
        self::assertTrue(AuditLogServiceProvider::isPackageDefault($app, FieldReader::class));
        self::assertFalse(AuditLogServiceProvider::isPackageDefault($app, 'audit-log.nothing-bound-here'));
        self::assertFalse(AuditLogServiceProvider::isPackageDefault($app, Recorder::class), 'A class bound to itself is no default.');

        app(AuditAccessPolicy::class);
        app(FieldReader::class);

        self::assertTrue(AuditLogServiceProvider::isPackageDefault($app, AuditAccessPolicy::class), 'A resolved shared default is still the default.');
        self::assertTrue(AuditLogServiceProvider::isPackageDefault($app, FieldReader::class));

        $app->instance(AuditAccessPolicy::class, new ClosurePolicy(static fn (): AccessScope => AccessScope::all()));
        $app->instance(FieldReader::class, new SealedFieldReader);

        self::assertFalse(AuditLogServiceProvider::isPackageDefault($app, AuditAccessPolicy::class), 'Another instance held over the default is not the default.');
        self::assertFalse(AuditLogServiceProvider::isPackageDefault($app, FieldReader::class), 'Any instance held over a transient default is not the default.');

        $app->singleton(AuditAccessPolicy::class, DenyAllPolicy::class);

        self::assertFalse(AuditLogServiceProvider::isPackageDefault($app, AuditAccessPolicy::class), 'The default class bound by the application is not the package\'s binding.');
    }

    /**
     * The runtime state is scoped: one instance per scope, forgotten as Octane
     * and queue workers do.
     *
     * @return void
     */
    public function testTheRuntimeStateIsScoped(): void
    {
        $frames   = app(ExecutionFrames::class);
        $identity = app(RequestIdentity::class);
        $latch    = app(ReportLatch::class);
        $guard    = app(WriteGuard::class);
        $reads    = app(ReadGuard::class);
        $queue    = app(CommitQueue::class);

        self::assertSame($latch, app(ReportLatch::class));
        self::assertSame($reads, app(ReadGuard::class));
        self::assertTrue($reads->during(static fn (): bool => app(ReadGuard::class)->isActive()));

        $this->app?->forgetScopedInstances();

        self::assertNotSame($frames, app(ExecutionFrames::class));
        self::assertNotSame($identity, app(RequestIdentity::class));
        self::assertNotSame($latch, app(ReportLatch::class));
        self::assertNotSame($guard, app(WriteGuard::class));
        self::assertNotSame($reads, app(ReadGuard::class));
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
        $mappers      = app(MapperRegistry::class);
        $watcher      = app(ModelWatcher::class);

        $this->app?->forgetScopedInstances();

        self::assertSame($recorder, app(Recorder::class));
        self::assertSame($catalogue, app(EventCatalogue::class));
        self::assertSame($contributors, app(ContributorRegistry::class));
        self::assertSame($mappers, app(MapperRegistry::class));
        self::assertSame($watcher, app(ModelWatcher::class));
    }

    /**
     * The capture state is scoped, so an event claimed in one request is free
     * in the next.
     *
     * @return void
     */
    public function testTheCaptureStateIsScoped(): void
    {
        $captured = app(CapturedEvents::class);
        $event    = new \stdClass;

        self::assertSame($captured, app(CapturedEvents::class));
        self::assertTrue($captured->claims($event));

        $this->app?->forgetScopedInstances();

        self::assertNotSame($captured, app(CapturedEvents::class));
        self::assertFalse(app(CapturedEvents::class)->isClaimed($event));
    }

    /**
     * The record id generator is scoped, so ids of one instant follow each
     * other within a request and the next request starts afresh.
     *
     * @return void
     */
    public function testTheRecordIdGeneratorIsScoped(): void
    {
        $generator = app(UuidV7::class);

        self::assertSame($generator, app(UuidV7::class));

        $this->app?->forgetScopedInstances();

        self::assertNotSame($generator, app(UuidV7::class));
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
            'a sign-in'          => [Login::class, RecordLaravelAuthEvent::class],
            'a failed sign-in'   => [Failed::class, RecordLaravelAuthEvent::class],
            'a lockout'          => [Lockout::class, RecordLaravelAuthEvent::class],
            'a sign-out'         => [Logout::class, RecordLaravelAuthEvent::class],
            'a device sign-out'  => [CurrentDeviceLogout::class, RecordLaravelAuthEvent::class],
            'other devices out'  => [OtherDeviceLogout::class, RecordLaravelAuthEvent::class],
            'a registration'     => [Registered::class, RecordLaravelAuthEvent::class],
            'a verification'     => [Verified::class, RecordLaravelAuthEvent::class],
            'a password reset'   => [PasswordReset::class, RecordLaravelAuthEvent::class],
            'a reset link sent'  => [PasswordResetLinkSent::class, RecordLaravelAuthEvent::class],
            'a Gate evaluation'  => [GateEvaluated::class, RecordGateDenial::class],
        ];
    }

    /**
     * Each event has the package's listener registered once.
     *
     * @param  class-string  $event
     * @param  class-string  $listener
     * @return void
     */
    #[DataProvider('provideListeners')]
    public function testListenersRegisterOnce(string $event, string $listener): void
    {
        self::assertSame([$listener], array_values(array_filter(
            self::listenersFor(Event::getRawListeners(), $event),
            static fn (mixed $registered): bool => is_string($registered) && str_starts_with($registered, 'SineMacula\\'),
        )));
    }

    /**
     * Rows of `[listener]`: every listener that captures events.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideCaptureListeners(): iterable
    {
        yield from [
            'the mapped events'   => [CaptureMappedEvent::class],
            'the auth events'     => [RecordLaravelAuthEvent::class],
            'the Gate denials'    => [RecordGateDenial::class],
            'the watched changes' => [RecordModelChange::class],
        ];
    }

    /**
     * A capture listener holds nothing, so the Octane worker container leaves
     * nothing in it.
     *
     * @param  class-string  $listener
     * @return void
     */
    #[DataProvider('provideCaptureListeners')]
    public function testACaptureListenerHoldsNothing(string $listener): void
    {
        $class = new \ReflectionClass($listener);

        self::assertNull($class->getConstructor());
        self::assertSame([], $class->getProperties());
        self::assertFalse($this->app?->bound($listener));
    }

    /**
     * A capture listener captures in the current container, as Octane's sandbox
     * is.
     *
     * @return void
     */
    public function testACaptureListenerCapturesWithTheCurrentContainer(): void
    {
        $root = $this->app;

        assert($root instanceof Application);

        AuditLog::fake();

        $listener = $root->make(RecordLaravelAuthEvent::class);
        $sandbox  = clone $root;
        $captured = new CapturedEvents;
        $event    = new Registered(new StubAuthUser);

        $sandbox->instance(CaptureCoordinator::class, new CaptureCoordinator($sandbox));
        $sandbox->instance(CapturedEvents::class, $captured);

        Container::setInstance($sandbox);

        try {
            $listener->handle($event);
        } finally {
            Container::setInstance($root);
        }

        self::assertTrue($captured->isClaimed($event));
        self::assertFalse($root->make(CapturedEvents::class)->isClaimed($event));
    }

    /**
     * Unrecorded events are never listened to, and nothing routes mapped events
     * until one is mapped.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testNoOtherCaptureListenerIsRegistered(): void
    {
        foreach ([Attempting::class, Validated::class, Authenticated::class] as $event) {
            self::assertSame([], array_values(array_filter(
                self::listenersFor(Event::getRawListeners(), $event),
                static fn (mixed $registered): bool => is_string($registered) && str_starts_with($registered, 'SineMacula\\'),
            )), "{$event} has a listener of the package's.");
        }

        $dispatcher = app('events');

        self::assertInstanceOf(Dispatcher::class, $dispatcher);

        $wildcards = (new \ReflectionProperty(Dispatcher::class, 'wildcards'))->getValue($dispatcher);

        self::assertIsArray($wildcards);
        self::assertNotContains(CaptureMappedEvent::class, self::listenersFor($wildcards, '*'));
    }

    /**
     * The commit probe listens once, catching an aborted PostgreSQL transaction
     * early.
     *
     * @return void
     */
    public function testTheCommitProbeListensOnce(): void
    {
        self::assertSame([[CommitQueue::class, 'probe']], array_values(array_filter(
            self::listenersFor(Event::getRawListeners(), TransactionCommitting::class),
            static fn (mixed $registered): bool => is_array($registered) && is_string($registered[0] ?? null) && str_starts_with($registered[0], 'SineMacula\\'),
        )));
    }

    /**
     * The commit queue hears each rollback once.
     *
     * @return void
     */
    public function testTheRollbackReleaseListensOnce(): void
    {
        self::assertSame([[CommitQueue::class, 'release']], array_values(array_filter(
            self::listenersFor(Event::getRawListeners(), TransactionRolledBack::class),
            static fn (mixed $registered): bool => is_array($registered) && is_string($registered[0] ?? null) && str_starts_with($registered[0], 'SineMacula\\'),
        )));
    }

    /**
     * The frame middleware heads the global stack once, so other middleware has
     * its request.
     *
     * @return void
     */
    public function testTheHttpFrameMiddlewareIsFirstAndOnce(): void
    {
        $kernel = app(HttpKernel::class);

        $middleware = $kernel->getGlobalMiddleware();

        self::assertSame(EnterHttpFrame::class, $middleware[0] ?? null);
        self::assertCount(1, array_keys($middleware, EnterHttpFrame::class, true));

        $this->app?->register($this->provider(), true);

        self::assertCount(1, array_keys($kernel->getGlobalMiddleware(), EnterHttpFrame::class, true));
    }

    /**
     * The provider adds no route or view path; local file serving is off as it
     * adds routes.
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

        $source = realpath(__DIR__ . '/../../src');

        self::assertIsString($source);
        self::assertNotSame('', $source);

        self::assertCount(0, Route::getRoutes()->getRoutes());
        self::assertArrayNotHasKey('audit-log', $finder->getHints());

        foreach ($paths as $path) {
            self::assertStringStartsNotWith($source, (string) realpath($path));
        }
    }

    /**
     * The package's translations are loaded under their namespace.
     *
     * @return void
     */
    public function testTheTranslationsAreLoaded(): void
    {
        self::assertSame('Signed in', __('audit-log::codes.authentication.signed_in'));
        self::assertSame('Audit trail exported', __('audit-log::codes.audit_log.trail_exported'));
    }

    /**
     * The translations tag publishes the language directory to the vendor
     * overrides.
     *
     * @return void
     */
    public function testTheTranslationsArePublishedUnderTheirTag(): void
    {
        $paths = ServiceProvider::pathsToPublish(AuditLogServiceProvider::class, self::LANG_TAG);

        self::assertCount(1, $paths);
        self::assertSame(realpath(__DIR__ . '/../../lang'), realpath((string) array_key_first($paths)));
        self::assertSame(lang_path('vendor/audit-log'), array_values($paths)[0]);
        self::assertContains(self::LANG_TAG, ServiceProvider::publishableGroups());
    }

    /**
     * Booting never resolves the translator.
     *
     * @return void
     */
    public function testBootingReadsNoTranslation(): void
    {
        self::assertFalse($this->app?->resolved('translator'));

        $this->provider()->boot();

        self::assertFalse($this->app->resolved('translator'));
        self::assertSame('Signed in', __('audit-log::codes.authentication.signed_in'));
    }

    /**
     * Every code of the package's own reads is in the catalogue from the start.
     *
     * @return void
     */
    public function testThePackageReadCodesAreThereFromTheStart(): void
    {
        $catalogue = app(EventCatalogue::class);

        foreach (PackageActivity::cases() as $activity) {
            $code = EventCode::package($activity);

            self::assertTrue($catalogue->isRegistered($code), "{$activity->value} is not defined.");
            self::assertTrue($catalogue->definitionFor($code)->equals($activity->definition()), "{$activity->value} is defined differently.");
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
     * Once booted, the event mappers and model watcher refuse more.
     *
     * @return void
     */
    public function testMappingAndWatchingAreFrozenOnceBooted(): void
    {
        self::assertTrue(app(MapperRegistry::class)->isFrozen());
        self::assertTrue(app(ModelWatcher::class)->isFrozen());
    }

    /**
     * Every package code is defined at boot.
     *
     * @return void
     */
    public function testThePackageCodesAreDefinedAtBoot(): void
    {
        $catalogue = app(EventCatalogue::class);

        foreach (CapturedActivity::cases() as $activity) {
            $code = EventCode::of($activity);

            self::assertTrue($catalogue->isRegistered($code), "{$activity->value} is not defined.");
            self::assertTrue($catalogue->definitionFor($code)->equals($activity->definition()), "{$activity->value} is defined differently.");
        }
    }

    /**
     * A package code already defined differently fails the boot, naming the
     * code.
     *
     * @return void
     */
    public function testADifferentDefinitionOfAPackageCodeIsRefusedAtBoot(): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define(EventDefinition::for(CapturedActivity::SIGNED_IN->value)->category('accounts'));

        $this->app?->instance(EventCatalogue::class, $catalogue);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The event code `authentication.signed_in` is already defined differently; a code has one definition.');

        (new \ReflectionMethod(AuditLogServiceProvider::class, 'registerCapture'))->invoke($this->provider());
    }

    /**
     * Booting the provider again defines nothing more and is not refused.
     *
     * @return void
     */
    public function testBootingAgainAfterBootDefinesNothingMore(): void
    {
        $catalogue = app(EventCatalogue::class);

        self::assertTrue($catalogue->isFrozen());

        (new \ReflectionMethod(AuditLogServiceProvider::class, 'registerCapture'))->invoke($this->provider());

        self::assertSame($catalogue, app(EventCatalogue::class));
        self::assertTrue($catalogue->isRegistered(EventCode::of(CapturedActivity::SIGNED_IN)));
    }

    /**
     * Mapping and watching from a provider's `boot()` are accepted and
     * captured.
     *
     * @return void
     */
    #[DefineEnvironment('mapAndWatchInAProvidersBoot')]
    public function testMappingAndWatchingInAProvidersBootAreAccepted(): void
    {
        $fake = FakeAuditStore::fake();

        self::assertTrue(app(MapperRegistry::class)->isFrozen());
        self::assertSame(PortalMapper::class, app(MapperRegistry::class)->mapperFor(PortalSignedIn::class));
        self::assertSame('line', app(ModelWatcher::class)->watchFor(PlainLine::class)?->as);
        self::assertTrue(Event::hasListeners('eloquent.created: ' . PlainLine::class));

        Event::dispatch(new PortalSignedIn('7'));

        self::assertSame([PortalMapper::CODE], array_map(static fn (AuditRecord $record): string => $record->event, $fake->recorded()));
    }

    /**
     * Booting reads no capture setting, so malformed ones still boot.
     *
     * @return void
     */
    #[DefineEnvironment('malformEveryCaptureSetting')]
    public function testNoCaptureListenerReadsASettingAtBoot(): void
    {
        self::assertTrue($this->app?->isBooted());
        self::assertTrue(app(MapperRegistry::class)->isFrozen());
        self::assertTrue(app(EventCatalogue::class)->isRegistered(EventCode::of(CapturedActivity::GATE_DENIED)));
        self::assertSame(1, Artisan::call('audit-log:check'));
    }

    /**
     * Definitions and contributors registered from a provider's `boot()` are
     * kept.
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
     * Booting reads no setting that could stop it.
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
     * Register an enum and a contributor from another provider's `boot()`.
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
     * Map an event and watch a model from another provider's `boot()`.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function mapAndWatchInAProvidersBoot(Application $app): void
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

                $recorder->map(PortalSignedIn::class, PortalMapper::class);
                $recorder->watch(PlainLine::class, as: 'line', fields: ['description']);
            }
        });
    }

    /**
     * Give every capture setting a malformed value.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function malformEveryCaptureSetting(Application $app): void
    {
        $app->make(ConfigRepository::class)->set([
            'audit-log.capture.laravel.except_guards'  => 'web',
            'audit-log.capture.laravel.identifier_key' => 'e mail',
            'audit-log.capture.gate.enabled'           => 'yes',
            'audit-log.capture.gate.only_abilities'    => [],
            'audit-log.capture.gate.except_abilities'  => 'update',
            'audit-log.capture.gate.reason_codes'      => ['Not A Code'],
            'audit-log.capture.bulk.max_members'       => 0,
            'audit-log.capture.bulk.max_bytes'         => 'many',
        ]);
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
     * Keep the entries of the `security` category for a year.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function keepSecurityForAYear(Application $app): void
    {
        $app->make(ConfigRepository::class)->set('audit-log.retention.categories', ['security' => 365]);
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
        // The provider must load no migration, which this class checks
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
     * The package's scheduled commands with their cron expressions.
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
     * The package command a scheduled event runs, or `null` for any other.
     *
     * @param  \Illuminate\Console\Scheduling\Event  $event
     * @return ?string
     */
    private static function commandOf(ScheduledEvent $event): ?string
    {
        return preg_match('/\'artisan\' (audit-log:.+)\z/', (string) $event->command, $matches) === 1 ? $matches[1] : null;
    }

    /**
     * A fresh instance of the package's provider on the test's application.
     *
     * @return \SineMacula\Laravel\AuditLog\AuditLogServiceProvider
     */
    private function provider(): AuditLogServiceProvider
    {
        $app = $this->app;

        self::assertNotNull($app);

        return new AuditLogServiceProvider($app);
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

            unset($value[AuditLogServiceProvider::class], $value[self::CONFIG_TAG], $value[self::MIGRATIONS_TAG], $value[self::LANG_TAG]);

            $paths->setValue(null, $value);
        }
    }
}
