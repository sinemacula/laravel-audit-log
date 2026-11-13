<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog;

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
use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Log\Context\Events\ContextDehydrating;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\AuditLog\Access\DenyAllPolicy;
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
use SineMacula\Laravel\AuditLog\Console\IntegritySchedule;
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
use SineMacula\Laravel\AuditLog\Delivery\CommitQueue;
use SineMacula\Laravel\AuditLog\Http\Middleware\EnterHttpFrame;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorFactory;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalPruneLedger;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Listeners\RecordGateDenial;
use SineMacula\Laravel\AuditLog\Listeners\RecordLaravelAuthEvent;
use SineMacula\Laravel\AuditLog\Listeners\TrackCommandFrames;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Querying\Describer;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\ReadGuard;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Support\SystemClock;
use SineMacula\Laravel\AuditLog\Support\UuidV7;

/**
 * Registers the package's bindings, listeners, middleware, commands, schedule,
 * translations and publishing tags; it adds no route.
 *
 * Registration is frozen once the application has booted, and booting issues no
 * query and reads no setting that could stop it, so a malformed one reaches
 * `audit-log:check`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuditLogServiceProvider extends ServiceProvider
{
    /** @var string The key the package's configuration is merged under. */
    public const string CONFIG = 'audit-log';

    /** @var array<class-string, class-string> Each public contract with a shared default, and that default's class. */
    private const array SHARED_DEFAULTS = [
        Clock::class             => SystemClock::class,
        AuditStore::class        => DatabaseAuditStore::class,
        KeyWrapper::class        => LocalKeyWrapper::class,
        RetentionPolicy::class   => ConfiguredRetentionPolicy::class,
        PruneLedger::class       => JournalPruneLedger::class,
        AuditAccessPolicy::class => DenyAllPolicy::class,
    ];

    /** @var list<string> File names of the shipped migrations, published under the `audit-log-migrations` tag. */
    private const array MIGRATIONS = [
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

    /**
     * Whether the contract is still bound by this provider and any instance
     * held under it is exactly the default's class.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  string  $contract
     * @return bool
     */
    public static function isPackageDefault(Container $container, string $contract): bool
    {
        $concrete = $container->getBindings()[$contract]['concrete'] ?? null;

        if (!$concrete instanceof \Closure || (new \ReflectionFunction($concrete))->getClosureScopeClass()?->getName() !== self::class) {
            return false;
        }

        // Laravel offers no public way to read an instance held over a binding
        $held = \Closure::bind(static fn (Container $container): ?object => $container->instances[$contract] ?? null, null, Container::class)($container);

        return $held === null || $held::class === (self::SHARED_DEFAULTS[$contract] ?? null);
    }

    /**
     * Register the package's defaults: a binding made before this provider
     * registers is kept, and one made after replaces the default.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/audit-log.php',
            self::CONFIG,
        );

        foreach (self::SHARED_DEFAULTS as $contract => $default) {
            $this->app->singletonIf($contract, static fn (Application $app): object => $app->make($default));
        }

        $this->app->singletonIf(IntegritySettings::class);
        $this->app->singletonIf(KeyRing::class);
        $this->app->bindIf(FieldEncrypter::class, static fn (Application $app): FieldEncrypter => $app->make(SubjectKeyEncrypter::class));
        $this->app->bindIf(FieldReader::class, static fn (Application $app): FieldReader => $app->make(SubjectKeyFieldReader::class));
        $this->app->bindIf(CheckpointAnchor::class, static fn (Application $app): CheckpointAnchor => $app->make(AnchorFactory::class)->make());
        $this->app->singletonIf(EventCatalogue::class);
        $this->app->singletonIf(ContributorRegistry::class);
        $this->app->singletonIf(MapperRegistry::class);
        $this->app->singletonIf(ModelWatcher::class);
        $this->app->singletonIf(Recorder::class);
        $this->app->scopedIf(ExecutionFrames::class);
        $this->app->scopedIf(RequestIdentity::class);
        $this->app->scopedIf(ReportLatch::class);
        $this->app->scopedIf(WriteGuard::class);
        $this->app->scopedIf(ReadGuard::class);
        $this->app->scopedIf(CommitQueue::class);
        $this->app->scopedIf(CapturedEvents::class);
        $this->app->scopedIf(UuidV7::class);
    }

    /**
     * Bootstrap framework integrations.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->registerTranslations();
        $this->registerPublishing();
        $this->registerCommands();
        $this->registerSchedule();
        $this->registerListeners();
        $this->registerCapture();
        $this->registerHttpFrame();
        $this->freezeRegistrationOnceBooted();
    }

    /**
     * Publish the configuration, the migrations and the translations under
     * their `audit-log-*` tags, in the console. The migrations are never loaded
     * from the package, so the application owns them.
     *
     * @return void
     */
    protected function registerPublishing(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__ . '/../config/audit-log.php' => config_path('audit-log.php'),
        ], 'audit-log-config');

        $migrations = [];

        foreach (self::MIGRATIONS as $migration) {
            $migrations[__DIR__ . '/../database/migrations/' . $migration] = database_path('migrations/' . $migration);
        }

        $this->publishes($migrations, 'audit-log-migrations');

        $this->publishes([
            dirname(__DIR__) . '/lang' => lang_path('vendor/audit-log'),
        ], 'audit-log-lang');
    }

    /**
     * Load the package's translations under the `audit-log` namespace once the
     * translator is resolved, so booting reads none of them.
     *
     * @return void
     */
    protected function registerTranslations(): void
    {
        $this->loadTranslationsFrom(dirname(__DIR__) . '/lang', Describer::NAMESPACE);
    }

    /**
     * Register the package's console commands when running in the console.
     *
     * @return void
     */
    protected function registerCommands(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->commands([
            CheckCommand::class,
            DrainCommand::class,
            EraseCommand::class,
            ExportCommand::class,
            HoldCommand::class,
            HoldsCommand::class,
            ImportCommand::class,
            KeysCommand::class,
            PruneCommand::class,
            ReconcileCommand::class,
            ReinstateCommand::class,
            ReleaseCommand::class,
            ReplayCommand::class,
            RewrapCommand::class,
            SealCommand::class,
            VerifyCommand::class,
        ]);
    }

    /**
     * Register the integrity schedule once the application resolves its
     * schedule, in the console.
     *
     * @return void
     */
    protected function registerSchedule(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->callAfterResolving(Schedule::class, static function (Schedule $schedule, Application $app): void {
            $app->make(IntegritySchedule::class)->register($schedule);
        });
    }

    /**
     * Register the listeners that track execution frames, carry context into
     * jobs and watch transactions. The frame-ending ones are added once booted,
     * after every other listener, so a record made on a job's or a command's
     * end is still inside its frame.
     *
     * @return void
     */
    protected function registerListeners(): void
    {
        Event::listen(CommandStarting::class, TrackCommandFrames::class);
        Event::listen(JobProcessing::class, TrackJobFrames::class);
        Event::listen(ContextDehydrating::class, CarryContextIntoJobs::class);
        Event::listen(TransactionCommitting::class, [CommitQueue::class, 'probe']);
        Event::listen(TransactionRolledBack::class, [CommitQueue::class, 'release']);

        $this->app->booted(static function (): void {
            Event::listen(CommandFinished::class, TrackCommandFrames::class);
            Event::listen([JobProcessed::class, JobFailed::class, JobExceptionOccurred::class], TrackJobFrames::class);
        });
    }

    /**
     * Listen for Laravel's authentication events and Gate evaluations, and
     * define the package's own codes unless an earlier boot froze the
     * catalogue.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    protected function registerCapture(): void
    {
        Event::listen([
            Login::class,
            Failed::class,
            Lockout::class,
            Logout::class,
            CurrentDeviceLogout::class,
            OtherDeviceLogout::class,
            Registered::class,
            Verified::class,
            PasswordReset::class,
            PasswordResetLinkSent::class,
        ], RecordLaravelAuthEvent::class);

        Event::listen(GateEvaluated::class, RecordGateDenial::class);

        $catalogue = $this->app->make(EventCatalogue::class);

        if ($catalogue->isFrozen()) {
            return;
        }

        $catalogue->define(CapturedActivity::class);
    }

    /**
     * Put the middleware that enters an HTTP frame first on the kernel's global
     * stack, so a record in any other global middleware has its request.
     *
     * @return void
     */
    protected function registerHttpFrame(): void
    {
        $this->callAfterResolving(HttpKernel::class, static function (mixed $kernel): void {

            if (!$kernel instanceof Kernel) {
                return;
            }

            $kernel->prependMiddleware(EnterHttpFrame::class);
        });
    }

    /**
     * Freeze the catalogue, the contributors, the event mappers and the model
     * watcher once the application has booted.
     *
     * @return void
     */
    protected function freezeRegistrationOnceBooted(): void
    {
        $this->app->booted(static function (Application $app): void {
            $app->make(EventCatalogue::class)->freeze();
            $app->make(ContributorRegistry::class)->freeze();
            $app->make(MapperRegistry::class)->freeze();
            $app->make(ModelWatcher::class)->freeze();
        });
    }
}
