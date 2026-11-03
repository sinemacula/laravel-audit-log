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
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Log\Context\Events\ContextDehydrating;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Capture\ModelWatcher;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use SineMacula\Laravel\AuditLog\Console\DrainCommand;
use SineMacula\Laravel\AuditLog\Console\IntegritySchedule;
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
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorFactory;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
use SineMacula\Laravel\AuditLog\Listeners\RecordGateDenial;
use SineMacula\Laravel\AuditLog\Listeners\RecordLaravelAuthEvent;
use SineMacula\Laravel\AuditLog\Listeners\TrackCommandFrames;
use SineMacula\Laravel\AuditLog\Listeners\TrackJobFrames;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Support\SystemClock;

/**
 * Package service provider: registers the package's configuration, its clock,
 * integrity settings, key ring, store and field encrypter, the anchor seals are
 * kept in and the prune ledger, the recorder with its catalogue, contributors,
 * event mappers and model watcher, the scoped runtime and capture state, the
 * listeners that track execution frames and carry context into jobs, the
 * listeners that capture Laravel's authentication events and Gate denials, the
 * package's own event codes, the global middleware that enters an HTTP frame,
 * its publishing tags (the configuration and the migrations, the artifacts
 * table's among them, which it never loads itself) and the `audit-log:check`,
 * `audit-log:drain`, `audit-log:replay`, `audit-log:seal` and
 * `audit-log:verify` console commands. It adds no route.
 *
 * In the console it schedules sealing, the sweep and a strict verification,
 * each of which its schedule setting can turn off, once the application
 * resolves its schedule; a malformed schedule is reported and schedules nothing
 * for that run.
 *
 * Binding `AuditStore` is the only seam for where records go: there is no
 * manager and no driver registry. The delivery classes are autowired for each
 * capture, so none outlives a request. The anchor is made from the settings on
 * each resolution, so a changed setting takes effect without a restart.
 *
 * The package's own codes are defined while it boots, so an application or an
 * integration that defines one of them differently is refused at boot. The
 * listener that routes mapped events is added by the first mapping, never by
 * the provider, so an application that maps nothing pays nothing for it.
 *
 * Registration of definitions, contributors, event mappers and watched models
 * is frozen once the application has booted, so a long-lived worker registers
 * once. Booting still issues no query and reads no setting that could stop it,
 * so a malformed one, a capture setting included, reaches `audit-log:check`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AuditLogServiceProvider extends ServiceProvider
{
    /** @var string The key the package's configuration is merged under. */
    public const string CONFIG = 'audit-log';

    /** @var list<string> File names of the shipped migrations, published under the `audit-log-migrations` tag. */
    private const array MIGRATIONS = [
        '2026_11_02_000000_create_audit_log_entries_table.php',
        '2026_11_02_000100_create_audit_log_outbox_table.php',
        '2026_11_02_000200_create_audit_log_deliveries_table.php',
        '2026_11_02_000300_create_audit_log_checkpoints_table.php',
        '2026_11_02_000400_create_audit_log_checkpoint_members_table.php',
        '2026_11_02_000500_create_audit_log_integrity_state_table.php',
        '2026_11_02_000600_create_audit_log_artifacts_table.php',
    ];

    /**
     * Register container bindings.
     *
     * Every binding is a default: one that the application or another package
     * made before this provider registers is kept, so a store, a clock or an
     * encrypter bound earlier is never replaced by the package's (an
     * `AuditStore` by `DatabaseAuditStore`, a `Clock` by `SystemClock`, a
     * `FieldEncrypter` by `NoFieldEncrypter`, a `PruneLedger` by
     * `NullPruneLedger`, a `CheckpointAnchor` by the configured anchor), and
     * one made after replaces the default, as any later binding does.
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

        $this->app->singletonIf(Clock::class, SystemClock::class);
        $this->app->singletonIf(IntegritySettings::class);
        $this->app->singletonIf(KeyRing::class);
        $this->app->singletonIf(AuditStore::class, DatabaseAuditStore::class);
        $this->app->singletonIf(FieldEncrypter::class, NoFieldEncrypter::class);
        $this->app->singletonIf(PruneLedger::class, NullPruneLedger::class);
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
        $this->app->scopedIf(CommitQueue::class);
        $this->app->scopedIf(CapturedEvents::class);
    }

    /**
     * Bootstrap framework integrations.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->registerPublishing();
        $this->registerCommands();
        $this->registerSchedule();
        $this->registerListeners();
        $this->registerCapture();
        $this->registerHttpFrame();
        $this->freezeRegistrationOnceBooted();
    }

    /**
     * Register the configuration file for publishing under the
     * `audit-log-config` tag, and the migrations under the
     * `audit-log-migrations` tag, when running in the console. The migrations
     * are published only, never loaded from the package, so the application
     * owns them and runs them on the storage connection.
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

        $this->commands([CheckCommand::class, DrainCommand::class, ReplayCommand::class, SealCommand::class, VerifyCommand::class]);
    }

    /**
     * Schedule sealing, the sweep and the strict verification once the
     * application resolves its schedule, when running in the console.
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
     * Register the listeners that track execution frames and carry context into
     * queued jobs, wherever the application runs: recording never branches on
     * the console.
     *
     * The events that end a frame are listened to once the application has
     * booted, after every listener any provider's `boot()` adds. An application
     * auditing a job's or a command's end is therefore still inside its frame,
     * and a record it makes there has the job's or the command's origin, name
     * and carried actor.
     *
     * @return void
     */
    protected function registerListeners(): void
    {
        Event::listen(CommandStarting::class, TrackCommandFrames::class);
        Event::listen(JobProcessing::class, TrackJobFrames::class);
        Event::listen(ContextDehydrating::class, CarryContextIntoJobs::class);
        Event::listen(TransactionCommitting::class, [CommitQueue::class, 'probe']);

        $this->app->booted(static function (): void {
            Event::listen(CommandFinished::class, TrackCommandFrames::class);
            Event::listen([JobProcessed::class, JobFailed::class, JobExceptionOccurred::class], TrackJobFrames::class);
        });
    }

    /**
     * Listen for Laravel's authentication events and for Gate evaluations, and
     * define the package's own codes, unless the catalogue is already frozen
     * because the provider is booted again after the application has, when they
     * were defined on its first boot. Nothing is read from configuration: each
     * listener reads its settings when an event reaches it, so a malformed one
     * never stops boot.
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
     * watcher once the application has booted, after which each refuses any
     * further registration.
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
