<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog;

use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
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
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use SineMacula\Laravel\AuditLog\Console\DrainCommand;
use SineMacula\Laravel\AuditLog\Console\ReplayCommand;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Delivery\CommitQueue;
use SineMacula\Laravel\AuditLog\Http\Middleware\EnterHttpFrame;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Listeners\CarryContextIntoJobs;
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
 * integrity settings, key ring, store and field encrypter, the recorder with
 * its catalogue and contributors, the scoped runtime state, the listeners that
 * track execution frames and carry context into jobs, the global middleware
 * that enters an HTTP frame, its publishing tags (the configuration and the
 * migrations, which it never loads itself) and the `audit-log:check`,
 * `audit-log:drain` and `audit-log:replay` console commands. It adds no route
 * and schedules nothing.
 *
 * Binding `AuditStore` is the only seam for where records go: there is no
 * manager and no driver registry. The delivery classes are autowired for each
 * capture, so none outlives a request.
 *
 * Registration of definitions and contributors is frozen once the application
 * has booted, so a long-lived worker registers once. Booting issues no query
 * and reads no setting that could stop it, so a malformed one reaches
 * `audit-log:check`.
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
    ];

    /**
     * Register container bindings.
     *
     * Every binding is a default: one that the application or another package
     * made before this provider registers is kept, so a store, a clock or an
     * encrypter bound earlier is never replaced by the package's (an
     * `AuditStore` by `DatabaseAuditStore`, a `Clock` by `SystemClock`, a
     * `FieldEncrypter` by `NoFieldEncrypter`), and one made after replaces the
     * default, as any later binding does.
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
        $this->app->singletonIf(EventCatalogue::class);
        $this->app->singletonIf(ContributorRegistry::class);
        $this->app->singletonIf(Recorder::class);
        $this->app->scopedIf(ExecutionFrames::class);
        $this->app->scopedIf(RequestIdentity::class);
        $this->app->scopedIf(ReportLatch::class);
        $this->app->scopedIf(WriteGuard::class);
        $this->app->scopedIf(CommitQueue::class);
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
        $this->registerListeners();
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

        $this->commands([CheckCommand::class, DrainCommand::class, ReplayCommand::class]);
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
     * Freeze the catalogue and the contributors once the application has
     * booted, after which each refuses any further registration.
     *
     * @return void
     */
    protected function freezeRegistrationOnceBooted(): void
    {
        $this->app->booted(static function (Application $app): void {
            $app->make(EventCatalogue::class)->freeze();
            $app->make(ContributorRegistry::class)->freeze();
        });
    }
}
