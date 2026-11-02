<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Support\SystemClock;

/**
 * Package service provider: registers the package's configuration, its clock,
 * integrity settings, key ring and store, its publishing tags (the
 * configuration and the migrations, which it never loads itself) and the
 * `audit-log:check` console command.
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
    ];

    /**
     * Register container bindings.
     *
     * Every binding is a default: one that the application or another package
     * made before this provider registers is kept, so a store or a clock bound
     * earlier is never replaced by the package's (an `AuditStore` by
     * `DatabaseAuditStore`, a `Clock` by `SystemClock`), and one made after
     * replaces the default, as any later binding does.
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

        $this->commands([CheckCommand::class]);
    }
}
