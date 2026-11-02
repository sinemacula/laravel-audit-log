<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Application as ConsoleApplication;
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\ServiceProvider;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Support\SystemClock;
use Tests\TestCase;

/**
 * Feature tests for the package AuditLogServiceProvider: the configuration it
 * merges, the defaults it binds, the files it publishes under each tag, the
 * migrations it never loads and the command it registers, in the console only.
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
