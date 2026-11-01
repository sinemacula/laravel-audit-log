<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\ServiceProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use Tests\TestCase;

/**
 * Feature tests for the package AuditLogServiceProvider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLogServiceProvider::class)]
final class AuditLogServiceProviderTest extends TestCase
{
    /** @var string The tag the configuration file is published under. */
    private const string CONFIG_TAG = 'audit-log-config';

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

            unset($value[AuditLogServiceProvider::class], $value[self::CONFIG_TAG]);

            $paths->setValue(null, $value);
        }
    }
}
