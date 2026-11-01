<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the shipped `config/audit-log.php`: the env vars it reads and
 * the defaults it falls back to, so a renamed key or env var fails here rather
 * than shipping silently.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class ShippedConfigTest extends TestCase
{
    /** @var string The shipped configuration file. */
    private const string CONFIG = __DIR__ . '/../../../config/audit-log.php';

    /** @var string Env var naming the storage connection. */
    private const string CONNECTION_ENV = 'AUDIT_LOG_STORAGE_CONNECTION';

    /**
     * Clear the env var after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        putenv(self::CONNECTION_ENV);

        parent::tearDown();
    }

    /**
     * With nothing in the environment the tables live on the default
     * connection.
     *
     * @return void
     */
    public function testStorageConnectionDefaultsToTheDefaultConnection(): void
    {
        putenv(self::CONNECTION_ENV);

        self::assertNull($this->config()['storage']['connection']);
    }

    /**
     * The storage connection is read from its env var.
     *
     * @return void
     */
    public function testStorageConnectionIsReadFromTheEnvironment(): void
    {
        putenv(self::CONNECTION_ENV . '=audit');

        self::assertSame('audit', $this->config()['storage']['connection']);
    }

    /**
     * Load the shipped configuration file afresh.
     *
     * @return array{storage: array{connection: ?string}}
     */
    private function config(): array
    {
        /** @var array{storage: array{connection: ?string}} */
        return require self::CONFIG;
    }
}
