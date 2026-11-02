<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the shipped `config/audit-log.php`: the env vars it reads, the
 * defaults it falls back to and the leaves it ships, so a renamed key or env
 * var, or an added or dropped leaf, fails here rather than shipping silently.
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

    /** @var string Env var naming the maintenance connection. */
    private const string MAINTENANCE_ENV = 'AUDIT_LOG_STORAGE_MAINTENANCE_CONNECTION';

    /** @var string Env var naming the entries table. */
    private const string TABLE_ENV = 'AUDIT_LOG_ENTRIES_TABLE';

    /** @var string Env var naming the current integrity key. */
    private const string CURRENT_ENV = 'AUDIT_LOG_INTEGRITY_CURRENT';

    /**
     * Clear every env var after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ([self::CONNECTION_ENV, self::MAINTENANCE_ENV, self::TABLE_ENV, self::CURRENT_ENV] as $env) {
            putenv($env);
        }

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
     * With nothing in the environment the maintenance connection is `null`,
     * which reads as the storage connection.
     *
     * @return void
     */
    public function testTheMaintenanceConnectionDefaultsToTheStorageConnection(): void
    {
        putenv(self::MAINTENANCE_ENV);

        self::assertNull($this->config()['storage']['maintenance_connection']);
    }

    /**
     * The maintenance connection is read from its env var.
     *
     * @return void
     */
    public function testTheMaintenanceConnectionIsReadFromTheEnvironment(): void
    {
        putenv(self::MAINTENANCE_ENV . '=audit_maintenance');

        self::assertSame('audit_maintenance', $this->config()['storage']['maintenance_connection']);
    }

    /**
     * With nothing in the environment the entries live in `audit_log_entries`.
     *
     * @return void
     */
    public function testTheEntriesTableDefaultsToAuditLogEntries(): void
    {
        putenv(self::TABLE_ENV);

        self::assertSame('audit_log_entries', $this->config()['entries']['table']);
    }

    /**
     * The entries table is read from its env var.
     *
     * @return void
     */
    public function testTheEntriesTableIsReadFromTheEnvironment(): void
    {
        putenv(self::TABLE_ENV . '=reporting_entries');

        self::assertSame('reporting_entries', $this->config()['entries']['table']);
    }

    /**
     * With nothing in the environment no key ring is configured, so the key is
     * derived from `app.key`.
     *
     * @return void
     */
    public function testTheIntegrityRingIsEmptyByDefault(): void
    {
        putenv(self::CURRENT_ENV);

        self::assertSame([], $this->config()['integrity']['keys']);
        self::assertNull($this->config()['integrity']['current']);
    }

    /**
     * The current integrity key is read from its env var.
     *
     * @return void
     */
    public function testTheCurrentIntegrityKeyIsReadFromTheEnvironment(): void
    {
        putenv(self::CURRENT_ENV . '=k2026');

        self::assertSame('k2026', $this->config()['integrity']['current']);
    }

    /**
     * The shipped file has exactly these leaves, in this order, so an added,
     * renamed or dropped leaf fails here.
     *
     * @return void
     */
    public function testTheShippedLeavesArePinned(): void
    {
        $config = $this->config();
        $leaves = [];

        foreach ($config as $section => $settings) {
            foreach (array_keys($settings) as $key) {
                $leaves[] = $section . '.' . $key;
            }
        }

        self::assertSame([
            'storage.connection',
            'storage.maintenance_connection',
            'entries.table',
            'integrity.keys',
            'integrity.current',
        ], $leaves);
    }

    /**
     * Load the shipped configuration file afresh.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{storage: array{connection: ?string, maintenance_connection: ?string}, entries: array{table: string}, integrity: array{keys: array<string, string>, current: ?string}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function config(): array
    {
        /** @var array{storage: array{connection: ?string, maintenance_connection: ?string}, entries: array{table: string}, integrity: array{keys: array<string, string>, current: ?string}} $config */
        $config = require self::CONFIG;

        return $config;
    }
}
