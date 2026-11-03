<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use Tests\TestCase;

/**
 * Feature tests for where the delivery tables live and what they are called:
 * the two table names, their defaults and the names each refuses, and the
 * outbox connection, which follows the storage connection unless it names its
 * own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliveryTables::class)]
final class DeliveryTablesTest extends TestCase
{
    /** @var string The outbox table's setting. */
    private const string OUTBOX_TABLE = 'audit-log.delivery.outbox.table';

    /** @var string The receipts table's setting. */
    private const string DELIVERIES_TABLE = 'audit-log.delivery.deliveries_table';

    /** @var string The outbox connection's setting. */
    private const string OUTBOX_CONNECTION = 'audit-log.delivery.outbox.connection';

    /** @var string The storage connection's setting. */
    private const string STORAGE_CONNECTION = 'audit-log.storage.connection';

    /** @var string What every refused table name is refused with, after its key. */
    private const string TABLE_MESSAGE = ' must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.';

    /** @var string The message every refused outbox connection fails with. */
    private const string CONNECTION_MESSAGE = '`audit-log.delivery.outbox.connection` must be a connection name, or null or empty for the storage connection.';

    /**
     * `DeliveryTables` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(DeliveryTables::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(DeliveryTables::class, $instance);
    }

    /**
     * With no delivery settings at all, the outbox is `audit_log_outbox` and
     * the receipts are in `audit_log_deliveries`.
     *
     * @return void
     */
    public function testTheTablesHaveTheirDefaults(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log', array_diff_key($config->array('audit-log'), ['delivery' => true]));

        self::assertFalse($config->has(self::OUTBOX_TABLE));
        self::assertFalse($config->has(self::DELIVERIES_TABLE));
        self::assertSame('audit_log_outbox', DeliveryTables::DEFAULT_OUTBOX);
        self::assertSame('audit_log_deliveries', DeliveryTables::DEFAULT_DELIVERIES);
        self::assertSame('audit_log_outbox', DeliveryTables::outboxTable());
        self::assertSame('audit_log_deliveries', DeliveryTables::deliveriesTable());
    }

    /**
     * Each table is the configured name, read on every call, and neither
     * setting changes the other's table.
     *
     * @return void
     */
    public function testTheConfiguredTablesAreUsed(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::OUTBOX_TABLE, 'queued_audit');
        $config->set(self::DELIVERIES_TABLE, 'audit_receipts');

        self::assertSame('queued_audit', DeliveryTables::outboxTable());
        self::assertSame('audit_receipts', DeliveryTables::deliveriesTable());

        $config->set(self::OUTBOX_TABLE, str_repeat('a', 47));
        $config->set(self::DELIVERIES_TABLE, '_');

        self::assertSame(str_repeat('a', 47), DeliveryTables::outboxTable());
        self::assertSame('_', DeliveryTables::deliveriesTable());
    }

    /**
     * Rows of `[setting, value]`: per setting, a capital, a leading digit, one
     * character too many, a value that is no string, and a `null` set
     * explicitly.
     *
     * @return iterable<string, array{0: string, 1: int|list<string>|string|null}>
     */
    public static function provideMalformedTables(): iterable
    {
        foreach ([self::OUTBOX_TABLE, self::DELIVERIES_TABLE] as $setting) {
            yield from [
                $setting . ': a capital'          => [$setting, 'Audit'],
                $setting . ': a leading digit'    => [$setting, '9a'],
                $setting . ': 48 characters'      => [$setting, str_repeat('a', 48)],
                $setting . ': an integer'         => [$setting, 42],
                $setting . ': null'               => [$setting, null],
                $setting . ': empty'              => [$setting, ''],
                $setting . ': a schema'           => [$setting, 'reporting.audit'],
                $setting . ': a list'             => [$setting, ['audit']],
                $setting . ': a trailing newline' => [$setting, "audit\n"],
            ];
        }
    }

    /**
     * Each refused table name fails closed, naming its own setting and the
     * names it takes, rather than falling back to the default.
     *
     * @param  string  $setting
     * @param  int|list<string>|string|null  $value
     * @return void
     */
    #[DataProvider('provideMalformedTables')]
    public function testRefusesAMalformedTable(string $setting, array|int|string|null $value): void
    {
        app(ConfigRepository::class)->set($setting, $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`' . $setting . '`' . self::TABLE_MESSAGE);

        $setting === self::OUTBOX_TABLE ? DeliveryTables::outboxTable() : DeliveryTables::deliveriesTable();
    }

    /**
     * A malformed table refuses only its own setting: the other table is read
     * as configured.
     *
     * @return void
     */
    public function testAMalformedTableLeavesTheOtherReadable(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::OUTBOX_TABLE, 'Audit');

        self::assertSame('audit_log_deliveries', DeliveryTables::deliveriesTable());

        $config->set(self::OUTBOX_TABLE, 'audit_log_outbox');
        $config->set(self::DELIVERIES_TABLE, 'Audit');

        self::assertSame('audit_log_outbox', DeliveryTables::outboxTable());
    }

    /**
     * With no outbox connection named, the outbox is on the storage connection:
     * the default one, reported as `null`, when no storage connection is named
     * either, and the named one when it is.
     *
     * @return void
     */
    public function testTheOutboxConnectionDefaultsToTheStorageConnection(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::OUTBOX_CONNECTION, null);
        $config->set(self::STORAGE_CONNECTION, null);

        self::assertNull(DeliveryTables::outboxConnection());

        $config->set(self::STORAGE_CONNECTION, 'audit');

        self::assertSame('audit', DeliveryTables::outboxConnection());
        self::assertSame('audit', DeliveryTables::resolvedOutboxConnection());

        $config->set('audit-log', array_diff_key($config->array('audit-log'), ['delivery' => true]));

        self::assertSame('audit', DeliveryTables::outboxConnection());
    }

    /**
     * An empty outbox connection, as an unset environment variable gives it, is
     * the storage connection.
     *
     * @return void
     */
    public function testAnEmptyOutboxConnectionIsTheStorageConnection(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::OUTBOX_CONNECTION, '');
        $config->set(self::STORAGE_CONNECTION, 'audit');

        self::assertSame('audit', DeliveryTables::outboxConnection());

        $config->set(self::STORAGE_CONNECTION, '');

        self::assertNull(DeliveryTables::outboxConnection());
    }

    /**
     * A named outbox connection is the one the outbox lives on, whatever the
     * storage connection is.
     *
     * @return void
     */
    public function testANamedOutboxConnectionIsUsed(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::OUTBOX_CONNECTION, 'outbox');
        $config->set(self::STORAGE_CONNECTION, 'audit');

        self::assertSame('outbox', DeliveryTables::outboxConnection());
        self::assertSame('outbox', DeliveryTables::resolvedOutboxConnection());
    }

    /**
     * Rows of `[value]`: outbox connection settings that are neither a name nor
     * `null`.
     *
     * @return iterable<string, array{0: bool|int|list<string>}>
     */
    public static function provideMalformedOutboxConnections(): iterable
    {
        yield from [
            'an integer' => [42],
            'an array'   => [['outbox']],
            'a boolean'  => [false],
        ];
    }

    /**
     * An outbox connection that is not a name fails closed, naming the setting
     * and what an empty one means, rather than falling back to the storage
     * connection, in both readers.
     *
     * @param  bool|int|list<string>  $value
     * @return void
     */
    #[DataProvider('provideMalformedOutboxConnections')]
    public function testRefusesAMalformedOutboxConnection(array|bool|int $value): void
    {
        app(ConfigRepository::class)->set(self::OUTBOX_CONNECTION, $value);

        try {
            DeliveryTables::outboxConnection();
            self::fail('Expected the outbox connection to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(self::CONNECTION_MESSAGE, $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::CONNECTION_MESSAGE);

        DeliveryTables::resolvedOutboxConnection();
    }

    /**
     * A malformed storage connection is refused through the outbox connection
     * that follows it, never read as the default connection.
     *
     * @return void
     */
    public function testAMalformedStorageConnectionIsRefusedThroughTheOutbox(): void
    {
        app(ConfigRepository::class)->set(self::STORAGE_CONNECTION, 42);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.storage.connection` must be a connection name, or null or empty for the default connection.');

        DeliveryTables::resolvedOutboxConnection();
    }

    /**
     * With neither the outbox nor the storage connection named, the resolved
     * outbox connection is the default one, by name.
     *
     * @return void
     */
    public function testTheResolvedConnectionFallsBackToTheDefault(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::OUTBOX_CONNECTION, null);
        $config->set(self::STORAGE_CONNECTION, null);

        self::assertSame(self::CONNECTION, DeliveryTables::resolvedOutboxConnection());

        $config->set('database.default', 'elsewhere');

        try {
            self::assertSame('elsewhere', DeliveryTables::resolvedOutboxConnection());
        } finally {
            $config->set('database.default', self::CONNECTION);
        }
    }
}
