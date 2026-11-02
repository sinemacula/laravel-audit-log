<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use Tests\TestCase;

/**
 * Feature tests for where the package's tables live: the storage connection,
 * the maintenance connection that falls back to it, the names each resolves to
 * when neither is named, and the message a setting that is not a name fails
 * with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageConnection::class)]
final class StorageConnectionTest extends TestCase
{
    /** @var string The storage connection setting. */
    private const string STORAGE = 'audit-log.storage.connection';

    /** @var string The maintenance connection setting. */
    private const string MAINTENANCE = 'audit-log.storage.maintenance_connection';

    /**
     * With no storage connection named, the tables live on the default
     * connection, which `name()` reports as `null`.
     *
     * @return void
     */
    public function testTheStorageConnectionDefaultsToTheDefaultConnection(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::STORAGE, null);

        self::assertNull(StorageConnection::name());
        self::assertSame(self::CONNECTION, StorageConnection::resolvedName());
    }

    /**
     * An empty storage connection, as an unset environment variable gives it,
     * is the default connection.
     *
     * @return void
     */
    public function testAnEmptyStorageConnectionIsTheDefaultConnection(): void
    {
        app(ConfigRepository::class)->set(self::STORAGE, '');

        self::assertNull(StorageConnection::name());
        self::assertSame(self::CONNECTION, StorageConnection::resolvedName());
    }

    /**
     * A named storage connection is the one the tables live on, as named.
     *
     * @return void
     */
    public function testTheStorageConnectionIsTheConfiguredName(): void
    {
        app(ConfigRepository::class)->set(self::STORAGE, 'audit');

        self::assertSame('audit', StorageConnection::name());
        self::assertSame('audit', StorageConnection::resolvedName());
    }

    /**
     * Rows of `[value]`: connection settings that are neither a name nor
     * `null`.
     *
     * @return iterable<string, array{0: bool|int|list<string>}>
     */
    public static function provideStorageConnectionsThatAreNotNames(): iterable
    {
        yield from [
            'an integer' => [42],
            'an array'   => [['audit']],
            'a boolean'  => [false],
        ];
    }

    /**
     * A storage connection that is not a name fails closed, naming the setting
     * and what an empty one means, rather than falling back to the default
     * connection.
     *
     * @param  bool|int|list<string>  $value
     * @return void
     */
    #[DataProvider('provideStorageConnectionsThatAreNotNames')]
    public function testAStorageConnectionThatIsNotANameFailsClosed(array|bool|int $value): void
    {
        app(ConfigRepository::class)->set(self::STORAGE, $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.storage.connection` must be a connection name, or null or empty for the default connection.');

        StorageConnection::name();
    }

    /**
     * The resolved storage name reads through the same check, so a storage
     * connection that is not a name never resolves to the default one.
     *
     * @return void
     */
    public function testTheResolvedStorageNameFailsClosedToo(): void
    {
        app(ConfigRepository::class)->set(self::STORAGE, 42);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.storage.connection` must be a connection name, or null or empty for the default connection.');

        StorageConnection::resolvedName();
    }

    /**
     * With no maintenance connection named, maintenance runs on the storage
     * connection: the default one when no storage connection is named either,
     * and the named one when it is.
     *
     * @return void
     */
    public function testTheMaintenanceConnectionDefaultsToTheStorageConnection(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::MAINTENANCE, null);
        $config->set(self::STORAGE, null);

        self::assertNull(StorageConnection::forMaintenance());
        self::assertSame(self::CONNECTION, StorageConnection::resolvedMaintenanceName());

        $config->set(self::STORAGE, 'audit');

        self::assertSame('audit', StorageConnection::forMaintenance());
        self::assertSame('audit', StorageConnection::resolvedMaintenanceName());
    }

    /**
     * An empty maintenance connection is the storage connection.
     *
     * @return void
     */
    public function testAnEmptyMaintenanceConnectionIsTheStorageConnection(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::MAINTENANCE, '');
        $config->set(self::STORAGE, 'audit');

        self::assertSame('audit', StorageConnection::forMaintenance());
        self::assertSame('audit', StorageConnection::resolvedMaintenanceName());
    }

    /**
     * A named maintenance connection is its own, whatever the storage
     * connection is, and naming it leaves the storage connection as it was.
     *
     * @return void
     */
    public function testTheMaintenanceConnectionIsItsOwnWhenNamed(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::MAINTENANCE, 'audit_maintenance');
        $config->set(self::STORAGE, 'audit');

        self::assertSame('audit_maintenance', StorageConnection::forMaintenance());
        self::assertSame('audit_maintenance', StorageConnection::resolvedMaintenanceName());
        self::assertSame('audit', StorageConnection::name());

        $config->set(self::STORAGE, null);

        self::assertSame('audit_maintenance', StorageConnection::forMaintenance());
        self::assertNull(StorageConnection::name());
    }

    /**
     * A maintenance connection that is not a name fails closed, naming the
     * setting and that an empty one means the storage connection, rather than
     * falling back to it.
     *
     * @param  bool|int|list<string>  $value
     * @return void
     */
    #[DataProvider('provideStorageConnectionsThatAreNotNames')]
    public function testAMaintenanceConnectionThatIsNotANameFailsClosed(array|bool|int $value): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::MAINTENANCE, $value);
        $config->set(self::STORAGE, 'audit');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.storage.maintenance_connection` must be a connection name, or null or empty for the storage connection.');

        StorageConnection::forMaintenance();
    }

    /**
     * An unnamed maintenance connection falls back through the storage
     * connection's check, so a storage connection that is not a name fails the
     * maintenance read too, with the storage connection's message.
     *
     * @return void
     */
    public function testAnUnnamedMaintenanceConnectionFailsWithAMalformedStorageConnection(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::MAINTENANCE, null);
        $config->set(self::STORAGE, 42);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.storage.connection` must be a connection name, or null or empty for the default connection.');

        StorageConnection::resolvedMaintenanceName();
    }

    /**
     * The resolved names follow the default connection when nothing is named,
     * whatever it is called.
     *
     * @return void
     */
    public function testTheResolvedNamesFallBackToTheDefaultConnection(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::STORAGE, null);
        $config->set(self::MAINTENANCE, null);
        $config->set('database.default', 'reporting');

        try {
            self::assertSame('reporting', StorageConnection::resolvedName());
            self::assertSame('reporting', StorageConnection::resolvedMaintenanceName());
        } finally {
            $config->set('database.default', self::CONNECTION);
        }
    }

    /**
     * `StorageConnection` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(StorageConnection::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(StorageConnection::class, $instance);
    }
}
