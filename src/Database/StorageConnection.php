<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Support\Facades\Config;

/**
 * The connections the package's tables live on, compared by name without
 * opening one; the settings must not change during a process's life.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class StorageConnection
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The connection the package's tables live on, or `null` for the default
     * connection.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public static function name(): ?string
    {
        return self::read('storage.connection', 'the default connection');
    }

    /**
     * The connection for lifecycle and import writes, or the storage connection
     * when unset; both must reach one database.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public static function forMaintenance(): ?string
    {
        return self::read('storage.maintenance_connection', 'the storage connection') ?? self::name();
    }

    /**
     * The storage connection's name, falling back to the default connection.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function resolvedName(): string
    {
        return self::name() ?? Config::string('database.default');
    }

    /**
     * The maintenance connection's name, falling back to the storage, then the
     * default connection.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     *
     * @internal
     */
    public static function resolvedMaintenanceName(): string
    {
        return self::forMaintenance() ?? Config::string('database.default');
    }

    /**
     * A connection setting under `audit-log`, `null` when empty; anything but a
     * string fails closed.
     *
     * @param  string  $key
     * @param  string  $fallback
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function read(string $key, string $fallback): ?string
    {
        $connection = Config::get('audit-log.' . $key);

        if ($connection !== null && !is_string($connection)) {
            throw new \InvalidArgumentException(sprintf('`audit-log.%s` must be a connection name, or null or empty for %s.', $key, $fallback));
        }

        return $connection === '' ? null : $connection;
    }
}
