<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Support\Facades\Config;

/**
 * Where the package's tables live: the connection the shipped model reads and
 * the store writes, and the one the shipped migration creates the entries table
 * on, so the two cannot disagree.
 *
 * The entries live on `audit-log.storage.connection` (`null` or empty for the
 * default connection). Pruning, holds, the lifecycle journal and an import's
 * journal rows run through `audit-log.storage.maintenance_connection` when it
 * names one, and through the storage connection otherwise, each in a
 * transaction of its own behind the lifecycle lock: a connection of their own
 * lets them use credentials of their own, with privileges the writer never
 * holds, but it must reach the same physical database as the storage
 * connection, which every lifecycle operation confirms by the installation id
 * before it takes the lock.
 *
 * The settings must stay the same for the life of a process: moving the tables
 * is a deploy, with a worker restart and a migration the application performs,
 * not a runtime switch. Connections are compared by name, a configured one or
 * the default one, so no connection is opened.
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
     * The connection pruning, holds, the lifecycle journal and an import's
     * journal rows run through: the one
     * `audit-log.storage.maintenance_connection` names, or the storage
     * connection.
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
     * The name of the storage connection: the configured one, or the default
     * one.
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
     * The name of the maintenance connection: the configured one, the storage
     * connection, or the default one.
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
     * Read a connection setting under `audit-log`: a name, or `null` for what
     * an empty one means. Anything else fails closed rather than falling back
     * to another connection.
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
