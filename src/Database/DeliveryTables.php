<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Support\Facades\Config;

/**
 * Where the delivery tables live and what they are called: the outbox
 * (`audit-log.delivery.outbox.table`, on
 * `audit-log.delivery.outbox.connection`) and the receipts of each destination
 * (`audit-log.delivery.deliveries_table`, always on the storage connection,
 * beside the entries they describe).
 *
 * A table name follows the entries table's grammar, 1 to 47 lower-case ASCII
 * letters, digits and underscores that does not start with a digit, so every
 * index name a migration derives from it fits the 63 characters PostgreSQL
 * keeps. The outbox connection is a name, or `null` or empty for the storage
 * connection; it may differ from the storage connection, so the outbox can sit
 * in the database the application's own transactions run on. Every setting is
 * read through the `Config` facade, because a migration cannot be injected, and
 * validated on every call; a malformed one fails closed with an
 * `InvalidArgumentException` naming the key and never the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DeliveryTables
{
    /** @var string The outbox table when none is configured. */
    public const string DEFAULT_OUTBOX = 'audit_log_outbox';

    /** @var string The receipts table when none is configured. */
    public const string DEFAULT_DELIVERIES = 'audit_log_deliveries';

    /** @var string The outbox table's full key. */
    private const string OUTBOX_TABLE = 'audit-log.delivery.outbox.table';

    /** @var string The receipts table's full key. */
    private const string DELIVERIES_TABLE = 'audit-log.delivery.deliveries_table';

    /** @var string The outbox connection's full key. */
    private const string OUTBOX_CONNECTION = 'audit-log.delivery.outbox.connection';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The name of the outbox table: the configured one, or `audit_log_outbox`
     * when none is configured.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function outboxTable(): string
    {
        return self::table(self::OUTBOX_TABLE, self::DEFAULT_OUTBOX);
    }

    /**
     * The name of the receipts table: the configured one, or
     * `audit_log_deliveries` when none is configured.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function deliveriesTable(): string
    {
        return self::table(self::DELIVERIES_TABLE, self::DEFAULT_DELIVERIES);
    }

    /**
     * The connection the outbox lives on: the configured one, or the storage
     * connection when none is configured, which is `null` for the default
     * connection.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public static function outboxConnection(): ?string
    {
        $connection = Config::get(self::OUTBOX_CONNECTION);

        if ($connection !== null && !is_string($connection)) {
            throw new \InvalidArgumentException(sprintf('`%s` must be a connection name, or null or empty for the storage connection.', self::OUTBOX_CONNECTION));
        }

        return $connection === null || $connection === '' ? StorageConnection::name() : $connection;
    }

    /**
     * The name of the outbox connection: the configured one, the storage
     * connection, or the default one.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function resolvedOutboxConnection(): string
    {
        return self::outboxConnection() ?? Config::string('database.default');
    }

    /**
     * Read a table setting, or the default when it is not set, and refuse a
     * name the migrations could not build every index name from.
     *
     * @param  string  $key
     * @param  string  $default
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function table(string $key, string $default): string
    {
        $table = Config::get($key, $default);

        if (!is_string($table) || preg_match(EntrySettings::TABLE_PATTERN, $table) !== 1) {
            $message = sprintf(
                '`%s` must be a table name of 1 to %d lower-case letters, digits and underscores that does not start with a digit.',
                $key,
                EntrySettings::MAX_TABLE_CHARACTERS,
            );

            throw new \InvalidArgumentException($message);
        }

        return $table;
    }
}
