<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Support\Facades\Config;

/**
 * The delivery tables' names and the outbox's connection, read on every call; a
 * malformed setting fails closed naming its key, never its value.
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
     * The outbox table's name, `audit_log_outbox` by default.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function outboxTable(): string
    {
        return EntrySettings::configuredTable(self::OUTBOX_TABLE, self::DEFAULT_OUTBOX);
    }

    /**
     * The receipts table's name, `audit_log_deliveries` by default; it is
     * always on the storage connection.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function deliveriesTable(): string
    {
        return EntrySettings::configuredTable(self::DELIVERIES_TABLE, self::DEFAULT_DELIVERIES);
    }

    /**
     * The outbox connection, or the storage connection when none is set, which
     * is `null` for the default connection.
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
     * The outbox connection's name, falling back to the default connection.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function resolvedOutboxConnection(): string
    {
        return self::outboxConnection() ?? Config::string('database.default');
    }
}
