<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

/**
 * The lifecycle and import tables' names, all on the storage connection; a
 * malformed setting fails closed naming its key, never its value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LifecycleTables
{
    /** @var string The journal table when none is configured. */
    public const string DEFAULT_JOURNAL = 'audit_log_lifecycle';

    /** @var string The holds table when none is configured. */
    public const string DEFAULT_HOLDS = 'audit_log_holds';

    /** @var string The lock table when none is configured. */
    public const string DEFAULT_LOCK = 'audit_log_lifecycle_lock';

    /** @var string The import batches table when none is configured. */
    public const string DEFAULT_IMPORT_BATCHES = 'audit_log_import_batches';

    /** @var string The journal table's full key. */
    private const string JOURNAL_TABLE = 'audit-log.lifecycle.journal_table';

    /** @var string The holds table's full key. */
    private const string HOLDS_TABLE = 'audit-log.lifecycle.holds_table';

    /** @var string The lock table's full key. */
    private const string LOCK_TABLE = 'audit-log.lifecycle.lock_table';

    /** @var string The import batches table's full key. */
    private const string IMPORT_BATCHES_TABLE = 'audit-log.import.batches_table';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The journal table's name, `audit_log_lifecycle` by default.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function journalTable(): string
    {
        return EntrySettings::configuredTable(self::JOURNAL_TABLE, self::DEFAULT_JOURNAL);
    }

    /**
     * The holds table's name, `audit_log_holds` by default.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function holdsTable(): string
    {
        return EntrySettings::configuredTable(self::HOLDS_TABLE, self::DEFAULT_HOLDS);
    }

    /**
     * The lock table's name, `audit_log_lifecycle_lock` by default.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function lockTable(): string
    {
        return EntrySettings::configuredTable(self::LOCK_TABLE, self::DEFAULT_LOCK);
    }

    /**
     * The import batches table's name, `audit_log_import_batches` by default.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function importBatchesTable(): string
    {
        return EntrySettings::configuredTable(self::IMPORT_BATCHES_TABLE, self::DEFAULT_IMPORT_BATCHES);
    }

    /**
     * Read every lifecycle table setting, so the first malformed one fails.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function validate(): void
    {
        self::journalTable();
        self::holdsTable();
        self::lockTable();
        self::importBatchesTable();
    }
}
