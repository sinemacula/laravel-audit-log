<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Support\Facades\Config;

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

    /** @var string What a malformed table name is refused with: its key, then the longest name. */
    private const string MALFORMED = '`%s` must be a table name of 1 to %d lower-case letters, digits and underscores that does not start with a digit.';

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
        return self::table(self::JOURNAL_TABLE, self::DEFAULT_JOURNAL);
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
        return self::table(self::HOLDS_TABLE, self::DEFAULT_HOLDS);
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
        return self::table(self::LOCK_TABLE, self::DEFAULT_LOCK);
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
        return self::table(self::IMPORT_BATCHES_TABLE, self::DEFAULT_IMPORT_BATCHES);
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

    /**
     * The table setting under the key, or the default, refused unless every
     * index name the migrations derive from it fits.
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

        if (is_string($table) && preg_match(EntrySettings::TABLE_PATTERN, $table) === 1) {
            return $table;
        }

        throw new \InvalidArgumentException(sprintf(self::MALFORMED, $key, EntrySettings::MAX_TABLE_CHARACTERS));
    }
}
