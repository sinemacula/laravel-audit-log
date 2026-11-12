<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Support\Facades\Config;

/**
 * The entries and artifacts table names, read on every call and refused unless
 * every index name derived from them fits PostgreSQL's 63 characters.
 *
 * Lower case only, since MySQL's `lower_case_table_names` differs per server.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EntrySettings
{
    /** @var int Longest table name: index names then fit 63 characters. */
    public const int MAX_TABLE_CHARACTERS = 47;

    /** @var string The table when none is configured. */
    public const string DEFAULT_TABLE = 'audit_log_entries';

    /** @var string The artifacts table when none is configured. */
    public const string DEFAULT_ARTIFACTS_TABLE = 'audit_log_artifacts';

    /** @var string Lower-case letters, digits and underscores, with no leading digit, up to the longest table name. */
    public const string TABLE_PATTERN = '/\A[a-z_][a-z0-9_]{0,46}\z/';

    /** @var string The entries table setting's full key. */
    private const string KEY = 'audit-log.entries.table';

    /** @var string The artifacts table setting's full key. */
    private const string ARTIFACTS_KEY = 'audit-log.entries.artifacts_table';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The entries table's name, `audit_log_entries` by default.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function table(): string
    {
        return self::named(self::KEY, self::DEFAULT_TABLE);
    }

    /**
     * The artifacts table's name, `audit_log_artifacts` by default.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function artifactsTable(): string
    {
        return self::named(self::ARTIFACTS_KEY, self::DEFAULT_ARTIFACTS_TABLE);
    }

    /**
     * The table setting under the key, or the default, refused with a message
     * naming the key unless it fits the grammar.
     *
     * @param  string  $key
     * @param  string  $default
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function named(string $key, string $default): string
    {
        $table = Config::get($key, $default);

        if (!is_string($table) || preg_match(self::TABLE_PATTERN, $table) !== 1) {
            $message = sprintf(
                '`%s` must be a table name of 1 to %d lower-case letters, digits and underscores that does not start with a digit.',
                $key,
                self::MAX_TABLE_CHARACTERS,
            );

            throw new \InvalidArgumentException($message);
        }

        return $table;
    }
}
