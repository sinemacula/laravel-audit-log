<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Support\Facades\Config;

/**
 * Reads the names of the entries table, `audit-log.entries.table`, and of the
 * artifacts table beside it, `audit-log.entries.artifacts_table`, which holds
 * each bulk operation's manifest, the one way the migrations, the model, the
 * store and the check command read them, and fails closed on a name the
 * migration could not build every index name from.
 *
 * Each name is 1 to 47 lower-case ASCII letters, digits and underscores that
 * does not start with a digit, so the longest index name the migration derives
 * from it fits the 63 characters PostgreSQL keeps (and MySQL's 64) and needs no
 * quoting. Capitals are refused: every engine reports index names in lower
 * case, PostgreSQL folds an unquoted name to it, and MySQL's
 * `lower_case_table_names` treats the case of a table name differently from one
 * server to the next, so a name in lower case is the same name on each. A
 * schema-qualified name is refused, because its dot would be in every index
 * name: choose the schema with the storage connection instead. The settings are
 * read through the `Config` facade, because a migration and a model constructor
 * cannot be injected, and validated on every call.
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
     * The name of the entries table: the configured one, or `audit_log_entries`
     * when none is configured.
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
     * The name of the artifacts table, which holds each bulk operation's
     * manifest beside its entry: the configured one, or `audit_log_artifacts`
     * when none is configured.
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
     * The table name under the key, or the default when it is not set, refused
     * with a message naming the key unless it fits the grammar.
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
