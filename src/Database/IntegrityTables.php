<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Support\Facades\Config;

/**
 * What the integrity tables are called: the seals
 * (`audit-log.integrity.checkpoints_table`), the entries each seal holds
 * (`audit-log.integrity.members_table`) and the operational progress of
 * sealing, anchoring and verification (`audit-log.integrity.state_table`).
 *
 * All three live on the storage connection, beside the entries they describe,
 * and no setting moves them. A table name follows the entries table's grammar,
 * 1 to 47 lower-case ASCII letters, digits and underscores that does not start
 * with a digit, so every index name a migration derives from it fits the 63
 * characters PostgreSQL keeps. Every setting is read through the `Config`
 * facade, because a migration cannot be injected, and validated on every call;
 * a malformed one fails closed with an `InvalidArgumentException` naming the
 * key and never the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IntegrityTables
{
    /** @var string The seals table when none is configured. */
    public const string DEFAULT_CHECKPOINTS = 'audit_log_checkpoints';

    /** @var string The members table when none is configured. */
    public const string DEFAULT_MEMBERS = 'audit_log_checkpoint_members';

    /** @var string The progress table when none is configured. */
    public const string DEFAULT_STATE = 'audit_log_integrity_state';

    /** @var string The seals table's full key. */
    private const string CHECKPOINTS_TABLE = 'audit-log.integrity.checkpoints_table';

    /** @var string The members table's full key. */
    private const string MEMBERS_TABLE = 'audit-log.integrity.members_table';

    /** @var string The progress table's full key. */
    private const string STATE_TABLE = 'audit-log.integrity.state_table';

    /** @var string What a malformed table name is refused with: its key, then the longest name. */
    private const string MALFORMED = '`%s` must be a table name of 1 to %d lower-case letters, digits and underscores that does not start with a digit.';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The name of the seals table: the configured one, or
     * `audit_log_checkpoints` when none is configured.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function checkpointsTable(): string
    {
        return self::table(self::CHECKPOINTS_TABLE, self::DEFAULT_CHECKPOINTS);
    }

    /**
     * The name of the members table: the configured one, or
     * `audit_log_checkpoint_members` when none is configured.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function membersTable(): string
    {
        return self::table(self::MEMBERS_TABLE, self::DEFAULT_MEMBERS);
    }

    /**
     * The name of the progress table: the configured one, or
     * `audit_log_integrity_state` when none is configured.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function stateTable(): string
    {
        return self::table(self::STATE_TABLE, self::DEFAULT_STATE);
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

        if (is_string($table) && preg_match(EntrySettings::TABLE_PATTERN, $table) === 1) {
            return $table;
        }

        throw new \InvalidArgumentException(sprintf(self::MALFORMED, $key, EntrySettings::MAX_TABLE_CHARACTERS));
    }
}
