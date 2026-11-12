<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Support\Facades\Config;

/**
 * The integrity tables' names, all on the storage connection; a malformed
 * setting fails closed naming its key, never its value.
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
     * The seals table's name, `audit_log_checkpoints` by default.
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
     * The seal members table's name, `audit_log_checkpoint_members` by default.
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
     * The progress table's name, `audit_log_integrity_state` by default.
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
