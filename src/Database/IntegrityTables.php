<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

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
        return EntrySettings::configuredTable(self::CHECKPOINTS_TABLE, self::DEFAULT_CHECKPOINTS);
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
        return EntrySettings::configuredTable(self::MEMBERS_TABLE, self::DEFAULT_MEMBERS);
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
        return EntrySettings::configuredTable(self::STATE_TABLE, self::DEFAULT_STATE);
    }
}
