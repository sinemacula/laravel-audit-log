<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Support\Facades\Config;

/**
 * The owners' key tables' names, all on the storage connection; an unset,
 * `null` or empty setting names the default, and a malformed one fails closed
 * naming its key, never its value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KeyTables
{
    /** @var string The subject keys table when none is configured. */
    public const string DEFAULT_SUBJECT_KEYS = 'audit_log_subject_keys';

    /** @var string The owner erasures table when none is configured. */
    public const string DEFAULT_OWNER_ERASURES = 'audit_log_owner_erasures';

    /** @var string The key uses table when none is configured. */
    public const string DEFAULT_KEY_USES = 'audit_log_key_uses';

    /** @var string The subject keys table's full key. */
    private const string SUBJECT_KEYS_TABLE = 'audit-log.privacy.subject_keys_table';

    /** @var string The owner erasures table's full key. */
    private const string OWNER_ERASURES_TABLE = 'audit-log.privacy.owner_erasures_table';

    /** @var string The key uses table's full key. */
    private const string KEY_USES_TABLE = 'audit-log.privacy.key_uses_table';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The subject keys table's name, `audit_log_subject_keys` by default.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function subjectKeysTable(): string
    {
        return self::table(self::SUBJECT_KEYS_TABLE, self::DEFAULT_SUBJECT_KEYS);
    }

    /**
     * The owner erasures table's name, `audit_log_owner_erasures` by default.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function ownerErasuresTable(): string
    {
        return self::table(self::OWNER_ERASURES_TABLE, self::DEFAULT_OWNER_ERASURES);
    }

    /**
     * The key uses table's name, `audit_log_key_uses` by default.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function keyUsesTable(): string
    {
        return self::table(self::KEY_USES_TABLE, self::DEFAULT_KEY_USES);
    }

    /**
     * Read every key table setting, so the first malformed one fails.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function validate(): void
    {
        self::subjectKeysTable();
        self::ownerErasuresTable();
        self::keyUsesTable();
    }

    /**
     * The table setting under the key, or the default when unset, `null` or
     * empty, refused unless every index name derived from it fits.
     *
     * @param  string  $key
     * @param  string  $default
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function table(string $key, string $default): string
    {
        $table = Config::get($key);

        return $table === null || $table === '' ? $default : EntrySettings::configuredTable($key, $default);
    }
}
