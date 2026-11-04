<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Support\Facades\Config;

/**
 * What the owners' key tables are called: the subject keys, one row per key
 * unit and generation (`audit-log.privacy.subject_keys_table`), the owner
 * erasures, each erasure and reinstatement of an owner
 * (`audit-log.privacy.owner_erasures_table`), and the key uses, which key
 * encrypted a field of which entry (`audit-log.privacy.key_uses_table`).
 *
 * All three live on the storage connection, beside the entries they describe,
 * and no setting moves them. A setting that is not set, or is set to `null` or
 * to an empty string, names its default table, so an environment variable left
 * empty changes nothing. Any other name follows the entries table's grammar, 1
 * to 47 lower-case ASCII letters, digits and underscores that does not start
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

    /** @var string What a malformed table name is refused with: its key, then the longest name. */
    private const string MALFORMED = '`%s` must be a table name of 1 to %d lower-case letters, digits and underscores that does not start with a digit.';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The name of the subject keys table: the configured one, or
     * `audit_log_subject_keys` when none is configured.
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
     * The name of the owner erasures table: the configured one, or
     * `audit_log_owner_erasures` when none is configured.
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
     * The name of the key uses table: the configured one, or
     * `audit_log_key_uses` when none is configured.
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
     * Read every key table setting, so the first malformed one fails closed,
     * naming its key.
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
     * Read a table setting, or the default when it is not set, `null` or empty,
     * and refuse a name the migrations could not build every index name from.
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

        if ($table === null || $table === '') {
            return $default;
        }

        if (is_string($table) && preg_match(EntrySettings::TABLE_PATTERN, $table) === 1) {
            return $table;
        }

        throw new \InvalidArgumentException(sprintf(self::MALFORMED, $key, EntrySettings::MAX_TABLE_CHARACTERS));
    }
}
