<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use Tests\TestCase;

/**
 * Feature tests for the names of the entries table and the artifacts table
 * beside it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EntrySettings::class)]
final class EntrySettingsTest extends TestCase
{
    /** @var string The setting the tests configure. */
    private const string KEY = 'audit-log.entries.table';

    /** @var string The message every refused table name fails with. */
    private const string MESSAGE = '`audit-log.entries.table` must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.';

    /** @var string The artifacts table's setting. */
    private const string ARTIFACTS_KEY = 'audit-log.entries.artifacts_table';

    /** @var string The message every refused artifacts table name fails with. */
    private const string ARTIFACTS_MESSAGE = '`audit-log.entries.artifacts_table` must be a table name of 1 to 47 lower-case letters, digits and underscores'
        . ' that does not start with a digit.';

    /**
     * With no table configured, the entries live in `audit_log_entries`.
     *
     * @return void
     */
    public function testTheTableDefaultsToAuditLogEntries(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log', array_diff_key($config->array('audit-log'), ['entries' => true]));

        self::assertFalse($config->has(self::KEY));
        self::assertSame('audit_log_entries', EntrySettings::DEFAULT_TABLE);
        self::assertSame('audit_log_entries', EntrySettings::table());
    }

    /**
     * Rows of `[table]`: names the setting accepts, at each end of its length
     * and with each kind of character it allows.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideAcceptedTables(): iterable
    {
        yield from [
            'one letter'             => ['a'],
            'one underscore'         => ['_'],
            'a leading underscore'   => ['_audit'],
            'digits after the first' => ['audit2026_entries'],
            'the shipped name'       => ['audit_log_entries'],
        ];
    }

    /**
     * A configured name of lower-case letters, digits and underscores that does
     * not start with a digit is the table, as configured.
     *
     * @param  string  $table
     * @return void
     */
    #[DataProvider('provideAcceptedTables')]
    public function testTheConfiguredTableIsUsed(string $table): void
    {
        app(ConfigRepository::class)->set(self::KEY, $table);

        self::assertSame($table, EntrySettings::table());
    }

    /**
     * A name of exactly 47 characters, the longest whose index names fit
     * PostgreSQL's 63, is accepted.
     *
     * @return void
     */
    public function testATableOf47CharactersIsAccepted(): void
    {
        $table = str_repeat('a', 47);

        app(ConfigRepository::class)->set(self::KEY, $table);

        self::assertSame(47, EntrySettings::MAX_TABLE_CHARACTERS);
        self::assertSame($table, EntrySettings::table());
    }

    /**
     * Rows of `[table]`: values refused as a table name; a capital is refused
     * because every engine reports index names in lower case.
     *
     * @return iterable<string, array{0: int|list<string>|string}>
     */
    public static function provideRefusedTables(): iterable
    {
        yield from [
            '48 characters'         => [str_repeat('a', 48)],
            'a space alone'         => [' '],
            'an integer'            => [42],
            'a list'                => [['audit_log_entries']],
            'a hyphen'              => ['audit-log'],
            'a space'               => ['audit log'],
            'a dot'                 => ['reporting.audit'],
            'a leading digit'       => ['1audit'],
            'a quote'               => ['audit"x'],
            'a non-ASCII letter'    => ['äudit'],
            'a trailing newline'    => ["audit\n"],
            'a leading space'       => [' audit'],
            'a backtick'            => ['audit`x'],
            '48 with an underscore' => ['_' . str_repeat('a', 47)],
            'capitals'              => ['AuditEntries'],
            'one capital'           => ['audit_Entries'],
            'a leading capital'     => ['Audit_entries'],
        ];
    }

    /**
     * Each refused value fails closed, naming the setting and the names it
     * takes.
     *
     * @param  int|list<string>|string  $table
     * @return void
     */
    #[DataProvider('provideRefusedTables')]
    public function testRefusesATableThatCannotNameEveryIndex(array|int|string $table): void
    {
        app(ConfigRepository::class)->set(self::KEY, $table);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MESSAGE);

        EntrySettings::table();
    }

    /**
     * Rows of `[key, value, read, default]`: every table setting, `null` and
     * empty, as an unset or empty environment variable leaves it.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: \Closure(): string, 3: string}>
     */
    public static function provideUnsetTableSettings(): iterable
    {
        $tables = [
            'audit-log.entries.table'                => [EntrySettings::table(...), EntrySettings::DEFAULT_TABLE],
            'audit-log.entries.artifacts_table'      => [EntrySettings::artifactsTable(...), EntrySettings::DEFAULT_ARTIFACTS_TABLE],
            'audit-log.integrity.checkpoints_table'  => [IntegrityTables::checkpointsTable(...), IntegrityTables::DEFAULT_CHECKPOINTS],
            'audit-log.integrity.members_table'      => [IntegrityTables::membersTable(...), IntegrityTables::DEFAULT_MEMBERS],
            'audit-log.integrity.state_table'        => [IntegrityTables::stateTable(...), IntegrityTables::DEFAULT_STATE],
            'audit-log.lifecycle.journal_table'      => [LifecycleTables::journalTable(...), LifecycleTables::DEFAULT_JOURNAL],
            'audit-log.lifecycle.holds_table'        => [LifecycleTables::holdsTable(...), LifecycleTables::DEFAULT_HOLDS],
            'audit-log.lifecycle.lock_table'         => [LifecycleTables::lockTable(...), LifecycleTables::DEFAULT_LOCK],
            'audit-log.import.batches_table'         => [LifecycleTables::importBatchesTable(...), LifecycleTables::DEFAULT_IMPORT_BATCHES],
            'audit-log.privacy.subject_keys_table'   => [KeyTables::subjectKeysTable(...), KeyTables::DEFAULT_SUBJECT_KEYS],
            'audit-log.privacy.owner_erasures_table' => [KeyTables::ownerErasuresTable(...), KeyTables::DEFAULT_OWNER_ERASURES],
            'audit-log.privacy.key_uses_table'       => [KeyTables::keyUsesTable(...), KeyTables::DEFAULT_KEY_USES],
            'audit-log.delivery.outbox.table'        => [DeliveryTables::outboxTable(...), DeliveryTables::DEFAULT_OUTBOX],
            'audit-log.delivery.deliveries_table'    => [DeliveryTables::deliveriesTable(...), DeliveryTables::DEFAULT_DELIVERIES],
        ];

        foreach ($tables as $key => [$read, $default]) {
            yield $key . ': null' => [$key, null, $read, $default];
            yield $key . ': empty' => [$key, '', $read, $default];
        }
    }

    /**
     * Every table setting that is `null` or empty names its default table.
     *
     * @param  string  $key
     * @param  ?string  $value
     * @param  \Closure(): string  $read
     * @param  string  $default
     * @return void
     */
    #[DataProvider('provideUnsetTableSettings')]
    public function testANullOrEmptyTableSettingIsItsDefault(string $key, ?string $value, \Closure $read, string $default): void
    {
        app(ConfigRepository::class)->set($key, $value);

        self::assertSame($default, $read());
    }

    /**
     * The setting is read on every call, so a changed name is the table at once
     * and a name changed to one that is refused fails at once.
     *
     * @return void
     */
    public function testTheSettingIsReadOnEveryCall(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::KEY, 'first_entries');

        self::assertSame('first_entries', EntrySettings::table());

        $config->set(self::KEY, 'second_entries');

        self::assertSame('second_entries', EntrySettings::table());

        $config->set(self::KEY, 'second.entries');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MESSAGE);

        EntrySettings::table();
    }

    /**
     * With no artifacts table configured, each bulk operation's manifest lives
     * in `audit_log_artifacts`, whatever the entries table is called.
     *
     * @return void
     */
    public function testTheArtifactsTableDefaults(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log', array_diff_key($config->array('audit-log'), ['entries' => true]));

        self::assertFalse($config->has(self::ARTIFACTS_KEY));
        self::assertSame('audit_log_artifacts', EntrySettings::DEFAULT_ARTIFACTS_TABLE);
        self::assertSame('audit_log_artifacts', EntrySettings::artifactsTable());

        $config->set(self::KEY, 'reporting_entries');

        self::assertSame('audit_log_artifacts', EntrySettings::artifactsTable());
    }

    /**
     * The artifacts table takes every name the entries table takes, up to 47
     * characters, read from its own key.
     *
     * @return void
     */
    public function testTheArtifactsTableHasTheEntriesGrammar(): void
    {
        $config = app(ConfigRepository::class);

        foreach ([...array_column([...self::provideAcceptedTables()], 0), str_repeat('a', 47)] as $table) {
            $config->set(self::ARTIFACTS_KEY, $table);

            self::assertSame($table, EntrySettings::artifactsTable());
        }

        $config->set(self::KEY, 'audit-log');
        $config->set(self::ARTIFACTS_KEY, 'reporting_artifacts');

        self::assertSame('reporting_artifacts', EntrySettings::artifactsTable());
    }

    /**
     * A value the entries table refuses is refused for the artifacts table too,
     * naming the artifacts table's key.
     *
     * @param  int|list<string>|string  $table
     * @return void
     */
    #[DataProvider('provideRefusedTables')]
    public function testAMalformedArtifactsTableIsRefusedNamingItsKey(array|int|string $table): void
    {
        app(ConfigRepository::class)->set(self::ARTIFACTS_KEY, $table);

        self::assertSame('audit_log_entries', EntrySettings::table());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::ARTIFACTS_MESSAGE);

        EntrySettings::artifactsTable();
    }

    /**
     * The constructor is private; reflection invokes it so the line is covered.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(EntrySettings::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(EntrySettings::class, $instance);
    }
}
