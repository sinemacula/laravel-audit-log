<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
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
     * @return iterable<string, array{0: int|list<string>|string|null}>
     */
    public static function provideRefusedTables(): iterable
    {
        yield from [
            '48 characters'         => [str_repeat('a', 48)],
            'empty'                 => [''],
            'null'                  => [null],
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
     * @param  int|list<string>|string|null  $table
     * @return void
     */
    #[DataProvider('provideRefusedTables')]
    public function testRefusesATableThatCannotNameEveryIndex(array|int|string|null $table): void
    {
        app(ConfigRepository::class)->set(self::KEY, $table);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MESSAGE);

        EntrySettings::table();
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
     * @param  int|list<string>|string|null  $table
     * @return void
     */
    #[DataProvider('provideRefusedTables')]
    public function testAMalformedArtifactsTableIsRefusedNamingItsKey(array|int|string|null $table): void
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
