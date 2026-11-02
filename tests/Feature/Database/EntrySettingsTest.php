<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use Tests\TestCase;

/**
 * Feature tests for the entries table's name: the default, the names it accepts
 * up to the longest one every index name fits, and the message any other value
 * fails with.
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
     * Rows of `[table]`: values that cannot name every index the migration
     * derives from the table, or are not a name at all; a capital anywhere is
     * refused, since every engine reports index names in lower case (protects
     * against a mutation that widens either character class).
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
     * `EntrySettings` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
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
