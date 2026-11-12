<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use Tests\TestCase;

/**
 * Feature tests for the names of the owners' key tables, and the refusal that
 * names the leaf and never the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyTables::class)]
final class KeyTablesTest extends TestCase
{
    /** @var string The subject keys table's setting. */
    private const string SUBJECT_KEYS_TABLE = 'audit-log.privacy.subject_keys_table';

    /** @var string The owner erasures table's setting. */
    private const string OWNER_ERASURES_TABLE = 'audit-log.privacy.owner_erasures_table';

    /** @var string The key uses table's setting. */
    private const string KEY_USES_TABLE = 'audit-log.privacy.key_uses_table';

    /** @var list<string> Every key table setting, in the order `validate()` reads them. */
    private const array SETTINGS = [self::SUBJECT_KEYS_TABLE, self::OWNER_ERASURES_TABLE, self::KEY_USES_TABLE];

    /** @var string What every refused table name is refused with, after its key. */
    private const string TABLE_MESSAGE = ' must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.';

    /**
     * The constructor is private; reflection invokes it so the line is covered.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(KeyTables::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(KeyTables::class, $instance);
    }

    /**
     * With no privacy settings at all, each table has its default name.
     *
     * @return void
     */
    public function testTheDefaultsApplyWhenNothingIsSet(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log', array_diff_key($config->array('audit-log'), ['privacy' => true]));

        foreach (self::SETTINGS as $setting) {
            self::assertFalse($config->has($setting), $setting);
        }

        self::assertSame('audit_log_subject_keys', KeyTables::DEFAULT_SUBJECT_KEYS);
        self::assertSame('audit_log_owner_erasures', KeyTables::DEFAULT_OWNER_ERASURES);
        self::assertSame('audit_log_key_uses', KeyTables::DEFAULT_KEY_USES);
        self::assertSame('audit_log_subject_keys', KeyTables::subjectKeysTable());
        self::assertSame('audit_log_owner_erasures', KeyTables::ownerErasuresTable());
        self::assertSame('audit_log_key_uses', KeyTables::keyUsesTable());
    }

    /**
     * Rows of `[value]`: `null` and an empty string, as an unset or empty
     * environment variable leaves a setting.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideUnsetValues(): iterable
    {
        yield from [
            'null'  => [null],
            'empty' => [''],
        ];
    }

    /**
     * A setting that is `null` or empty names its default table, and leaves the
     * others as configured.
     *
     * @param  ?string  $value
     * @return void
     */
    #[DataProvider('provideUnsetValues')]
    public function testANullOrEmptySettingIsItsDefault(?string $value): void
    {
        $config = app(ConfigRepository::class);

        $config->set(array_fill_keys(self::SETTINGS, $value));

        self::assertSame('audit_log_subject_keys', KeyTables::subjectKeysTable());
        self::assertSame('audit_log_owner_erasures', KeyTables::ownerErasuresTable());
        self::assertSame('audit_log_key_uses', KeyTables::keyUsesTable());

        $config->set(self::OWNER_ERASURES_TABLE, 'audit_markers');

        self::assertSame('audit_log_subject_keys', KeyTables::subjectKeysTable());
        self::assertSame('audit_markers', KeyTables::ownerErasuresTable());
        self::assertSame('audit_log_key_uses', KeyTables::keyUsesTable());
    }

    /**
     * Each table is its configured name, read on every call, and no setting
     * changes another's table.
     *
     * @return void
     */
    public function testEachTableIsItsSetting(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::SUBJECT_KEYS_TABLE, 'audit_keys');
        $config->set(self::OWNER_ERASURES_TABLE, 'audit_markers');
        $config->set(self::KEY_USES_TABLE, 'audit_uses');

        self::assertSame('audit_keys', KeyTables::subjectKeysTable());
        self::assertSame('audit_markers', KeyTables::ownerErasuresTable());
        self::assertSame('audit_uses', KeyTables::keyUsesTable());

        $config->set(self::SUBJECT_KEYS_TABLE, str_repeat('k', 47));
        $config->set(self::OWNER_ERASURES_TABLE, '_');
        $config->set(self::KEY_USES_TABLE, 'uses_2');

        self::assertSame(str_repeat('k', 47), KeyTables::subjectKeysTable());
        self::assertSame('_', KeyTables::ownerErasuresTable());
        self::assertSame('uses_2', KeyTables::keyUsesTable());
    }

    /**
     * Rows of `[setting, value]`: per setting, the shapes a table name must not
     * take.
     *
     * @return iterable<string, array{0: string, 1: bool|int|list<string>|string}>
     */
    public static function provideMalformedNames(): iterable
    {
        foreach (self::SETTINGS as $setting) {
            yield from [
                $setting . ': a capital'          => [$setting, 'Audit'],
                $setting . ': a schema'           => [$setting, 'reporting.audit'],
                $setting . ': 48 characters'      => [$setting, str_repeat('a', 48)],
                $setting . ': a leading digit'    => [$setting, '9a'],
                $setting . ': an integer'         => [$setting, 42],
                $setting . ': false'              => [$setting, false],
                $setting . ': a space'            => [$setting, ' '],
                $setting . ': a hyphen'           => [$setting, 'audit-keys'],
                $setting . ': a list'             => [$setting, ['audit']],
                $setting . ': a trailing newline' => [$setting, "audit\n"],
            ];
        }
    }

    /**
     * Each refused table name fails closed, naming its own leaf and the names
     * it takes, rather than falling back to the default.
     *
     * @param  string  $setting
     * @param  bool|int|list<string>|string  $value
     * @return void
     */
    #[DataProvider('provideMalformedNames')]
    public function testRefusesANameOutsideTheGrammarNamingTheLeaf(string $setting, array|bool|int|string $value): void
    {
        app(ConfigRepository::class)->set($setting, $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`' . $setting . '`' . self::TABLE_MESSAGE);

        self::read($setting);
    }

    /**
     * The message names the leaf and the grammar alone: a refused value, which
     * may be anything an operator typed, is never repeated in it.
     *
     * @return void
     */
    public function testAMessageNamesTheLeafAndNeverTheValue(): void
    {
        $config = app(ConfigRepository::class);

        foreach (self::SETTINGS as $setting) {
            $config->set($setting, 'Leaked_Value_9');

            try {
                self::read($setting);
                self::fail('Expected the table to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('`' . $setting . '`' . self::TABLE_MESSAGE, $exception->getMessage(), $setting);
                self::assertStringNotContainsString('Leaked_Value_9', $exception->getMessage(), $setting);
            }

            $config->set($setting, 'audit_valid');
        }
    }

    /**
     * Validation fails closed naming the first malformed setting, in the order
     * it reads them.
     *
     * @return void
     */
    public function testValidateNamesTheFirstBadLeaf(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(array_fill_keys(self::SETTINGS, 'audit_valid'));

        KeyTables::validate();

        foreach (self::SETTINGS as $at => $malformed) {
            $config->set(array_fill_keys(self::SETTINGS, 'audit_valid'));
            $config->set(array_fill_keys(array_slice(self::SETTINGS, $at), 'Audit'));

            try {
                KeyTables::validate();
                self::fail(sprintf('Expected `%s` to be refused.', $malformed));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('`' . $malformed . '`' . self::TABLE_MESSAGE, $exception->getMessage(), $malformed);
            }
        }
    }

    /**
     * Read the table the setting names.
     *
     * @param  string  $setting
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function read(string $setting): string
    {
        return match ($setting) {
            self::SUBJECT_KEYS_TABLE   => KeyTables::subjectKeysTable(),
            self::OWNER_ERASURES_TABLE => KeyTables::ownerErasuresTable(),
            default                    => KeyTables::keyUsesTable(),
        };
    }
}
