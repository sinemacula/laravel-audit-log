<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use Tests\TestCase;

/**
 * Feature tests for what the lifecycle tables are called: the four table names,
 * their defaults, each read as configured on every call, the names each
 * refuses, with a message that names the key and never the value, and the
 * validation that reads every one of them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleTables::class)]
final class LifecycleTablesTest extends TestCase
{
    /** @var string The journal table's setting. */
    private const string JOURNAL_TABLE = 'audit-log.lifecycle.journal_table';

    /** @var string The holds table's setting. */
    private const string HOLDS_TABLE = 'audit-log.lifecycle.holds_table';

    /** @var string The lock table's setting. */
    private const string LOCK_TABLE = 'audit-log.lifecycle.lock_table';

    /** @var string The import batches table's setting. */
    private const string IMPORT_BATCHES_TABLE = 'audit-log.import.batches_table';

    /** @var list<string> Every lifecycle table setting, in the order `validate()` reads them. */
    private const array SETTINGS = [self::JOURNAL_TABLE, self::HOLDS_TABLE, self::LOCK_TABLE, self::IMPORT_BATCHES_TABLE];

    /** @var string What every refused table name is refused with, after its key. */
    private const string TABLE_MESSAGE = ' must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.';

    /**
     * `LifecycleTables` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(LifecycleTables::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(LifecycleTables::class, $instance);
    }

    /**
     * With no lifecycle or import settings at all, the journal is in
     * `audit_log_lifecycle`, the holds in `audit_log_holds`, the lock in
     * `audit_log_lifecycle_lock` and the batches in `audit_log_import_batches`.
     *
     * @return void
     */
    public function testTheDefaultsApplyWhenNothingIsSet(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log', array_diff_key($config->array('audit-log'), ['lifecycle' => true, 'import' => true]));

        foreach (self::SETTINGS as $setting) {
            self::assertFalse($config->has($setting), $setting);
        }

        self::assertSame('audit_log_lifecycle', LifecycleTables::DEFAULT_JOURNAL);
        self::assertSame('audit_log_holds', LifecycleTables::DEFAULT_HOLDS);
        self::assertSame('audit_log_lifecycle_lock', LifecycleTables::DEFAULT_LOCK);
        self::assertSame('audit_log_import_batches', LifecycleTables::DEFAULT_IMPORT_BATCHES);
        self::assertSame('audit_log_lifecycle', LifecycleTables::journalTable());
        self::assertSame('audit_log_holds', LifecycleTables::holdsTable());
        self::assertSame('audit_log_lifecycle_lock', LifecycleTables::lockTable());
        self::assertSame('audit_log_import_batches', LifecycleTables::importBatchesTable());
    }

    /**
     * Each table is the configured name, read on every call, and no setting
     * changes another's table.
     *
     * @return void
     */
    public function testEachNameIsReadFromItsSetting(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::JOURNAL_TABLE, 'audit_journal');
        $config->set(self::HOLDS_TABLE, 'audit_holds');
        $config->set(self::LOCK_TABLE, 'audit_lock');
        $config->set(self::IMPORT_BATCHES_TABLE, 'audit_imports');

        self::assertSame('audit_journal', LifecycleTables::journalTable());
        self::assertSame('audit_holds', LifecycleTables::holdsTable());
        self::assertSame('audit_lock', LifecycleTables::lockTable());
        self::assertSame('audit_imports', LifecycleTables::importBatchesTable());

        $config->set(self::JOURNAL_TABLE, str_repeat('a', 47));
        $config->set(self::HOLDS_TABLE, '_');
        $config->set(self::LOCK_TABLE, 'lock_2');
        $config->set(self::IMPORT_BATCHES_TABLE, 'b');

        self::assertSame(str_repeat('a', 47), LifecycleTables::journalTable());
        self::assertSame('_', LifecycleTables::holdsTable());
        self::assertSame('lock_2', LifecycleTables::lockTable());
        self::assertSame('b', LifecycleTables::importBatchesTable());
    }

    /**
     * Rows of `[setting, value]`: per setting, a capital, a schema-qualified
     * name, one character too many, a leading digit, a value that is no string,
     * a `null` set explicitly, and the other shapes a table name must not take.
     *
     * @return iterable<string, array{0: string, 1: int|list<string>|string|null}>
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
                $setting . ': null'               => [$setting, null],
                $setting . ': empty'              => [$setting, ''],
                $setting . ': a hyphen'           => [$setting, 'audit-holds'],
                $setting . ': a list'             => [$setting, ['audit']],
                $setting . ': a trailing newline' => [$setting, "audit\n"],
            ];
        }
    }

    /**
     * Each refused table name fails closed, naming its own setting and the
     * names it takes, rather than falling back to the default.
     *
     * @param  string  $setting
     * @param  int|list<string>|string|null  $value
     * @return void
     */
    #[DataProvider('provideMalformedNames')]
    public function testRefusesAMalformedNameNamingTheKey(string $setting, array|int|string|null $value): void
    {
        app(ConfigRepository::class)->set($setting, $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`' . $setting . '`' . self::TABLE_MESSAGE);

        self::read($setting);
    }

    /**
     * The message names the key and the grammar alone: a refused value, which
     * may be anything an operator typed, is never repeated in it.
     *
     * @return void
     */
    public function testAMessageNamesTheKeyAndNeverTheValue(): void
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
     * A malformed table refuses only its own setting: the others are read as
     * configured.
     *
     * @return void
     */
    public function testAMalformedNameLeavesTheOthersReadable(): void
    {
        $config = app(ConfigRepository::class);

        foreach (self::SETTINGS as $malformed) {
            $config->set(array_fill_keys(self::SETTINGS, 'audit_valid'));
            $config->set($malformed, 'Audit');

            foreach (array_diff(self::SETTINGS, [$malformed]) as $setting) {
                self::assertSame('audit_valid', self::read($setting), $setting);
            }
        }
    }

    /**
     * Validation reads every setting: with all four well-formed it passes, and
     * with any one malformed it fails closed naming that one, whichever it is.
     *
     * @return void
     */
    public function testValidateReadsEverySetting(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(array_fill_keys(self::SETTINGS, 'audit_valid'));

        LifecycleTables::validate();

        foreach (self::SETTINGS as $malformed) {
            $config->set(array_fill_keys(self::SETTINGS, 'audit_valid'));
            $config->set($malformed, 'Audit');

            try {
                LifecycleTables::validate();
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
            self::JOURNAL_TABLE => LifecycleTables::journalTable(),
            self::HOLDS_TABLE   => LifecycleTables::holdsTable(),
            self::LOCK_TABLE    => LifecycleTables::lockTable(),
            default             => LifecycleTables::importBatchesTable(),
        };
    }
}
