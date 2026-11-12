<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use Tests\TestCase;

/**
 * Feature tests for the integrity table names, and the refusal that names the
 * key and never the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegrityTables::class)]
final class IntegrityTablesTest extends TestCase
{
    /** @var string The seals table's setting. */
    private const string CHECKPOINTS_TABLE = 'audit-log.integrity.checkpoints_table';

    /** @var string The members table's setting. */
    private const string MEMBERS_TABLE = 'audit-log.integrity.members_table';

    /** @var string The progress table's setting. */
    private const string STATE_TABLE = 'audit-log.integrity.state_table';

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
        $reflection  = new \ReflectionClass(IntegrityTables::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(IntegrityTables::class, $instance);
    }

    /**
     * With no integrity settings at all, each table has its default name.
     *
     * @return void
     */
    public function testTheTablesHaveTheirDefaults(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log', array_diff_key($config->array('audit-log'), ['integrity' => true]));

        self::assertFalse($config->has(self::CHECKPOINTS_TABLE));
        self::assertFalse($config->has(self::MEMBERS_TABLE));
        self::assertFalse($config->has(self::STATE_TABLE));
        self::assertSame('audit_log_checkpoints', IntegrityTables::DEFAULT_CHECKPOINTS);
        self::assertSame('audit_log_checkpoint_members', IntegrityTables::DEFAULT_MEMBERS);
        self::assertSame('audit_log_integrity_state', IntegrityTables::DEFAULT_STATE);
        self::assertSame('audit_log_checkpoints', IntegrityTables::checkpointsTable());
        self::assertSame('audit_log_checkpoint_members', IntegrityTables::membersTable());
        self::assertSame('audit_log_integrity_state', IntegrityTables::stateTable());
    }

    /**
     * Each table is the configured name, read on every call, and no setting
     * changes another's table.
     *
     * @return void
     */
    public function testEachTableIsReadAsConfigured(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::CHECKPOINTS_TABLE, 'audit_seals');
        $config->set(self::MEMBERS_TABLE, 'audit_seal_members');
        $config->set(self::STATE_TABLE, 'audit_progress');

        self::assertSame('audit_seals', IntegrityTables::checkpointsTable());
        self::assertSame('audit_seal_members', IntegrityTables::membersTable());
        self::assertSame('audit_progress', IntegrityTables::stateTable());

        $config->set(self::CHECKPOINTS_TABLE, str_repeat('a', 47));
        $config->set(self::MEMBERS_TABLE, '_');
        $config->set(self::STATE_TABLE, 'state_2');

        self::assertSame(str_repeat('a', 47), IntegrityTables::checkpointsTable());
        self::assertSame('_', IntegrityTables::membersTable());
        self::assertSame('state_2', IntegrityTables::stateTable());
    }

    /**
     * Rows of `[setting, value]`: per setting, the shapes a table name must not
     * take.
     *
     * @return iterable<string, array{0: string, 1: int|list<string>|string|null}>
     */
    public static function provideMalformedTables(): iterable
    {
        foreach ([self::CHECKPOINTS_TABLE, self::MEMBERS_TABLE, self::STATE_TABLE] as $setting) {
            yield from [
                $setting . ': a capital'          => [$setting, 'Audit'],
                $setting . ': a leading digit'    => [$setting, '9a'],
                $setting . ': 48 characters'      => [$setting, str_repeat('a', 48)],
                $setting . ': an integer'         => [$setting, 42],
                $setting . ': null'               => [$setting, null],
                $setting . ': empty'              => [$setting, ''],
                $setting . ': a schema'           => [$setting, 'reporting.audit'],
                $setting . ': a hyphen'           => [$setting, 'audit-seals'],
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
    #[DataProvider('provideMalformedTables')]
    public function testRefusesAMalformedTable(string $setting, array|int|string|null $value): void
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

        foreach ([self::CHECKPOINTS_TABLE, self::MEMBERS_TABLE, self::STATE_TABLE] as $setting) {
            $config->set($setting, 'Leaked_Value_9');

            try {
                self::read($setting);
                self::fail('Expected the table to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('`' . $setting . '`' . self::TABLE_MESSAGE, $exception->getMessage(), $setting);
                self::assertStringNotContainsString('Leaked_Value_9', $exception->getMessage(), $setting);
            }
        }
    }

    /**
     * A malformed table refuses only its own setting: the others are read as
     * configured.
     *
     * @return void
     */
    public function testAMalformedTableLeavesTheOthersReadable(): void
    {
        $config = app(ConfigRepository::class);

        $config->set(self::CHECKPOINTS_TABLE, 'Audit');

        self::assertSame('audit_log_checkpoint_members', IntegrityTables::membersTable());
        self::assertSame('audit_log_integrity_state', IntegrityTables::stateTable());

        $config->set(self::CHECKPOINTS_TABLE, 'audit_log_checkpoints');
        $config->set(self::MEMBERS_TABLE, 'Audit');

        self::assertSame('audit_log_checkpoints', IntegrityTables::checkpointsTable());
        self::assertSame('audit_log_integrity_state', IntegrityTables::stateTable());

        $config->set(self::MEMBERS_TABLE, 'audit_log_checkpoint_members');
        $config->set(self::STATE_TABLE, 'Audit');

        self::assertSame('audit_log_checkpoints', IntegrityTables::checkpointsTable());
        self::assertSame('audit_log_checkpoint_members', IntegrityTables::membersTable());
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
            self::CHECKPOINTS_TABLE => IntegrityTables::checkpointsTable(),
            self::MEMBERS_TABLE     => IntegrityTables::membersTable(),
            default                 => IntegrityTables::stateTable(),
        };
    }
}
