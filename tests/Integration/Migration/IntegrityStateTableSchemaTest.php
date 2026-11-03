<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the shape of the table the shipped integrity state
 * migration creates, on whichever engine the suite runs against.
 *
 * The migration runs for the longest table name the setting accepts and with
 * the schema builder's default time precision lowered to whole seconds, so the
 * key's name and the microsecond precision are what the migration itself
 * declares.
 *
 * Marked `#[CoversNothing]` because a migration is an anonymous class PHPUnit
 * cannot attribute coverage to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class IntegrityStateTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped integrity state migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000500_create_audit_log_integrity_state_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_integrity_state_for_a_long_table_name';

    /**
     * Run the shipped migration for `TABLE`, with the schema builder's default
     * time precision lowered to whole seconds while it runs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('audit-log.integrity.state_table', self::TABLE);

        Schema::dropIfExists(self::TABLE);

        $precision = Builder::$defaultTimePrecision;

        Builder::defaultTimePrecision(0);

        try {
            $this->loadMigration()->up(); // @phpstan-ignore method.notFound
        } finally {
            Builder::defaultTimePrecision($precision);
        }
    }

    /**
     * Drop the table the test migrated.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::TABLE);

        parent::tearDown();
    }

    /**
     * The table holds a name, its value and when it was written, in that order,
     * and none of them may be missing.
     *
     * @return void
     */
    public function testCreatesEveryColumnWithItsNullability(): void
    {
        self::assertSame([
            'name'       => false,
            'value'      => false,
            'updated_at' => false,
        ], array_column(Schema::getColumns(self::TABLE), 'nullable', 'name'));
    }

    /**
     * The name is the primary key, alone, so each name holds one value, and is
     * the table's only index.
     *
     * @return void
     */
    public function testTheNameIsThePrimaryKey(): void
    {
        $indexes = Schema::getIndexes(self::TABLE);

        self::assertCount(1, $indexes);

        $key = reset($indexes);

        self::assertTrue($key['primary']);
        self::assertSame(['name'], $key['columns']);

        DB::table(self::TABLE)->insert(self::row('seal.last'));

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row('seal.last'));
    }

    /**
     * The name has 64 characters, and the value is text, so a value is never
     * cut to a length.
     *
     * @return void
     */
    public function testTheValueIsText(): void
    {
        $columns = Schema::getColumns(self::TABLE);
        $names   = array_column($columns, 'type_name', 'name');

        self::assertSame('text', $names['value']);

        if (Schema::getConnection()->getDriverName() !== 'sqlite') {
            self::assertStringContainsString('(64)', array_column($columns, 'type', 'name')['name']);
        }

        $value = '{"cursor":"' . str_repeat('a', 4000) . '"}';

        DB::table(self::TABLE)->insert(self::row('sweep.cursor', ['value' => $value]));

        self::assertSame($value, DB::table(self::TABLE)->value('value'));
    }

    /**
     * When a value was written is stored to the microsecond, as the migration
     * declares whatever the builder's default.
     *
     * @return void
     */
    public function testStoresTheTimeToTheMicrosecond(): void
    {
        if (Schema::getConnection()->getDriverName() !== 'sqlite') {
            self::assertStringContainsString('(6)', array_column(Schema::getColumns(self::TABLE), 'type', 'name')['updated_at']);
        }

        DB::table(self::TABLE)->insert(self::row('seal.last', ['updated_at' => '2026-11-01 12:00:00.123456']));

        self::assertSame('2026-11-01 12:00:00.123456', DB::table(self::TABLE)->value('updated_at'));
    }

    /**
     * At the longest table name the setting accepts, the key's name fits
     * PostgreSQL's 63 characters; MySQL calls every primary key `primary`.
     *
     * @return void
     */
    public function testTheKeyNameFitsAtTheLongestTableName(): void
    {
        $driver = Schema::getConnection()->getDriverName();

        if ($driver === 'sqlite') {
            self::markTestSkipped('SQLite names its primary key index itself and limits no name.');
        }

        self::assertSame(47, strlen(self::TABLE));

        $names = array_column(Schema::getIndexes(self::TABLE), 'name');

        self::assertCount(1, $names);
        self::assertLessThanOrEqual(63, strlen($names[0]));
        self::assertSame($driver === 'pgsql' ? self::TABLE . '_pkey' : 'primary', $names[0]);
    }

    /**
     * The table has no foreign keys, so progress needs nothing of the seals it
     * describes, and may be lost without touching them.
     *
     * @return void
     */
    public function testHasNoForeignKeys(): void
    {
        self::assertSame([], Schema::getForeignKeys(self::TABLE));
        self::assertFalse(Schema::hasColumn(self::TABLE, 'created_at'));
    }

    /**
     * On MySQL every character column takes the table's binary collation
     * without padding, and the table is on InnoDB, whatever the connection's
     * defaults are.
     *
     * @return void
     */
    public function testOnMySqlEveryCharacterColumnIsBinaryWithoutPadding(): void
    {
        if (Schema::getConnection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL compares by a collation the migration sets.');
        }

        $collations = array_filter(array_column(Schema::getColumns(self::TABLE), 'collation', 'name'), static fn (?string $collation): bool => $collation !== null);

        self::assertSame(['name' => 'utf8mb4_0900_bin', 'value' => 'utf8mb4_0900_bin'], $collations);

        $tables = Schema::getTables();

        self::assertSame('utf8mb4_0900_bin', array_column($tables, 'collation', 'name')[self::TABLE]);
        self::assertSame('InnoDB', array_column($tables, 'engine', 'name')[self::TABLE]);
    }

    /**
     * Rolling the migration back drops the configured table.
     *
     * @return void
     */
    public function testRollsBackByDroppingTheTable(): void
    {
        $this->loadMigration()->down(); // @phpstan-ignore method.notFound

        self::assertFalse(Schema::hasTable(self::TABLE));
    }

    /**
     * Running the migration when the configured table already exists throws a
     * `TableAlreadyExistsException` naming the table, the connection and the
     * `integrity.state_table` setting that renames it, and leaves the table as
     * it was.
     *
     * @return void
     */
    public function testAnExistingTableStopsTheMigrationNamingTheSetting(): void
    {
        DB::table(self::TABLE)->insert(self::row('seal.last'));

        try {
            $this->loadMigration()->up(); // @phpstan-ignore method.notFound
            self::fail('Expected the migration to stop.');
        } catch (TableAlreadyExistsException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame(
                'Cannot install the laravel-audit-log migration for the \'' . self::TABLE . '\' table: a table with that name already exists on connection \''
                . self::CONNECTION . '\'. Set `integrity.state_table` in config/audit-log.php to a different name and re-run the migration.',
                $exception->getMessage(),
            );
        }

        self::assertSame(1, DB::table(self::TABLE)->count());
    }

    /**
     * A progress row under the name, with the given columns replaced.
     *
     * @param  string  $name
     * @param  array<string, string>  $columns
     * @return array<string, string>
     */
    private static function row(string $name, array $columns = []): array
    {
        return [
            'name'       => $name,
            'value'      => '{"sequence":1}',
            'updated_at' => '2026-11-01 12:00:00.000000',
            ...$columns,
        ];
    }

    /**
     * Require the shipped anonymous-class migration file and return the
     * resulting `Migration` instance.
     *
     * @return \Illuminate\Database\Migrations\Migration
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function loadMigration(): Migration
    {
        $migration = include self::MIGRATION_PATH;

        if (!$migration instanceof Migration) {
            self::fail('Integrity state migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
