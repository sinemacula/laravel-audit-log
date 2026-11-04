<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Console\SchemaChecks;
use SineMacula\Laravel\AuditLog\Console\TableShape;
use SineMacula\Laravel\AuditLog\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the shape of the holds projection the shipped migration
 * creates, on whichever engine the suite runs against: its columns, their
 * types, lengths and nullability, the shape's indexes, one row per hold, and
 * the collision guard, the setting that renames it and its rollback.
 *
 * The migration runs for the longest table name the setting accepts and with
 * the schema builder's default time precision lowered to whole seconds, so the
 * index names and the microsecond precision are what the migration itself
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
final class HoldsTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped holds migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000800_create_audit_log_holds_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_holds_under_a_very_long_table_name_xx';

    /** @var string The setting that names the table. */
    private const string SETTING = 'audit-log.lifecycle.holds_table';

    /** @var string A table name the setting may give instead, for the rename test. */
    private const string RENAMED = 'audit_renamed_holds';

    /** @var array<string, int> The length of every string column. */
    private const array STRING_LENGTHS = [
        'scope_digest'       => 64,
        'basis'              => 32,
        'authority_type'     => 191,
        'authority_id'       => 191,
        'reason'             => 64,
        'external_reference' => 191,
    ];

    /** @var list<string> The columns that hold a time. */
    private const array TIMES = ['placed_at', 'review_by'];

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

        config()->set(self::SETTING, self::TABLE);

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
     * Drop the tables the test migrated.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::TABLE);
        Schema::dropIfExists(self::RENAMED);

        parent::tearDown();
    }

    /**
     * The table holds the thirteen columns of a hold, in order, each with the
     * type family, length and nullability the shape gives it: only the import
     * batch, the review date and the external reference may be missing.
     *
     * @return void
     */
    public function testEveryColumnHasItsTypeLengthAndNullability(): void
    {
        $shape   = TableShape::holds();
        $columns = Schema::getColumns(self::TABLE);

        self::assertSame(array_keys($shape->columns), array_column($columns, 'name'));
        self::assertSame(array_map(static fn (array $column): bool => $column[2], $shape->columns), array_column($columns, 'nullable', 'name'));
        self::assertSame([], (new SchemaChecks(app(DatabaseManager::class)))->problems(self::CONNECTION, self::TABLE, $shape));

        if (Schema::getConnection()->getDriverName() === 'sqlite') {
            return;
        }

        $types = array_column($columns, 'type', 'name');

        foreach (self::STRING_LENGTHS as $column => $length) {
            self::assertStringContainsString('(' . $length . ')', $types[$column], $column);
        }

        foreach (self::TIMES as $column) {
            self::assertStringContainsString('(6)', $types[$column], $column);
        }
    }

    /**
     * The primary key is the hold's id, and the other indexes are exactly the
     * shape's: the holds by review date and by import batch, each named after
     * the table.
     *
     * @return void
     */
    public function testTheIndexesAreTheShapesIndexes(): void
    {
        $shape     = TableShape::holds();
        $indexes   = Schema::getIndexes(self::TABLE);
        $primary   = array_values(array_filter($indexes, static fn (array $index): bool => $index['primary']));
        $secondary = [];

        foreach ($indexes as $index) {
            if ($index['primary']) {
                continue;
            }

            $secondary[substr($index['name'], strlen(self::TABLE))] = [$index['columns'], $index['unique']];
        }

        ksort($secondary);

        $expected = $shape->indexes;

        ksort($expected);

        self::assertCount(1, $primary);
        self::assertSame($shape->primary, $primary[0]['columns']);
        self::assertSame($expected, $secondary);
    }

    /**
     * At the longest table name the setting accepts, every index name fits
     * PostgreSQL's 63 characters. SQLite names its primary key index itself and
     * limits no name, so there the primary key is left out.
     *
     * @return void
     */
    public function testEveryIndexNameFitsAtTheLongestTableName(): void
    {
        self::assertSame(47, strlen(self::TABLE));

        $sqlite  = Schema::getConnection()->getDriverName() === 'sqlite';
        $indexes = array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$sqlite || !$index['primary']);

        foreach (array_column($indexes, 'name') as $name) {
            self::assertLessThanOrEqual(63, strlen($name), $name);
        }
    }

    /**
     * The table has no foreign keys, so nothing cascades into or out of it.
     *
     * @return void
     */
    public function testHasNoForeignKeys(): void
    {
        self::assertSame([], Schema::getForeignKeys(self::TABLE));
    }

    /**
     * On MySQL the table is binary without padding and on InnoDB, as every
     * table the package keeps.
     *
     * @return void
     */
    public function testOnMySqlTheTableIsBinaryAndInnoDb(): void
    {
        if (Schema::getConnection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL has a collation and a storage engine per table.');
        }

        $tables = array_column(Schema::getTables(), null, 'name');

        self::assertSame('utf8mb4_0900_bin', $tables[self::TABLE]['collation']);
        self::assertSame('InnoDB', $tables[self::TABLE]['engine']);
    }

    /**
     * A hold is kept once: a second row under one hold id is refused.
     *
     * @return void
     */
    public function testAHoldIsKeptOnce(): void
    {
        DB::table(self::TABLE)->insert(self::row());

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row(['journal_sequence' => 2]));
    }

    /**
     * The scope is text kept byte for byte, and a hold placed with no import
     * batch, no review date and no external reference stores none.
     *
     * @return void
     */
    public function testTheScopeIsTextAndTheOptionalColumnsMayBeMissing(): void
    {
        $scope = '{"tenants":[["team","42"]],"categories":["security"]}';

        DB::table(self::TABLE)->insert(self::row(['scope' => $scope]));

        $row = DB::table(self::TABLE)->first(['scope', 'import_batch_id', 'review_by', 'external_reference']);

        self::assertNotNull($row);
        self::assertSame([$scope, null, null, null], array_values((array) $row));
    }

    /**
     * Running the migration when the configured table already exists throws a
     * `TableAlreadyExistsException` naming the table, the connection and the
     * `lifecycle.holds_table` setting that renames it, and leaves the table as
     * it was.
     *
     * @return void
     */
    public function testTheMigrationRefusesAnExistingTable(): void
    {
        $before = DB::table(self::TABLE)->count();

        try {
            $this->loadMigration()->up(); // @phpstan-ignore method.notFound
            self::fail('Expected the migration to stop.');
        } catch (TableAlreadyExistsException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame(
                'Cannot install the laravel-audit-log migration for the \'' . self::TABLE . '\' table: a table with that name already exists on connection \''
                . self::CONNECTION . '\'. Set `lifecycle.holds_table` in config/audit-log.php to a different name and re-run the migration.',
                $exception->getMessage(),
            );
        }

        self::assertTrue(Schema::hasTable(self::TABLE));
        self::assertSame($before, DB::table(self::TABLE)->count());
    }

    /**
     * The table is created under whatever name its setting gives, and its
     * indexes are named after it.
     *
     * @return void
     */
    public function testARenamedTableIsCreatedUnderItsSetting(): void
    {
        config()->set(self::SETTING, self::RENAMED);

        self::assertFalse(Schema::hasTable(self::RENAMED));

        $this->loadMigration()->up(); // @phpstan-ignore method.notFound

        self::assertTrue(Schema::hasTable(self::RENAMED));

        foreach (Schema::getIndexes(self::RENAMED) as $index) {
            self::assertTrue($index['primary'] || str_starts_with($index['name'], self::RENAMED . '_'), $index['name']);
        }
    }

    /**
     * Rolling the migration back drops the configured table.
     *
     * @return void
     */
    public function testDownDropsTheTable(): void
    {
        $this->loadMigration()->down(); // @phpstan-ignore method.notFound

        self::assertFalse(Schema::hasTable(self::TABLE));
    }

    /**
     * A hold with every column a hold must have, with the given columns
     * replaced.
     *
     * @param  array<string, int|string>  $columns
     * @return array<string, int|string>
     */
    private static function row(array $columns = []): array
    {
        return [
            'hold_id'          => '01932b4e-9000-7000-8000-000000000001',
            'scope'            => '{}',
            'scope_digest'     => str_repeat('a', 64),
            'basis'            => 'litigation',
            'placed_at'        => '2026-11-01 12:00:00.000000',
            'authority_type'   => 'operator',
            'authority_id'     => '7',
            'reason'           => 'legal_hold',
            'operation_id'     => '01932b4e-9000-7000-8000-00000000aaaa',
            'journal_sequence' => 1,
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
            self::fail('The holds migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
