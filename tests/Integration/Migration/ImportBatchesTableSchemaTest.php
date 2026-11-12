<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Console\SchemaChecks;
use SineMacula\Laravel\AuditLog\Console\TableShape;
use SineMacula\Laravel\AuditLog\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the import batches table the shipped migration creates,
 * on every engine; a migration is an anonymous class, so they cover nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class ImportBatchesTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped import batches migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_001000_create_audit_log_import_batches_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_import_batches_under_a_long_name_xxxx';

    /** @var string The setting that names the table. */
    private const string SETTING = 'audit-log.import.batches_table';

    /** @var string A table name the setting may give instead, for the rename test. */
    private const string RENAMED = 'audit_renamed_batches';

    /** @var array<string, int> The length of every string column. */
    private const array STRING_LENGTHS = [
        'source_id'          => 64,
        'source_region'      => 32,
        'input_format'       => 32,
        'importer_type'      => 191,
        'importer_id'        => 191,
        'reason'             => 64,
        'external_reference' => 191,
        'file_sha256'        => 64,
        'status'             => 16,
    ];

    /** @var list<string> The columns that hold a time. */
    private const array TIMES = ['started_at', 'updated_at', 'finished_at'];

    /**
     * Migrate `TABLE` with the builder's default precision at whole seconds.
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
     * Twenty-one columns in order; only the region, reference, hold, conflicts
     * and finish are nullable.
     *
     * @return void
     */
    public function testEveryColumnHasItsTypeLengthAndNullability(): void
    {
        $shape   = TableShape::importBatches();
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
     * The indexes are the primary key and the shape's status index.
     *
     * @return void
     */
    public function testTheIndexesAreTheShapesIndexes(): void
    {
        $shape     = TableShape::importBatches();
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
     * Every index name fits PostgreSQL's 63 characters at the longest table
     * name; SQLite names its own primary key, so it is left out.
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
     * On MySQL the table is binary without padding and on InnoDB.
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
     * No column is a reserved word: an unquoted `SELECT` of every one runs.
     *
     * @return void
     */
    public function testNoColumnIsAReservedWord(): void
    {
        DB::table(self::TABLE)->insert(self::row());

        $columns = array_column(Schema::getColumns(self::TABLE), 'name');
        $rows    = DB::select('select ' . implode(', ', $columns) . ' from ' . self::TABLE);

        self::assertCount(1, $rows);
        self::assertSame($columns, array_keys((array) $rows[0]));
        self::assertNotContains('read', $columns);
        self::assertNotContains('format', $columns);
    }

    /**
     * Whether the batch was verified externally is kept as written.
     *
     * @return void
     */
    public function testExternallyVerifiedIsKeptAsWritten(): void
    {
        DB::table(self::TABLE)->insert(self::row(['externally_verified' => false]));

        self::assertFalse((bool) DB::table(self::TABLE)->value('externally_verified'));
    }

    /**
     * Whether the batch was verified externally has no default.
     *
     * @return void
     */
    public function testExternallyVerifiedHasNoDefault(): void
    {
        $row = self::row();

        unset($row['externally_verified']);

        $this->expectException(QueryException::class);

        DB::table(self::TABLE)->insert($row);
    }

    /**
     * The counts are signed, as PostgreSQL has no unsigned integers.
     *
     * @return void
     */
    public function testTheCountsAreIntegersAndARunningBatchHasNoFinish(): void
    {
        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        foreach (['lines_read', 'imported', 'duplicates', 'conflicts', 'rejected'] as $column) {
            self::assertStringNotContainsString('unsigned', $types[$column], $column);
        }

        DB::table(self::TABLE)->insert(self::row(['lines_read' => 2 ** 31 - 1]));

        $row = DB::table(self::TABLE)->first(['lines_read', 'finished_at', 'hold_id', 'conflict_ids']);

        self::assertNotNull($row);
        self::assertSame([2 ** 31 - 1, null, null, null], array_values((array) $row));
    }

    /**
     * An existing table is refused with an exception naming the setting.
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
                . self::CONNECTION . '\'. Set `import.batches_table` in config/audit-log.php to a different name and re-run the migration.',
                $exception->getMessage(),
            );
        }

        self::assertTrue(Schema::hasTable(self::TABLE));
        self::assertSame($before, DB::table(self::TABLE)->count());
    }

    /**
     * A renamed table and its indexes are created under its setting's name.
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
     * A full running batch row with the given columns replaced.
     *
     * @param  array<string, bool|int|string>  $columns
     * @return array<string, bool|int|string>
     */
    private static function row(array $columns = []): array
    {
        return [
            'id'                  => '01932b4e-9000-7000-8000-000000000001',
            'source_id'           => 'legacy-app',
            'input_format'        => 'audit-log-import/v1',
            'importer_type'       => 'operator',
            'importer_id'         => '7',
            'reason'              => 'migration',
            'file_sha256'         => str_repeat('a', 64),
            'externally_verified' => false,
            'status'              => 'running',
            'lines_read'          => 0,
            'imported'            => 0,
            'duplicates'          => 0,
            'conflicts'           => 0,
            'rejected'            => 0,
            'started_at'          => '2026-11-01 12:00:00.000000',
            'updated_at'          => '2026-11-01 12:00:00.000000',
            ...$columns,
        ];
    }

    /**
     * Require the shipped migration file and return its instance.
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
            self::fail('The import batches migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
