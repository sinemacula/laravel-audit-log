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
 * Integration tests for the lifecycle lock the shipped migration creates, on
 * every engine; a migration is an anonymous class, so they cover nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class LifecycleLockTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped lifecycle lock migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000900_create_audit_log_lifecycle_lock_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_lifecycle_lock_under_a_long_name_xxxx';

    /** @var string The setting that names the table. */
    private const string SETTING = 'audit-log.lifecycle.lock_table';

    /** @var string A table name the setting may give instead, for the rename test. */
    private const string RENAMED = 'audit_renamed_lock';

    /** @var array<string, int> The length of every string column. */
    private const array STRING_LENGTHS = [
        'token' => 64,
    ];

    /** @var list<string> The columns that hold a time. */
    private const array TIMES = ['locked_at'];

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
     * The lock's three columns in order; the token and time are nullable.
     *
     * @return void
     */
    public function testEveryColumnHasItsTypeLengthAndNullability(): void
    {
        $shape   = TableShape::lock();
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
     * The primary key is the row's id, and there is no other index.
     *
     * @return void
     */
    public function testTheIndexesAreTheShapesIndexes(): void
    {
        $shape     = TableShape::lock();
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
     * The migration seeds one row, `id` 1, for the first transaction to lock.
     *
     * @return void
     */
    public function testTheMigrationSeedsTheOneLockRow(): void
    {
        $rows = DB::table(self::TABLE)->get(['id', 'token', 'locked_at'])->all();

        self::assertCount(1, $rows);
        self::assertSame(1, (int) $rows[0]->id);
        self::assertNull($rows[0]->token);
        self::assertNull($rows[0]->locked_at);
    }

    /**
     * The lock row is taken by an update; a second row under its id is refused.
     *
     * @return void
     */
    public function testTheLockRowIsUpdatedAndKeptOnce(): void
    {
        $token = str_repeat('a', 36) . ':' . str_repeat('b', 16);

        self::assertSame(53, strlen($token));
        self::assertSame(1, DB::table(self::TABLE)->where('id', 1)->update(['token' => $token, 'locked_at' => '2026-11-01 12:00:00.123456']));
        self::assertSame($token, DB::table(self::TABLE)->where('id', 1)->value('token'));
        self::assertSame('2026-11-01 12:00:00.123456', DB::table(self::TABLE)->where('id', 1)->value('locked_at'));

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(['id' => 1, 'token' => null, 'locked_at' => null]);
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
                . self::CONNECTION . '\'. Set `lifecycle.lock_table` in config/audit-log.php to a different name and re-run the migration.',
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
            self::fail('The lifecycle lock migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
