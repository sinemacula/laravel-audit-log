<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Console\SchemaChecks;
use SineMacula\Laravel\AuditLog\Console\TableShape;
use SineMacula\Laravel\AuditLog\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the owner erasures table the shipped migration creates,
 * on every engine; a migration is an anonymous class, so they cover nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class OwnerErasuresTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped owner erasures migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_001200_create_audit_log_owner_erasures_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_owner_erasures_under_a_long_tablexxxx';

    /** @var string The setting that names the table. */
    private const string SETTING = 'audit-log.privacy.owner_erasures_table';

    /** @var string A table name the setting may give instead, for the rename test. */
    private const string RENAMED = 'audit_renamed_owner_erasures';

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
     * Seven columns in order with their types, none nullable.
     *
     * @return void
     */
    public function testTheColumnsAreInOrderWithTheirTypes(): void
    {
        $shape   = TableShape::ownerErasures();
        $columns = Schema::getColumns(self::TABLE);

        self::assertSame(array_keys($shape->columns), array_column($columns, 'name'));
        self::assertSame(array_fill_keys(array_keys($shape->columns), false), array_column($columns, 'nullable', 'name'));
        self::assertSame([], (new SchemaChecks(app(DatabaseManager::class)))->problems(self::CONNECTION, self::TABLE, $shape));

        if (Schema::getConnection()->getDriverName() === 'sqlite') {
            return;
        }

        $types = array_column($columns, 'type', 'name');

        foreach (['owner_type' => 191, 'owner_id' => 191, 'transition' => 16, 'created_at' => 6] as $column => $size) {
            self::assertStringContainsString('(' . $size . ')', $types[$column], $column);
        }
    }

    /**
     * The only other index holds an owner's markers in journal order.
     *
     * @return void
     */
    public function testTheOwnerIsIndexedWithItsSequence(): void
    {
        $indexes   = Schema::getIndexes(self::TABLE);
        $primary   = array_values(array_filter($indexes, static fn (array $index): bool => $index['primary']));
        $secondary = array_values(array_filter($indexes, static fn (array $index): bool => !$index['primary']));

        self::assertCount(1, $primary);
        self::assertSame(['id'], $primary[0]['columns']);
        self::assertCount(1, $secondary);
        self::assertSame(self::TABLE . '_owner_index', $secondary[0]['name']);
        self::assertSame(['owner_type', 'owner_id', 'journal_sequence'], $secondary[0]['columns']);
        self::assertFalse($secondary[0]['unique']);
    }

    /**
     * An owner's markers are kept in journal order, past 32-bit sequences.
     *
     * @return void
     */
    public function testAnOwnersMarkersAreKeptInJournalOrder(): void
    {
        DB::table(self::TABLE)->insert([
            self::row(1, 'erased', 2 ** 40),
            self::row(2, 'reinstated', 2 ** 40 + 1),
            self::row(3, 'erased', 7),
        ]);

        $latest = DB::table(self::TABLE)
            ->where('owner_type', 'customer')
            ->where('owner_id', '42')
            ->orderByDesc('journal_sequence')
            ->first(['transition', 'journal_sequence']);

        self::assertNotNull($latest);
        self::assertSame(['reinstated', 2 ** 40 + 1], [$latest->transition, (int) $latest->journal_sequence]);
        self::assertSame(3, DB::table(self::TABLE)->count());
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
     * Index names fit PostgreSQL's limit; on MySQL the table is binary InnoDB.
     *
     * @return void
     */
    public function testTheNamesFitAndOnMySqlTheTableIsBinaryAndInnoDb(): void
    {
        self::assertSame(47, strlen(self::TABLE));

        $driver = Schema::getConnection()->getDriverName();

        foreach (Schema::getIndexes(self::TABLE) as $index) {
            self::assertTrue(($driver === 'sqlite' && $index['primary']) || strlen($index['name']) <= 63, $index['name']);
        }

        if ($driver !== 'mysql') {
            return;
        }

        $tables = array_column(Schema::getTables(), null, 'name');

        self::assertSame('utf8mb4_0900_bin', $tables[self::TABLE]['collation']);
        self::assertSame('InnoDB', $tables[self::TABLE]['engine']);
    }

    /**
     * An existing table is refused naming the setting, and keeps its markers.
     *
     * @return void
     */
    public function testAnExistingTableIsNeverReplaced(): void
    {
        DB::table(self::TABLE)->insert(self::row(1, 'erased', 1));

        try {
            $this->loadMigration()->up(); // @phpstan-ignore method.notFound
            self::fail('Expected the migration to stop.');
        } catch (TableAlreadyExistsException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame(
                'Cannot install the laravel-audit-log migration for the \'' . self::TABLE . '\' table: a table with that name already exists on connection \''
                . self::CONNECTION . '\'. Set `privacy.owner_erasures_table` in config/audit-log.php to a different name and re-run the migration.',
                $exception->getMessage(),
            );
        }

        self::assertTrue(Schema::hasTable(self::TABLE));
        self::assertSame(1, DB::table(self::TABLE)->count());
    }

    /**
     * A renamed table and its index are created under its setting's name.
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
     * A marker of one owner, numbered so its id is its own.
     *
     * @param  int  $number
     * @param  string  $transition
     * @param  int  $sequence
     * @return array<string, int|string>
     */
    private static function row(int $number, string $transition, int $sequence): array
    {
        return [
            'id'               => sprintf('01932b4e-9000-7000-8000-%012d', $number),
            'owner_type'       => 'customer',
            'owner_id'         => '42',
            'transition'       => $transition,
            'generation_floor' => 3,
            'journal_sequence' => $sequence,
            'created_at'       => '2026-11-01 12:00:00.000000',
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
            self::fail('The owner erasures migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
