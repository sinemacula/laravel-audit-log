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
 * Integration tests for the shape of the owner erasures table the shipped
 * migration creates, on whichever engine the suite runs against: its columns in
 * order with their types, lengths and nullability, an owner's markers indexed
 * in journal order, a journal sequence beyond 32 bits, and the collision guard,
 * the setting that renames it and its rollback.
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
     * The table holds the seven columns of a marker, in order, each with the
     * type family, length and nullability the shape gives it, none of them
     * nullable, and the schema checks find nothing wrong with it.
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
     * The primary key is the journal row's id, and the one other index is an
     * owner's markers in journal order, named after the table: the owner's
     * latest marker is read from it.
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
     * An owner may hold any number of markers, each at its own journal
     * sequence, a sequence beyond 32 bits included, and the latest is the one
     * with the highest sequence.
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
     * At the longest table name the setting accepts, every index name fits
     * PostgreSQL's 63 characters; on MySQL the table is binary without padding
     * and on InnoDB, as every table the package keeps.
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
     * Running the migration when the configured table already exists throws a
     * `TableAlreadyExistsException` naming the table, the connection and the
     * `privacy.owner_erasures_table` setting that renames it, and leaves the
     * table and its markers as they were.
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
     * The table is created under whatever name its setting gives, and its index
     * is named after it.
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
     * A marker of one owner, numbered so its id is its own, with its transition
     * and its journal row's sequence.
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
            self::fail('The owner erasures migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
