<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Console\SchemaChecks;
use SineMacula\Laravel\AuditLog\Console\TableShape;
use SineMacula\Laravel\AuditLog\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the key uses table the shipped migration creates, on
 * every engine; a migration is an anonymous class, so they cover nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class KeyUsesTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped key uses migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_001300_create_audit_log_key_uses_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_key_uses_under_a_long_table_name_xxxx';

    /** @var string The setting that names the table. */
    private const string SETTING = 'audit-log.privacy.key_uses_table';

    /** @var string A table name the setting may give instead, for the rename test. */
    private const string RENAMED = 'audit_renamed_key_uses';

    /** @var string The id of a key, its number replacing `%012d`. */
    private const string KEY_ID = '01932b4e-9000-7000-8000-%012d';

    /** @var string The id of an entry, its number replacing `%012d`. */
    private const string ENTRY_ID = '01932b4e-a000-7000-8000-%012d';

    /**
     * Run the shipped migration for `TABLE`.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set(self::SETTING, self::TABLE);

        Schema::dropIfExists(self::TABLE);

        $this->loadMigration()->up(); // @phpstan-ignore method.notFound
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
     * The key and entry columns, in order, are together the primary key.
     *
     * @return void
     */
    public function testTheKeyAndEntryArePrimary(): void
    {
        $shape   = TableShape::keyUses();
        $columns = Schema::getColumns(self::TABLE);
        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertSame(['key_id', 'entry_id'], array_column($columns, 'name'));
        self::assertSame(['key_id' => false, 'entry_id' => false], array_column($columns, 'nullable', 'name'));
        self::assertCount(1, $primary);
        self::assertSame(['key_id', 'entry_id'], $primary[0]['columns']);
        self::assertSame([], (new SchemaChecks(app(DatabaseManager::class)))->problems(self::CONNECTION, self::TABLE, $shape));
    }

    /**
     * A key and entry pair is recorded once.
     *
     * @return void
     */
    public function testAPairIsRecordedOnce(): void
    {
        DB::table(self::TABLE)->insert([self::row(1, 1), self::row(1, 2), self::row(2, 1)]);

        self::assertSame(3, DB::table(self::TABLE)->count());

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row(1, 2));
    }

    /**
     * The entry alone has a non-unique index named after the table.
     *
     * @return void
     */
    public function testTheEntryIsIndexed(): void
    {
        $secondary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$index['primary']));

        self::assertCount(1, $secondary);
        self::assertSame(self::TABLE . '_entry_index', $secondary[0]['name']);
        self::assertSame(['entry_id'], $secondary[0]['columns']);
        self::assertFalse($secondary[0]['unique']);
        self::assertLessThanOrEqual(63, strlen(self::TABLE . '_primary'));
    }

    /**
     * The table has no foreign keys.
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
     * An existing table is refused naming the setting, and keeps its rows.
     *
     * @return void
     */
    public function testAnExistingTableIsNeverReplaced(): void
    {
        DB::table(self::TABLE)->insert(self::row(1, 1));

        try {
            $this->loadMigration()->up(); // @phpstan-ignore method.notFound
            self::fail('Expected the migration to stop.');
        } catch (TableAlreadyExistsException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame(
                'Cannot install the laravel-audit-log migration for the \'' . self::TABLE . '\' table: a table with that name already exists on connection \''
                . self::CONNECTION . '\'. Set `privacy.key_uses_table` in config/audit-log.php to a different name and re-run the migration.',
                $exception->getMessage(),
            );
        }

        self::assertTrue(Schema::hasTable(self::TABLE));
        self::assertSame(1, DB::table(self::TABLE)->count());
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
     * A key use of the numbered key and the numbered entry.
     *
     * @param  int  $key
     * @param  int  $entry
     * @return array<string, string>
     */
    private static function row(int $key, int $entry): array
    {
        return ['key_id' => sprintf(self::KEY_ID, $key), 'entry_id' => sprintf(self::ENTRY_ID, $entry)];
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
            self::fail('The key uses migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
