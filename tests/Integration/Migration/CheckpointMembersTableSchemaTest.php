<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the checkpoint members migration's table on every
 * engine; a migration is an anonymous class, so they cover nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class CheckpointMembersTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped checkpoint members migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000400_create_audit_log_checkpoint_members_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_checkpoint_members_for_a_long_table_x';

    /**
     * Run the shipped migration for `TABLE`.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('audit-log.integrity.members_table', self::TABLE);

        Schema::dropIfExists(self::TABLE);

        $this->loadMigration()->up(); // @phpstan-ignore method.notFound
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
     * The seal, entry and HMAC columns, in order, none nullable.
     *
     * @return void
     */
    public function testCreatesEveryColumnWithItsNullability(): void
    {
        self::assertSame([
            'checkpoint_id' => false,
            'entry_id'      => false,
            'hmac'          => false,
        ], array_column(Schema::getColumns(self::TABLE), 'nullable', 'name'));
    }

    /**
     * Both ids are UUIDs and the HMAC is the length of SHA-256 in hex.
     *
     * @return void
     */
    public function testSizesEveryStringColumn(): void
    {
        $driver = Schema::getConnection()->getDriverName();

        if ($driver === 'sqlite') {
            self::markTestSkipped('SQLite does not record a length for string columns.');
        }

        $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

        self::assertSame($driver === 'pgsql' ? 'uuid' : 'char(36)', $types['checkpoint_id']);
        self::assertSame($driver === 'pgsql' ? 'uuid' : 'char(36)', $types['entry_id']);
        self::assertStringContainsString('(64)', $types['hmac']);
    }

    /**
     * The primary key is the seal, then the entry.
     *
     * @return void
     */
    public function testTheKeyIsTheCheckpointAndTheEntry(): void
    {
        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertCount(1, $primary);
        self::assertSame(['checkpoint_id', 'entry_id'], $primary[0]['columns']);
    }

    /**
     * Beside the primary key, the only index is the entry's unique one.
     *
     * @return void
     */
    public function testIndexesTheEntryAlone(): void
    {
        $secondary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$index['primary']));

        self::assertSame(
            [[self::TABLE . '_entry_unique', ['entry_id'], true]],
            array_map(static fn (array $index): array => [$index['name'], $index['columns'], $index['unique']], $secondary),
        );
    }

    /**
     * A seal holds many entries, read by its id.
     *
     * @return void
     */
    public function testASealHoldsManyEntries(): void
    {
        DB::table(self::TABLE)->insert([self::row(1, 1), self::row(1, 2), self::row(2, 3)]);

        self::assertSame(2, DB::table(self::TABLE)->where('checkpoint_id', self::id(1))->count());
        self::assertSame(1, DB::table(self::TABLE)->where('checkpoint_id', self::id(2))->count());
    }

    /**
     * An entry belongs to at most one seal.
     *
     * @return void
     */
    public function testAnEntryBelongsToAtMostOneSeal(): void
    {
        DB::table(self::TABLE)->insert(self::row(1, 1));

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row(2, 1));
    }

    /**
     * A seal names an entry once: the same member row twice is refused.
     *
     * @return void
     */
    public function testASealNamesAnEntryOnce(): void
    {
        DB::table(self::TABLE)->insert(self::row(1, 1));

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row(1, 1));
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
        $lengths = array_map(strlen(...), array_column($indexes, 'name'));

        self::assertCount($sqlite ? 1 : 2, $lengths);
        self::assertLessThanOrEqual(63, max($lengths));
        self::assertContains(strlen(self::TABLE . '_entry_unique'), $lengths);
    }

    /**
     * The table has no foreign keys and no timestamps.
     *
     * @return void
     */
    public function testHasNoForeignKeys(): void
    {
        self::assertSame([], Schema::getForeignKeys(self::TABLE));
        self::assertFalse(Schema::hasColumn(self::TABLE, 'created_at'));
        self::assertFalse(Schema::hasColumn(self::TABLE, 'updated_at'));
    }

    /**
     * On MySQL every character column is binary without padding.
     *
     * @return void
     */
    public function testOnMySqlEveryCharacterColumnIsBinaryWithoutPadding(): void
    {
        if (Schema::getConnection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL compares by a collation the migration sets.');
        }

        $collations = array_filter(array_column(Schema::getColumns(self::TABLE), 'collation', 'name'), static fn (?string $collation): bool => $collation !== null);

        self::assertEqualsCanonicalizing(['checkpoint_id', 'entry_id', 'hmac'], array_keys($collations));

        foreach ($collations as $column => $collation) {
            self::assertSame('utf8mb4_0900_bin', $collation, $column);
        }

        $tables = array_column(Schema::getTables(), 'collation', 'name');

        self::assertSame('utf8mb4_0900_bin', $tables[self::TABLE]);
    }

    /**
     * On MySQL the table is on InnoDB.
     *
     * @return void
     */
    public function testOnMySqlTheTableIsInnoDb(): void
    {
        if (Schema::getConnection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL has a storage engine per table.');
        }

        $tables = array_column(Schema::getTables(), 'engine', 'name');

        self::assertSame('InnoDB', $tables[self::TABLE]);
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
     * An existing table is refused with an exception naming the setting.
     *
     * @return void
     */
    public function testAnExistingTableStopsTheMigrationNamingTheSetting(): void
    {
        DB::table(self::TABLE)->insert(self::row(1, 1));

        try {
            $this->loadMigration()->up(); // @phpstan-ignore method.notFound
            self::fail('Expected the migration to stop.');
        } catch (TableAlreadyExistsException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame(
                'Cannot install the laravel-audit-log migration for the \'' . self::TABLE . '\' table: a table with that name already exists on connection \''
                . self::CONNECTION . '\'. Set `integrity.members_table` in config/audit-log.php to a different name and re-run the migration.',
                $exception->getMessage(),
            );
        }

        self::assertSame(1, DB::table(self::TABLE)->count());
    }

    /**
     * The id of the numbered seal.
     *
     * @param  int  $number
     * @return string
     */
    private static function id(int $number): string
    {
        return sprintf('01932b4e-9000-7000-8000-%012d', $number);
    }

    /**
     * A member row naming the numbered entry under the numbered seal.
     *
     * @param  int  $seal
     * @param  int  $entry
     * @return array<string, string>
     */
    private static function row(int $seal, int $entry): array
    {
        return [
            'checkpoint_id' => self::id($seal),
            'entry_id'      => sprintf('01932b4e-8a40-7000-8000-%012d', $entry),
            'hmac'          => str_repeat('a', 64),
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
            self::fail('Checkpoint members migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
