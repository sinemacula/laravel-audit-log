<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the shape of the table the shipped artifacts migration
 * creates, on whichever engine the suite runs against: its columns and their
 * types, its key, one artifact for each entry, its binary collation and engine
 * on MySQL, the storage connection it is created on, the setting a collision
 * names, and its rollback.
 *
 * The migration runs for the longest table name the setting accepts and with
 * the schema builder's default time precision lowered to whole seconds, so the
 * index name and the microsecond precision are what the migration itself
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
final class ArtifactsTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped artifacts migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000600_create_audit_log_artifacts_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_artifacts_for_the_longest_table_name_';

    /** @var string A connection of its own the storage connection setting may name. */
    private const string STORAGE = 'audit_store';

    /** @var array<string, array<string, array{0: string, 1: ?string}>> The type name and, where the engine records it, the full type of each column, in order, on each engine. */
    private const array TYPES = [
        'sqlite' => [
            'id'           => ['varchar', null],
            'entry_id'     => ['varchar', null],
            'kind'         => ['varchar', null],
            'member_count' => ['integer', null],
            'digest'       => ['varchar', null],
            'members'      => ['text', null],
            'created_at'   => ['datetime', null],
        ],
        'mysql' => [
            'id'           => ['char', 'char(36)'],
            'entry_id'     => ['char', 'char(36)'],
            'kind'         => ['varchar', 'varchar(16)'],
            'member_count' => ['int', 'int unsigned'],
            'digest'       => ['varchar', 'varchar(64)'],
            'members'      => ['longtext', 'longtext'],
            'created_at'   => ['datetime', 'datetime(6)'],
        ],
        'pgsql' => [
            'id'           => ['uuid', 'uuid'],
            'entry_id'     => ['uuid', 'uuid'],
            'kind'         => ['varchar', 'character varying(16)'],
            'member_count' => ['int4', 'integer'],
            'digest'       => ['varchar', 'character varying(64)'],
            'members'      => ['text', 'text'],
            'created_at'   => ['timestamp', 'timestamp(6) without time zone'],
        ],
    ];

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

        config()->set('audit-log.entries.artifacts_table', self::TABLE);

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
     * Drop the table the test migrated, on the test's connection and on the
     * storage connection of its own a test may configure.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::connection(self::CONNECTION)->dropIfExists(self::TABLE);

        if (app(ConfigRepository::class)->has('database.connections.' . self::STORAGE)) {
            Schema::connection(self::STORAGE)->dropIfExists(self::TABLE);
            DB::purge(self::STORAGE);
        }

        parent::tearDown();
    }

    /**
     * The table holds the artifact's id, its entry, its kind, its count, its
     * digest, its encrypted members and its time, in that order, each of its
     * type and none of them nullable: the ids are UUIDs, the digest the length
     * of SHA-256 in hex, the members long text, the count unsigned on MySQL,
     * and the time to the microsecond.
     *
     * @return void
     */
    public function testTheColumnsHaveTheirTypes(): void
    {
        $driver  = Schema::getConnection()->getDriverName();
        $columns = Schema::getColumns(self::TABLE);
        $types   = self::TYPES[$driver];

        self::assertSame(array_keys($types), array_column($columns, 'name'));
        self::assertSame(array_fill_keys(array_keys($types), false), array_column($columns, 'nullable', 'name'));
        self::assertSame(array_column($types, 0), array_column($columns, 'type_name'));

        if ($driver === 'sqlite') {
            return;
        }

        self::assertSame(array_column($types, 1), array_column($columns, 'type'));
    }

    /**
     * The id is the primary key, over it alone, so a second artifact under the
     * same id is refused.
     *
     * @return void
     */
    public function testTheIdIsThePrimaryKey(): void
    {
        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertCount(1, $primary);
        self::assertSame(['id'], $primary[0]['columns']);

        DB::table(self::TABLE)->insert(self::row(1, 1));

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row(1, 2));
    }

    /**
     * Beside the primary key, the only index is the entry's own, unique, so an
     * entry has at most one artifact: a second artifact for the entry, under
     * another id, is refused.
     *
     * @return void
     */
    public function testAnEntryHasOneArtifact(): void
    {
        $secondary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$index['primary']));

        self::assertSame(
            [[self::TABLE . '_entry_unique', ['entry_id'], true]],
            array_map(static fn (array $index): array => [$index['name'], $index['columns'], $index['unique']], $secondary),
        );

        DB::table(self::TABLE)->insert(self::row(1, 1));

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row(2, 1));
    }

    /**
     * Artifacts of different entries are each kept.
     *
     * @return void
     */
    public function testEachEntryMayHaveItsOwnArtifact(): void
    {
        DB::table(self::TABLE)->insert([self::row(1, 1), self::row(2, 2)]);

        self::assertSame(2, DB::table(self::TABLE)->count());
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
        $lengths = array_map(strlen(...), array_column($indexes, 'name'));

        self::assertCount($sqlite ? 1 : 2, $lengths);
        self::assertLessThanOrEqual(63, max($lengths));
        self::assertContains(strlen(self::TABLE . '_entry_unique'), $lengths);
    }

    /**
     * The members hold far more than the 64 KiB a plain text column does, and
     * read back byte for byte.
     *
     * @return void
     */
    public function testTheMembersHoldMoreThanAPlainTextColumn(): void
    {
        $members = str_repeat('eyJpdiI6IjAxMjM0NTY3ODkiLCJ2YWx1ZSI6ImFiY2RlZiJ9', 4096);

        DB::table(self::TABLE)->insert([...self::row(1, 1), 'members' => $members]);

        self::assertGreaterThan(65535, strlen($members));
        self::assertSame($members, DB::table(self::TABLE)->value('members'));
    }

    /**
     * The time is stored to the microsecond, as the migration declares whatever
     * the builder's default, so a time written with six fractional digits reads
     * back with all six.
     *
     * @return void
     */
    public function testStoresTheTimeToTheMicrosecond(): void
    {
        DB::table(self::TABLE)->insert([...self::row(1, 1), 'created_at' => '2026-11-01 12:00:00.123456']);

        self::assertSame('2026-11-01 12:00:00.123456', DB::table(self::TABLE)->value('created_at'));
    }

    /**
     * The table has no foreign keys and no `updated_at`, so pruning an entry
     * never cascades and an artifact is never stamped as changed.
     *
     * @return void
     */
    public function testHasNoForeignKeysAndNoUpdateTime(): void
    {
        self::assertSame([], Schema::getForeignKeys(self::TABLE));
        self::assertFalse(Schema::hasColumn(self::TABLE, 'updated_at'));
    }

    /**
     * On MySQL every character column takes the table's binary collation
     * without padding, whatever the connection's collation is, and the table is
     * on InnoDB, so an artifact commits with its entry or not at all.
     *
     * @return void
     */
    public function testOnMySqlTheTableIsBinaryAndInnoDb(): void
    {
        if (Schema::getConnection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL has a collation the migration sets and a storage engine per table.');
        }

        $collations = array_filter(array_column(Schema::getColumns(self::TABLE), 'collation', 'name'), static fn (?string $collation): bool => $collation !== null);

        self::assertEqualsCanonicalizing(['id', 'entry_id', 'kind', 'digest', 'members'], array_keys($collations));

        foreach ($collations as $column => $collation) {
            self::assertSame('utf8mb4_0900_bin', $collation, $column);
        }

        $tables = array_column(Schema::getTables(), null, 'name');

        self::assertSame('utf8mb4_0900_bin', $tables[self::TABLE]['collation']);
        self::assertSame('InnoDB', $tables[self::TABLE]['engine']);
    }

    /**
     * The migration runs on the storage connection: once the setting names a
     * connection of its own, the table is created there and not on the default
     * connection.
     *
     * @return void
     */
    public function testTheTableIsOnTheStorageConnection(): void
    {
        $this->loadMigration()->down(); // @phpstan-ignore method.notFound

        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::STORAGE, [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'store_']);
        $config->set('audit-log.storage.connection', self::STORAGE);

        $migration = $this->loadMigration();

        $migration->up(); // @phpstan-ignore method.notFound

        self::assertSame(self::STORAGE, $migration->getConnection());
        self::assertTrue(Schema::connection(self::STORAGE)->hasTable(self::TABLE));
        self::assertFalse(Schema::connection(self::CONNECTION)->hasTable(self::TABLE));
    }

    /**
     * Running the migration when the configured table already exists throws a
     * `TableAlreadyExistsException` naming the table, the connection and the
     * `entries.artifacts_table` setting that renames it, and leaves the table
     * as it was.
     *
     * @return void
     */
    public function testAnExistingTableIsRefusedNamingTheSetting(): void
    {
        DB::table(self::TABLE)->insert(self::row(1, 1));

        try {
            $this->loadMigration()->up(); // @phpstan-ignore method.notFound
            self::fail('Expected the migration to stop.');
        } catch (TableAlreadyExistsException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame(
                'Cannot install the laravel-audit-log migration for the \'' . self::TABLE . '\' table: a table with that name already exists on connection \''
                . self::CONNECTION . '\'. Set `entries.artifacts_table` in config/audit-log.php to a different name and re-run the migration.',
                $exception->getMessage(),
            );
        }

        self::assertSame(1, DB::table(self::TABLE)->count());
    }

    /**
     * Rolling the migration back drops the configured table, and leaves the
     * entries table beside it.
     *
     * @return void
     */
    public function testARollbackDropsIt(): void
    {
        $this->loadMigration()->down(); // @phpstan-ignore method.notFound

        self::assertFalse(Schema::hasTable(self::TABLE));
        self::assertTrue(Schema::hasTable('audit_log_entries'));
    }

    /**
     * An artifact row, its id and its entry's numbered.
     *
     * @param  int  $artifact
     * @param  int  $entry
     * @return array<string, int|string>
     */
    private static function row(int $artifact, int $entry): array
    {
        return [
            'id'           => sprintf('01932b4e-9000-7000-8000-%012d', $artifact),
            'entry_id'     => sprintf('01932b4e-8a40-7000-8000-%012d', $entry),
            'kind'         => 'bulk',
            'member_count' => 3,
            'digest'       => str_repeat('a', 64),
            'members'      => 'eyJpdiI6IjAxMjM0NTY3ODkifQ==',
            'created_at'   => '2026-11-01 12:00:00.000000',
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
            self::fail('Artifacts migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
