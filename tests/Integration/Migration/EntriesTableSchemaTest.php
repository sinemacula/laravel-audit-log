<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use Tests\Fixtures\Database\EntriesTableShape;
use Tests\TestCase;

/**
 * Integration tests for the shape of the table the shipped entries migration
 * creates, on whichever engine the suite runs against.
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
final class EntriesTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped entries migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000000_create_audit_log_entries_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_entries_for_a_very_long_table_name_xx';

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

        config()->set('audit-log.entries.table', self::TABLE);

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
     * The table holds the 36 columns of the stored envelope; only what a record
     * may lack is nullable, and every column the HMAC needs to name the event,
     * its outcome, its source, its times and its signature is not.
     *
     * @return void
     */
    public function testCreatesEveryColumnWithItsNullability(): void
    {
        $columns = array_column(Schema::getColumns(self::TABLE), 'nullable', 'name');

        ksort($columns);

        self::assertSame([
            'actor_id'          => true,
            'actor_type'        => true,
            'category'          => false,
            'context'           => true,
            'correlation_id'    => true,
            'credential_id'     => true,
            'event'             => false,
            'event_version'     => false,
            'guard'             => true,
            'hmac'              => false,
            'id'                => false,
            'import_batch_id'   => true,
            'integrity_version' => false,
            'ip'                => true,
            'key_id'            => false,
            'occurred_at'       => false,
            'origin'            => true,
            'outcome'           => false,
            'principal_id'      => true,
            'principal_type'    => true,
            'properties'        => true,
            'provenance'        => false,
            'reason'            => true,
            'record_version'    => false,
            'recorded_at'       => false,
            'request_id'        => true,
            'session_id'        => true,
            'source_id'         => false,
            'source_record_id'  => true,
            'source_region'     => true,
            'subject_id'        => true,
            'subject_type'      => true,
            'tenant_id'         => true,
            'tenant_type'       => true,
            'trace_id'          => true,
            'user_agent'        => true,
        ], $columns);
    }

    /**
     * The columns are in the stored envelope's order: the captured record's
     * fields, then the four the finalisation adds.
     *
     * @return void
     */
    public function testKeepsTheColumnsInTheEnvelopesOrder(): void
    {
        self::assertSame([
            'id', 'record_version', 'event', 'event_version', 'category', 'outcome', 'reason',
            'actor_type', 'actor_id', 'subject_type', 'subject_id', 'principal_type', 'principal_id', 'tenant_type', 'tenant_id',
            'credential_id', 'guard', 'session_id', 'request_id', 'trace_id', 'correlation_id',
            'origin', 'provenance', 'source_id', 'source_region', 'source_record_id', 'import_batch_id',
            'ip', 'user_agent', 'context', 'properties', 'occurred_at',
            'recorded_at', 'integrity_version', 'key_id', 'hmac',
        ], array_column(Schema::getColumns(self::TABLE), 'name'));
    }

    /**
     * The id is the primary key, alone.
     *
     * @return void
     */
    public function testTheIdIsThePrimaryKey(): void
    {
        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertCount(1, $primary);
        self::assertSame(['id'], $primary[0]['columns']);
    }

    /**
     * Every string column has the length the record allows it, and the ids
     * drawn as UUIDs are stored as UUIDs.
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

        foreach (EntriesTableShape::STRING_LENGTHS as $column => $length) {
            self::assertStringContainsString('(' . $length . ')', $types[$column], $column);
        }

        foreach (['id', 'import_batch_id'] as $column) {
            self::assertSame($driver === 'pgsql' ? 'uuid' : 'char(36)', $types[$column], $column);
        }
    }

    /**
     * Both times are stored to the microsecond, as the migration declares
     * whatever the builder's default, so a time written with six fractional
     * digits reads back with all six.
     *
     * @return void
     */
    public function testStoresBothTimesToTheMicrosecond(): void
    {
        if (Schema::getConnection()->getDriverName() !== 'sqlite') {
            $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

            self::assertStringContainsString('(6)', $types['occurred_at']);
            self::assertStringContainsString('(6)', $types['recorded_at']);
        }

        DB::table(self::TABLE)->insert(self::row(1, ['occurred_at' => '2026-11-01 12:00:00.123456', 'recorded_at' => '2026-11-01 12:00:00.654321']));

        $row = DB::table(self::TABLE)->first(['occurred_at', 'recorded_at']);

        self::assertNotNull($row);
        self::assertSame('2026-11-01 12:00:00.123456', $row->occurred_at);
        self::assertSame('2026-11-01 12:00:00.654321', $row->recorded_at);
    }

    /**
     * The context and the properties are `json`, never `jsonb`, so nothing the
     * engine does to the text matters to integrity; SQLite stores them as text.
     *
     * @return void
     */
    public function testThePayloadColumnsAreJsonNeverJsonb(): void
    {
        $expected = Schema::getConnection()->getDriverName() === 'sqlite' ? 'text' : 'json';
        $types    = array_column(Schema::getColumns(self::TABLE), 'type_name', 'name');

        self::assertSame($expected, $types['context']);
        self::assertSame($expected, $types['properties']);
    }

    /**
     * The record, event and integrity versions are small integers.
     *
     * @return void
     */
    public function testTheVersionColumnsAreSmallIntegers(): void
    {
        $expected = match (Schema::getConnection()->getDriverName()) {
            'mysql' => 'smallint',
            'pgsql' => 'int2',
            default => 'integer',
        };

        $types = array_column(Schema::getColumns(self::TABLE), 'type_name', 'name');

        foreach (['record_version', 'event_version', 'integrity_version'] as $column) {
            self::assertSame($expected, $types[$column], $column);
        }
    }

    /**
     * Each lookup has its own index, its columns in the order the lookup uses
     * them and named after the table with a short suffix, and a source's own
     * record id is unique within the source.
     *
     * @return void
     */
    public function testIndexesEveryLookupUnderItsOwnShortName(): void
    {
        $secondary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$index['primary']));

        $indexes = array_map(static fn (array $index): array => [$index['name'], $index['columns'], $index['unique']], $secondary);

        sort($indexes);

        self::assertSame([
            [self::TABLE . '_actor_index', ['actor_type', 'actor_id', 'occurred_at'], false],
            [self::TABLE . '_category_index', ['category', 'occurred_at'], false],
            [self::TABLE . '_correlate_index', ['correlation_id'], false],
            [self::TABLE . '_event_index', ['event', 'occurred_at'], false],
            [self::TABLE . '_occurred_index', ['occurred_at'], false],
            [self::TABLE . '_principal_index', ['principal_type', 'principal_id', 'occurred_at'], false],
            [self::TABLE . '_source_unique', ['source_id', 'source_record_id'], true],
            [self::TABLE . '_subject_index', ['subject_type', 'subject_id', 'occurred_at'], false],
            [self::TABLE . '_tenant_index', ['tenant_type', 'tenant_id', 'occurred_at'], false],
        ], $indexes);
    }

    /**
     * At the longest table name the setting accepts, every index name, the
     * primary key's included, fits PostgreSQL's 63 characters, and the longest
     * reaches it exactly. SQLite names its primary key index itself and limits
     * no name, so there the primary key is left out.
     *
     * @return void
     */
    public function testEveryIndexNameFitsAtTheLongestTableName(): void
    {
        self::assertSame(47, strlen(self::TABLE));

        $sqlite  = Schema::getConnection()->getDriverName() === 'sqlite';
        $indexes = array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$sqlite || !$index['primary']);
        $lengths = array_map(strlen(...), array_column($indexes, 'name'));

        self::assertCount($sqlite ? 9 : 10, $lengths);
        self::assertSame(63, max($lengths));
    }

    /**
     * The table has no timestamps, since a row is never updated, and no foreign
     * keys, so each table the package keeps is pruned on its own.
     *
     * @return void
     */
    public function testHasNoTimestampsAndNoForeignKeys(): void
    {
        self::assertFalse(Schema::hasColumn(self::TABLE, 'created_at'));
        self::assertFalse(Schema::hasColumn(self::TABLE, 'updated_at'));
        self::assertSame([], Schema::getForeignKeys(self::TABLE));
    }

    /**
     * On MySQL every character column takes the table's binary collation
     * without padding, whatever the connection's collation is.
     *
     * @return void
     */
    public function testOnMySqlEveryCharacterColumnIsBinaryWithoutPadding(): void
    {
        if (Schema::getConnection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL compares by a collation the migration sets.');
        }

        $collations = array_filter(array_column(Schema::getColumns(self::TABLE), 'collation', 'name'), static fn (?string $collation): bool => $collation !== null);

        self::assertEqualsCanonicalizing([...array_keys(EntriesTableShape::STRING_LENGTHS), 'id', 'import_batch_id'], array_keys($collations));

        foreach ($collations as $column => $collation) {
            self::assertSame('utf8mb4_0900_bin', $collation, $column);
        }

        $tables = array_column(Schema::getTables(), 'collation', 'name');

        self::assertSame('utf8mb4_0900_bin', $tables[self::TABLE]);
    }

    /**
     * On MySQL the table is on InnoDB, so its writes are transactional.
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
     * Ids that differ only in case are distinct, on every engine.
     *
     * @return void
     */
    public function testIdsDifferingOnlyInCaseAreDistinct(): void
    {
        DB::table(self::TABLE)->insert([self::row(1, ['actor_id' => 'ABC']), self::row(2, ['actor_id' => 'abc'])]);

        self::assertSame(1, DB::table(self::TABLE)->where('actor_id', 'abc')->count());
        self::assertSame(1, DB::table(self::TABLE)->where('actor_id', 'ABC')->count());
    }

    /**
     * Ids that differ only by a trailing space are distinct, on every engine:
     * the unique index keeps both and a lookup finds one, which a padding
     * collation such as MySQL's `utf8mb4_bin` would not.
     *
     * @return void
     */
    public function testIdsDifferingOnlyByATrailingSpaceAreDistinct(): void
    {
        DB::table(self::TABLE)->insert(self::row(1, ['source_id' => 'app', 'source_record_id' => 'r1']));
        DB::table(self::TABLE)->insert(self::row(2, ['source_id' => 'app', 'source_record_id' => 'r1 ']));

        self::assertSame(2, DB::table(self::TABLE)->where('source_id', 'app')->count());
        self::assertSame(1, DB::table(self::TABLE)->where('source_record_id', 'r1')->count());
        self::assertSame(1, DB::table(self::TABLE)->where('source_record_id', 'r1 ')->count());
    }

    /**
     * The source identity is unique: a source's record id stored twice is
     * refused.
     *
     * @return void
     */
    public function testASourcesRecordIdIsStoredOnce(): void
    {
        DB::table(self::TABLE)->insert(self::row(1, ['source_id' => 'app', 'source_record_id' => 'r1']));

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row(2, ['source_id' => 'app', 'source_record_id' => 'r1']));
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
     * A row with every column a row must have, numbered so each row's id is its
     * own, with the given columns replaced.
     *
     * @param  int  $number
     * @param  array<string, string>  $columns
     * @return array<string, int|string>
     */
    private static function row(int $number, array $columns = []): array
    {
        return [
            'id'                => sprintf('0195f4a2-7b1c-7000-8000-%012d', $number),
            'record_version'    => 1,
            'event'             => 'invoice.approved',
            'event_version'     => 1,
            'category'          => 'billing',
            'outcome'           => 'success',
            'provenance'        => 'captured',
            'source_id'         => 'app',
            'occurred_at'       => '2026-11-01 12:00:00.000000',
            'recorded_at'       => '2026-11-01 12:00:00.000000',
            'integrity_version' => 1,
            'key_id'            => 'test-key',
            'hmac'              => str_repeat('a', 64),
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
            self::fail('Entries migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
