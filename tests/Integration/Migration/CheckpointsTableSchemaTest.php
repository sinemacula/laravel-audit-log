<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Schema\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Database\TableAlreadyExistsException;
use Tests\Concerns\LoadsShippedMigrations;
use Tests\TestCase;

/**
 * Integration tests for the table the shipped checkpoints migration creates, on
 * every engine; a migration is an anonymous class, so they cover nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class CheckpointsTableSchemaTest extends TestCase
{
    use LoadsShippedMigrations;

    /** @var string Absolute path to the shipped checkpoints migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000300_create_audit_log_checkpoints_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_checkpoints_for_a_very_long_table_xxx';

    /** @var list<string> The columns that hold a time. */
    private const array TIMES = ['first_recorded_at', 'last_recorded_at', 'sealed_at', 'anchored_at'];

    /** @var array<string, int> The length of every string column. */
    private const array STRING_LENGTHS = [
        'log_id'             => 64,
        'previous_digest'    => 64,
        'members_digest'     => 64,
        'seal_digest'        => 64,
        'signer'             => 16,
        'key_id'             => 32,
        'journal_head'       => 64,
        'signature'          => 64,
        'anchor'             => 64,
        'anchor_error_class' => 191,
    ];

    /**
     * Migrate `TABLE` with the builder's default precision at whole seconds.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('audit-log.integrity.checkpoints_table', self::TABLE);

        Schema::dropIfExists(self::TABLE);

        $precision = Builder::$defaultTimePrecision;

        Builder::defaultTimePrecision(0);

        try {
            $this->loadMigration(self::MIGRATION_PATH)->up(); // @phpstan-ignore method.notFound
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
     * Twenty-one columns; only the link, journal head and anchor are nullable.
     *
     * @return void
     */
    public function testCreatesEveryColumnWithItsNullability(): void
    {
        $columns = array_column(Schema::getColumns(self::TABLE), 'nullable', 'name');

        ksort($columns);

        self::assertSame([
            'algorithm_version'  => false,
            'anchor'             => true,
            'anchor_error_class' => true,
            'anchor_receipt'     => true,
            'anchored_at'        => true,
            'first_recorded_at'  => false,
            'id'                 => false,
            'journal_head'       => true,
            'journal_sequence'   => true,
            'key_id'             => false,
            'last_recorded_at'   => false,
            'log_id'             => false,
            'member_count'       => false,
            'members_digest'     => false,
            'previous_digest'    => true,
            'previous_id'        => true,
            'seal_digest'        => false,
            'sealed_at'          => false,
            'sequence'           => false,
            'signature'          => false,
            'signer'             => false,
        ], $columns);
    }

    /**
     * The columns are in seal order, the anchor columns last.
     *
     * @return void
     */
    public function testKeepsTheColumnsInOrder(): void
    {
        self::assertSame([
            'id', 'sequence', 'log_id', 'previous_id', 'previous_digest',
            'member_count', 'members_digest', 'seal_digest',
            'first_recorded_at', 'last_recorded_at', 'sealed_at',
            'signer', 'key_id', 'algorithm_version', 'journal_sequence', 'journal_head', 'signature',
            'anchor', 'anchor_receipt', 'anchored_at', 'anchor_error_class',
        ], array_column(Schema::getColumns(self::TABLE), 'name'));
    }

    /**
     * The id is the primary key, alone, so a seal is kept once.
     *
     * @return void
     */
    public function testTheIdIsThePrimaryKey(): void
    {
        $primary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['primary']));

        self::assertCount(1, $primary);
        self::assertSame(['id'], $primary[0]['columns']);

        DB::table(self::TABLE)->insert(self::row(1));

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row(1, ['sequence' => 2]));
    }

    /**
     * A sequence is held by one seal only.
     *
     * @return void
     */
    public function testTheSequenceIsUnique(): void
    {
        $unique = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => $index['name'] === self::TABLE . '_sequence_unique'));

        self::assertCount(1, $unique);
        self::assertSame(['sequence'], $unique[0]['columns']);
        self::assertTrue($unique[0]['unique']);

        DB::table(self::TABLE)->insert(self::row(1));

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row(2, ['sequence' => 1]));
    }

    /**
     * The only other indexes are the anchorer's and the journal commitment's.
     *
     * @return void
     */
    public function testIndexesWhatTheAnchorerAndTheJournalCheckRead(): void
    {
        $secondary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$index['primary']));

        $indexes = array_map(static fn (array $index): array => [$index['name'], $index['columns'], $index['unique']], $secondary);

        sort($indexes);

        self::assertSame([
            [self::TABLE . '_anchored_index', ['anchored_at', 'sequence'], false],
            [self::TABLE . '_journal_index', ['journal_sequence'], false],
            [self::TABLE . '_sequence_unique', ['sequence'], true],
        ], $indexes);
    }

    /**
     * Every index name fits PostgreSQL's 63 characters, the longest exactly;
     * SQLite names its own primary key, so it is left out.
     *
     * @return void
     */
    public function testEveryIndexNameFitsAtTheLongestTableName(): void
    {
        self::assertSame(47, strlen(self::TABLE));

        $sqlite  = Schema::getConnection()->getDriverName() === 'sqlite';
        $indexes = array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$sqlite || !$index['primary']);
        $lengths = array_map(strlen(...), array_column($indexes, 'name'));

        self::assertCount($sqlite ? 3 : 4, $lengths);
        self::assertSame(63, max($lengths));
    }

    /**
     * Every string column has the length its value takes; ids are UUIDs.
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

        foreach (self::STRING_LENGTHS as $column => $length) {
            self::assertStringContainsString('(' . $length . ')', $types[$column], $column);
        }

        foreach (['id', 'previous_id'] as $column) {
            self::assertSame($driver === 'pgsql' ? 'uuid' : 'char(36)', $types[$column], $column);
        }
    }

    /**
     * The sequences are big integers and the algorithm version a small one.
     *
     * @return void
     */
    public function testTheSequenceIsABigInteger(): void
    {
        $driver = Schema::getConnection()->getDriverName();
        $types  = array_column(Schema::getColumns(self::TABLE), 'type_name', 'name');

        self::assertSame(match ($driver) {
            'mysql' => 'bigint',
            'pgsql' => 'int8',
            default => 'integer',
        }, $types['sequence']);

        self::assertSame(match ($driver) {
            'mysql' => 'smallint',
            'pgsql' => 'int2',
            default => 'integer',
        }, $types['algorithm_version']);

        self::assertSame($types['sequence'], $types['journal_sequence']);

        DB::table(self::TABLE)->insert(self::row(1, ['sequence' => 2 ** 40, 'journal_sequence' => 2 ** 41]));

        self::assertSame(2 ** 40, DB::table(self::TABLE)->value('sequence'));
        self::assertSame(2 ** 41, DB::table(self::TABLE)->value('journal_sequence'));
    }

    /**
     * Every time is stored to the microsecond, whatever the builder's default.
     *
     * @return void
     */
    public function testStoresEveryTimeToTheMicrosecond(): void
    {
        if (Schema::getConnection()->getDriverName() !== 'sqlite') {
            $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

            foreach (self::TIMES as $column) {
                self::assertStringContainsString('(6)', $types[$column], $column);
            }
        }

        $times = [
            'first_recorded_at' => '2026-10-31 23:34:56.890123',
            'last_recorded_at'  => '2026-10-31 23:35:00.000001',
            'sealed_at'         => '2026-10-31 23:40:00.123456',
            'anchored_at'       => '2026-10-31 23:40:01.654321',
        ];

        DB::table(self::TABLE)->insert(self::row(1, $times));

        $row = (array) DB::table(self::TABLE)->first(self::TIMES);

        self::assertSame($times, $row);
    }

    /**
     * The receipt is `json`, never `jsonb`, so the anchor's text is kept.
     *
     * @return void
     */
    public function testTheReceiptIsJsonNeverJsonb(): void
    {
        $expected = Schema::getConnection()->getDriverName() === 'sqlite' ? 'text' : 'json';
        $types    = array_column(Schema::getColumns(self::TABLE), 'type_name', 'name');

        self::assertSame($expected, $types['anchor_receipt']);
    }

    /**
     * The anchor columns are written after the seal, the rest left as inserted.
     *
     * @return void
     */
    public function testTheAnchorColumnsAreWrittenAfterTheSeal(): void
    {
        DB::table(self::TABLE)->insert(self::row(1));

        DB::table(self::TABLE)->where('id', self::id(1))->update([
            'anchor'         => 'disk:0123456789abcdef',
            'anchor_receipt' => '{"path":"audit-log-anchors/app/1.json","sha256":"' . str_repeat('a', 64) . '"}',
            'anchored_at'    => '2026-10-31 23:41:00.000000',
        ]);

        $row = DB::table(self::TABLE)->first(['previous_id', 'previous_digest', 'anchor', 'anchor_receipt', 'anchor_error_class']);

        self::assertNotNull($row);
        self::assertNull($row->previous_id);
        self::assertNull($row->previous_digest);
        self::assertSame('disk:0123456789abcdef', $row->anchor);
        self::assertSame(['path' => 'audit-log-anchors/app/1.json', 'sha256' => str_repeat('a', 64)], json_decode((string) $row->anchor_receipt, true));
        self::assertNull($row->anchor_error_class);
    }

    /**
     * The journal head is null for an empty journal, else kept as written.
     *
     * @return void
     */
    public function testTheJournalHeadIsNullForAnEmptyJournalAndKeptOtherwise(): void
    {
        DB::table(self::TABLE)->insert(self::row(1));
        DB::table(self::TABLE)->insert(self::row(2, ['journal_sequence' => 7, 'journal_head' => str_repeat('f', 64)]));

        $rows = DB::table(self::TABLE)->orderBy('sequence')->get(['journal_sequence', 'journal_head'])->all();

        self::assertNull($rows[0]->journal_sequence);
        self::assertNull($rows[0]->journal_head);
        self::assertSame(7, $rows[1]->journal_sequence);
        self::assertSame(str_repeat('f', 64), $rows[1]->journal_head);
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

        self::assertEqualsCanonicalizing(['id', 'previous_id', ...array_keys(self::STRING_LENGTHS)], array_keys($collations));

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
        $this->loadMigration(self::MIGRATION_PATH)->down(); // @phpstan-ignore method.notFound

        self::assertFalse(Schema::hasTable(self::TABLE));
    }

    /**
     * An existing table is refused with an exception naming the setting.
     *
     * @return void
     */
    public function testAnExistingTableStopsTheMigrationNamingTheSetting(): void
    {
        DB::table(self::TABLE)->insert(self::row(1));

        try {
            $this->loadMigration(self::MIGRATION_PATH)->up(); // @phpstan-ignore method.notFound
            self::fail('Expected the migration to stop.');
        } catch (TableAlreadyExistsException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame(
                'Cannot install the laravel-audit-log migration for the \'' . self::TABLE . '\' table: a table with that name already exists on connection \''
                . self::CONNECTION . '\'. Set `integrity.checkpoints_table` in config/audit-log.php to a different name and re-run the migration.',
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
     * A genesis seal, numbered so its id and sequence are its own.
     *
     * @param  int  $number
     * @param  array<string, int|string>  $columns
     * @return array<string, int|string>
     */
    private static function row(int $number, array $columns = []): array
    {
        return [
            'id'                => self::id($number),
            'sequence'          => $number,
            'log_id'            => 'app-eu-1',
            'member_count'      => 2,
            'members_digest'    => str_repeat('a', 64),
            'seal_digest'       => str_repeat('b', 64),
            'first_recorded_at' => '2026-10-31 23:34:56.000000',
            'last_recorded_at'  => '2026-10-31 23:35:00.000000',
            'sealed_at'         => '2026-10-31 23:40:00.000000',
            'signer'            => 'hmac',
            'key_id'            => 'k2026',
            'algorithm_version' => 1,
            'signature'         => str_repeat('c', 64),
            ...$columns,
        ];
    }
}
