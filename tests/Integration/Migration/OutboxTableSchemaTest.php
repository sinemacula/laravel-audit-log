<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the table the shipped outbox migration creates, on
 * every engine; a migration is an anonymous class, so they cover nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class OutboxTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped outbox migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000100_create_audit_log_outbox_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_outbox_for_a_very_long_table_name_xxx';

    /** @var list<string> The columns that hold a time. */
    private const array TIMES = ['available_at', 'claimed_until', 'failed_at', 'created_at'];

    /**
     * Migrate `TABLE` with the builder's default precision at whole seconds.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('audit-log.delivery.outbox.table', self::TABLE);

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
     * Nine columns in order; only the claim and the failure are nullable.
     *
     * @return void
     */
    public function testCreatesEveryColumnWithItsNullability(): void
    {
        $columns = Schema::getColumns(self::TABLE);

        self::assertSame([
            'id'               => false,
            'payload'          => false,
            'attempts'         => false,
            'available_at'     => false,
            'claimed_until'    => true,
            'claimed_by'       => true,
            'failed_at'        => true,
            'last_error_class' => true,
            'created_at'       => false,
        ], array_column($columns, 'nullable', 'name'));
    }

    /**
     * A new row has had no attempts until a drain claims it.
     *
     * @return void
     */
    public function testAttemptsStartAtZero(): void
    {
        DB::table(self::TABLE)->insert(self::row(1));

        self::assertSame(1, DB::table(self::TABLE)->where('attempts', 0)->count());
    }

    /**
     * The id is the primary key, alone, so a record is in the outbox once.
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

        DB::table(self::TABLE)->insert(self::row(1));
    }

    /**
     * The id is a UUID, and the short strings have the lengths they are cut to.
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

        self::assertSame($driver === 'pgsql' ? 'uuid' : 'char(36)', $types['id']);
        self::assertStringContainsString('(64)', $types['claimed_by']);
        self::assertStringContainsString('(191)', $types['last_error_class']);
    }

    /**
     * The payload is long text, so the largest encrypted envelope fits.
     *
     * @return void
     */
    public function testThePayloadIsLongText(): void
    {
        $expected = Schema::getConnection()->getDriverName() === 'mysql' ? 'longtext' : 'text';
        $types    = array_column(Schema::getColumns(self::TABLE), 'type_name', 'name');

        self::assertSame($expected, $types['payload']);
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
            'available_at'  => '2026-11-01 12:00:00.123456',
            'claimed_until' => '2026-11-01 12:05:00.234567',
            'failed_at'     => '2026-11-01 12:10:00.345678',
            'created_at'    => '2026-11-01 11:59:59.456789',
        ];

        DB::table(self::TABLE)->insert(self::row(1, $times));

        $row = (array) DB::table(self::TABLE)->first(self::TIMES);

        self::assertSame($times, $row);
    }

    /**
     * The only other indexes are the drain's and the backlog monitor's.
     *
     * @return void
     */
    public function testIndexesWhatTheDrainAndTheMonitorRead(): void
    {
        $secondary = array_values(array_filter(Schema::getIndexes(self::TABLE), static fn (array $index): bool => !$index['primary']));
        $indexes   = array_map(static fn (array $index): array => [$index['name'], $index['columns'], $index['unique']], $secondary);

        usort($indexes, static fn (array $one, array $other): int => strcmp($one[0], $other[0]));

        self::assertSame(
            [[self::TABLE . '_due_index', ['failed_at', 'available_at'], false], [self::TABLE . '_queued_index', ['failed_at', 'created_at'], false]],
            $indexes,
        );
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

        self::assertCount($sqlite ? 2 : 3, $lengths);
        self::assertLessThanOrEqual(63, max($lengths));
        self::assertContains(strlen(self::TABLE . '_queued_index'), $lengths);
    }

    /**
     * The table has no foreign keys.
     *
     * @return void
     */
    public function testHasNoForeignKeys(): void
    {
        self::assertSame([], Schema::getForeignKeys(self::TABLE));
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

        self::assertEqualsCanonicalizing(['id', 'payload', 'claimed_by', 'last_error_class'], array_keys($collations));

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
     * Claim tokens differing only in case are distinct.
     *
     * @return void
     */
    public function testClaimTokensDifferingOnlyInCaseAreDistinct(): void
    {
        DB::table(self::TABLE)->insert([self::row(1, ['claimed_by' => 'ABC']), self::row(2, ['claimed_by' => 'abc'])]);

        self::assertSame(1, DB::table(self::TABLE)->where('claimed_by', 'abc')->count());
        self::assertSame(1, DB::table(self::TABLE)->where('claimed_by', 'ABC')->count());
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
        DB::table(self::TABLE)->insert(self::row(1));

        try {
            $this->loadMigration()->up(); // @phpstan-ignore method.notFound
            self::fail('Expected the migration to stop.');
        } catch (TableAlreadyExistsException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame(
                'Cannot install the laravel-audit-log migration for the \'' . self::TABLE . '\' table: a table with that name already exists on connection \''
                . self::CONNECTION . '\'. Set `delivery.outbox.table` in config/audit-log.php to a different name and re-run the migration.',
                $exception->getMessage(),
            );
        }

        self::assertSame(1, DB::table(self::TABLE)->count());
    }

    /**
     * A full row, numbered so its id is its own.
     *
     * @param  int  $number
     * @param  array<string, string>  $columns
     * @return array<string, string>
     */
    private static function row(int $number, array $columns = []): array
    {
        return [
            'id'           => sprintf('0195f4a2-7b1c-7000-8000-%012d', $number),
            'payload'      => 'eyJpdiI6ImVuY3J5cHRlZCJ9',
            'available_at' => '2026-11-01 12:00:00.000000',
            'created_at'   => '2026-11-01 12:00:00.000000',
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
            self::fail('Outbox migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
