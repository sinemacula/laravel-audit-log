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
 * Integration tests for the table the shipped deliveries migration creates, on
 * every engine; a migration is an anonymous class, so they cover nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class DeliveriesTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped deliveries migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000200_create_audit_log_deliveries_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_deliveries_for_a_very_long_table_name';

    /**
     * Migrate `TABLE` with the builder's default precision at whole seconds.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('audit-log.delivery.deliveries_table', self::TABLE);

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
     * Six columns in order; only the delivery and the last error are nullable.
     *
     * @return void
     */
    public function testCreatesEveryColumnWithItsNullability(): void
    {
        self::assertSame([
            'entry_id'           => false,
            'destination'        => false,
            'attempts'           => false,
            'first_attempted_at' => false,
            'delivered_at'       => true,
            'last_error_class'   => true,
        ], array_column(Schema::getColumns(self::TABLE), 'nullable', 'name'));
    }

    /**
     * The entry id is a UUID; the destination and error have their lengths.
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

        self::assertSame($driver === 'pgsql' ? 'uuid' : 'char(36)', $types['entry_id']);
        self::assertStringContainsString('(64)', $types['destination']);
        self::assertStringContainsString('(191)', $types['last_error_class']);
    }

    /**
     * A new receipt has no attempts, and both times keep their microseconds.
     *
     * @return void
     */
    public function testStoresBothTimesToTheMicrosecond(): void
    {
        if (Schema::getConnection()->getDriverName() !== 'sqlite') {
            $types = array_column(Schema::getColumns(self::TABLE), 'type', 'name');

            self::assertStringContainsString('(6)', $types['first_attempted_at']);
            self::assertStringContainsString('(6)', $types['delivered_at']);
        }

        DB::table(self::TABLE)->insert(self::row(1, 'store', ['first_attempted_at' => '2026-11-01 12:00:00.123456', 'delivered_at' => '2026-11-01 12:00:01.654321']));

        $row = DB::table(self::TABLE)->first(['attempts', 'first_attempted_at', 'delivered_at']);

        self::assertNotNull($row);
        self::assertSame(0, (int) $row->attempts);
        self::assertSame('2026-11-01 12:00:00.123456', $row->first_attempted_at);
        self::assertSame('2026-11-01 12:00:01.654321', $row->delivered_at);
    }

    /**
     * The primary key is the entry, then the destination, and the only index.
     *
     * @return void
     */
    public function testTheKeyIsTheEntryAndTheDestination(): void
    {
        $indexes = Schema::getIndexes(self::TABLE);

        self::assertCount(1, $indexes);

        $key = reset($indexes);

        self::assertTrue($key['primary']);
        self::assertSame(['entry_id', 'destination'], $key['columns']);
    }

    /**
     * An entry has one receipt per destination.
     *
     * @return void
     */
    public function testAnEntryHasOneReceiptPerDestination(): void
    {
        DB::table(self::TABLE)->insert([self::row(1, 'store'), self::row(1, 'siem'), self::row(2, 'store')]);

        self::assertSame(2, DB::table(self::TABLE)->where('entry_id', self::id(1))->count());

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row(1, 'siem'));
    }

    /**
     * Destinations differing only in case or trailing space are distinct.
     *
     * @return void
     */
    public function testDestinationsDifferingOnlyInCaseOrPaddingAreDistinct(): void
    {
        DB::table(self::TABLE)->insert([self::row(1, 'siem'), self::row(1, 'SIEM'), self::row(1, 'siem ')]);

        self::assertSame(3, DB::table(self::TABLE)->count());
        self::assertSame(1, DB::table(self::TABLE)->where('destination', 'siem')->count());
    }

    /**
     * The key's name fits PostgreSQL's 63 characters; MySQL names it `primary`.
     *
     * @return void
     */
    public function testTheKeyNameFitsAtTheLongestTableName(): void
    {
        $driver = Schema::getConnection()->getDriverName();

        if ($driver === 'sqlite') {
            self::markTestSkipped('SQLite names its primary key index itself and limits no name.');
        }

        self::assertSame(47, strlen(self::TABLE));

        $names = array_column(Schema::getIndexes(self::TABLE), 'name');

        self::assertCount(1, $names);
        self::assertLessThanOrEqual(63, strlen($names[0]));

        self::assertSame($driver === 'pgsql' ? self::TABLE . '_pkey' : 'primary', $names[0]);
    }

    /**
     * The table has no foreign keys.
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

        self::assertEqualsCanonicalizing(['entry_id', 'destination', 'last_error_class'], array_keys($collations));

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
        DB::table(self::TABLE)->insert(self::row(1, 'store'));

        try {
            $this->loadMigration()->up(); // @phpstan-ignore method.notFound
            self::fail('Expected the migration to stop.');
        } catch (TableAlreadyExistsException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame(
                'Cannot install the laravel-audit-log migration for the \'' . self::TABLE . '\' table: a table with that name already exists on connection \''
                . self::CONNECTION . '\'. Set `delivery.deliveries_table` in config/audit-log.php to a different name and re-run the migration.',
                $exception->getMessage(),
            );
        }

        self::assertSame(1, DB::table(self::TABLE)->count());
    }

    /**
     * The id of the numbered entry.
     *
     * @param  int  $number
     * @return string
     */
    private static function id(int $number): string
    {
        return sprintf('0195f4a2-7b1c-7000-8000-%012d', $number);
    }

    /**
     * A receipt for the numbered entry and the destination.
     *
     * @param  int  $number
     * @param  string  $destination
     * @param  array<string, string>  $columns
     * @return array<string, string>
     */
    private static function row(int $number, string $destination, array $columns = []): array
    {
        return [
            'entry_id'           => self::id($number),
            'destination'        => $destination,
            'first_attempted_at' => '2026-11-01 12:00:00.000000',
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
            self::fail('Deliveries migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
