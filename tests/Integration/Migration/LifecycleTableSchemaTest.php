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
 * Integration tests for the shape of the lifecycle journal the shipped
 * migration creates, on whichever engine the suite runs against: its columns,
 * their types, lengths and nullability, the shape's indexes, a unique sequence,
 * a payload kept as text byte for byte, and the collision guard, the setting
 * that renames it and its rollback.
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
final class LifecycleTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped lifecycle journal migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000700_create_audit_log_lifecycle_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_lifecycle_under_a_long_table_name_xxx';

    /** @var string The setting that names the table. */
    private const string SETTING = 'audit-log.lifecycle.journal_table';

    /** @var string A table name the setting may give instead, for the rename test. */
    private const string RENAMED = 'audit_renamed_journal';

    /** @var array<string, int> The length of every string column. */
    private const array STRING_LENGTHS = [
        'log_id'             => 64,
        'kind'               => 32,
        'authority_type'     => 191,
        'authority_id'       => 191,
        'reason'             => 64,
        'external_reference' => 191,
        'payload_digest'     => 64,
        'previous_hmac'      => 64,
        'key_id'             => 32,
        'hmac'               => 64,
    ];

    /** @var list<string> The columns that hold a time. */
    private const array TIMES = ['occurred_at'];

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
     * The table holds the seventeen columns of a journal row, in order, each
     * with the type family, length and nullability the shape gives it: only the
     * authority, the seal, the hold and the link to the row before may be
     * missing.
     *
     * @return void
     */
    public function testEveryColumnHasItsTypeLengthAndNullability(): void
    {
        $shape   = TableShape::journal();
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
     * The primary key is the row's id, and the other indexes are exactly the
     * shape's: the unique sequence and the lookups by seal, by hold and by
     * kind, each named after the table.
     *
     * @return void
     */
    public function testTheIndexesAreTheShapesIndexes(): void
    {
        $shape     = TableShape::journal();
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
     * On MySQL the table is binary without padding and on InnoDB, as every
     * table the package keeps.
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
     * A sequence is held by one row only, so two operations that both read the
     * same head can never both extend it.
     *
     * @return void
     */
    public function testTheSequenceIsUnique(): void
    {
        DB::table(self::TABLE)->insert(self::row(1));

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row(2, ['sequence' => 1]));
    }

    /**
     * The payload is text, never a JSON column, so the bytes the digest covers
     * are the bytes read back: keys keep their order and spacing, which a JSON
     * column on MySQL would not; a sequence beyond a 32-bit integer is kept.
     *
     * @return void
     */
    public function testThePayloadIsTextKeptByteForByte(): void
    {
        $types   = array_column(Schema::getColumns(self::TABLE), 'type_name', 'name');
        $payload = '{"z":1,"a":{"y":[2,1],"b":"\u00e9"}}';

        self::assertSame(match (Schema::getConnection()->getDriverName()) {
            'mysql' => 'longtext',
            default => 'text',
        }, $types['payload']);

        DB::table(self::TABLE)->insert(self::row(1, ['payload' => $payload, 'sequence' => 2 ** 40]));

        self::assertSame($payload, DB::table(self::TABLE)->value('payload'));
        self::assertSame(2 ** 40, DB::table(self::TABLE)->value('sequence'));
    }

    /**
     * The first row has no previous HMAC and names no authority, seal or hold;
     * every other column is required.
     *
     * @return void
     */
    public function testTheFirstRowNeedsNoLinkAndAPruneRunNoAuthority(): void
    {
        DB::table(self::TABLE)->insert(self::row(1));

        $row = DB::table(self::TABLE)->first(['previous_hmac', 'authority_type', 'authority_id', 'reason', 'seal_id', 'hold_id']);

        self::assertNotNull($row);
        self::assertSame([null, null, null, null, null, null], array_values((array) $row));
    }

    /**
     * Running the migration when the configured table already exists throws a
     * `TableAlreadyExistsException` naming the table, the connection and the
     * `lifecycle.journal_table` setting that renames it, and leaves the table
     * as it was.
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
                . self::CONNECTION . '\'. Set `lifecycle.journal_table` in config/audit-log.php to a different name and re-run the migration.',
                $exception->getMessage(),
            );
        }

        self::assertTrue(Schema::hasTable(self::TABLE));
        self::assertSame($before, DB::table(self::TABLE)->count());
    }

    /**
     * The table is created under whatever name its setting gives, and its
     * indexes are named after it.
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
     * A first journal row with every column a row must have, numbered so its id
     * and sequence are its own, with the given columns replaced.
     *
     * @param  int  $number
     * @param  array<string, int|string>  $columns
     * @return array<string, int|string>
     */
    private static function row(int $number, array $columns = []): array
    {
        return [
            'id'             => sprintf('01932b4e-9000-7000-8000-%012d', $number),
            'sequence'       => $number,
            'log_id'         => 'app-eu-1',
            'kind'           => 'prune_run',
            'operation_id'   => '01932b4e-9000-7000-8000-00000000aaaa',
            'occurred_at'    => '2026-11-01 12:00:00.000000',
            'payload'        => '{}',
            'payload_digest' => str_repeat('a', 64),
            'key_id'         => 'k2026',
            'hmac'           => str_repeat('b', 64),
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
            self::fail('The lifecycle journal migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
