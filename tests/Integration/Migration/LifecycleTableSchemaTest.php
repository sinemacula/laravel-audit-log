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
 * Integration tests for the lifecycle journal the shipped migration creates, on
 * every engine; a migration is an anonymous class, so they cover nothing.
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
     * Seventeen columns; only authority, seal, hold and link are nullable.
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
     * The indexes are the primary key and the shape's four.
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
     * A sequence is held by one row only.
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
     * The payload is text kept byte for byte, which a MySQL JSON column is not.
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
     * The first row needs no link, authority, seal or hold.
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
     * An existing table is refused with an exception naming the setting.
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
     * A first journal row, numbered so its id and sequence are its own.
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
            self::fail('The lifecycle journal migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
