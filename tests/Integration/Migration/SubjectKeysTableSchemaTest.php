<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Schema\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Console\SchemaChecks;
use SineMacula\Laravel\AuditLog\Console\TableShape;
use SineMacula\Laravel\AuditLog\Database\TableAlreadyExistsException;
use Tests\Concerns\LoadsShippedMigrations;
use Tests\TestCase;

/**
 * Integration tests for the subject keys table the shipped migration creates,
 * on every engine; a migration is an anonymous class, so they cover nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class SubjectKeysTableSchemaTest extends TestCase
{
    use LoadsShippedMigrations;

    /** @var string Absolute path to the shipped subject keys migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_001100_create_audit_log_subject_keys_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_subject_keys_under_a_long_table_namex';

    /** @var string The setting that names the table. */
    private const string SETTING = 'audit-log.privacy.subject_keys_table';

    /** @var string A table name the setting may give instead, for the rename test. */
    private const string RENAMED = 'audit_renamed_subject_keys';

    /** @var string The digest of a key unit, as a row stores it. */
    private const string UNIT = '6f1ed002ab5595859014ebf0951522d9e1a2b3c4d5e6f708192a3b4c5d6e7f80';

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
            $this->loadMigration(self::MIGRATION_PATH)->up(); // @phpstan-ignore method.notFound
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
     * Fifteen columns in order; only the tenant, wrapped key, its key id and
     * erasure are nullable.
     *
     * @return void
     */
    public function testTheColumnsAreInOrderWithTheirTypes(): void
    {
        $shape   = TableShape::subjectKeys();
        $columns = Schema::getColumns(self::TABLE);

        self::assertSame(array_keys($shape->columns), array_column($columns, 'name'));
        self::assertSame(array_map(static fn (array $column): bool => $column[2], $shape->columns), array_column($columns, 'nullable', 'name'));
        self::assertSame([], (new SchemaChecks(app(DatabaseManager::class)))->problems(self::CONNECTION, self::TABLE, $shape));

        if (Schema::getConnection()->getDriverName() === 'sqlite') {
            return;
        }

        $types = array_column($columns, 'type', 'name');

        foreach ($shape->columns as $column => [$family, $size]) {
            if ($family !== 'string' && $family !== 'datetime') {
                continue;
            }

            self::assertStringContainsString('(' . $size . ')', $types[$column], $column);
        }
    }

    /**
     * A unit holds one key per generation.
     *
     * @return void
     */
    public function testTheUnitAndGenerationAreUnique(): void
    {
        DB::table(self::TABLE)->insert(self::row(1, ['generation' => 1]));
        DB::table(self::TABLE)->insert(self::row(2, ['generation' => 2]));
        DB::table(self::TABLE)->insert(self::row(3, ['generation' => 1, 'unit' => str_repeat('b', 64)]));

        self::assertSame(3, DB::table(self::TABLE)->count());

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row(4, ['generation' => 2]));
    }

    /**
     * Tenantless rows cannot share a generation; the unit's digest is unique.
     *
     * @return void
     */
    public function testTwoTenantlessRowsCannotShareAGeneration(): void
    {
        DB::table(self::TABLE)->insert(self::row(1, ['tenant_type' => null, 'tenant_id' => null]));
        DB::table(self::TABLE)->insert(self::row(2, ['tenant_type' => null, 'tenant_id' => null, 'generation' => 2]));

        self::assertSame(2, DB::table(self::TABLE)->whereNull('tenant_type')->count());

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row(3, ['tenant_type' => null, 'tenant_id' => null]));
    }

    /**
     * The indexes are the primary key and the shape's three.
     *
     * @return void
     */
    public function testTheOwnerAndTheErasureAreIndexed(): void
    {
        $shape     = TableShape::subjectKeys();
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
     * A key reads back as written, its wrapped key byte for byte.
     *
     * @return void
     *
     * @throws \DateMalformedStringException
     */
    public function testAKeyIsReadBackAsWritten(): void
    {
        $wrapped = rtrim(strtr(base64_encode(str_repeat("\xfb\xef", 30)), '+/', '-_'), '=');

        DB::table(self::TABLE)->insert(self::row(1, ['wrapped_key' => $wrapped, 'created_at' => '2026-11-01 12:00:00.120000']));
        DB::table(self::TABLE)->insert(self::row(2, [
            'generation'  => 2,
            'state'       => 'erased',
            'wrapped_key' => null,
            'wrap_key_id' => null,
            'erasure_id'  => '01932b4e-9000-7000-8000-000000000099',
        ]));

        $live   = DB::table(self::TABLE)->where('generation', 1)->first(['wrapped_key', 'created_at']);
        $erased = DB::table(self::TABLE)->where('generation', 2)->first(['state', 'wrapped_key', 'wrap_key_id', 'erasure_id']);

        self::assertNotNull($live);
        self::assertNotNull($erased);
        self::assertSame([$wrapped, '2026-11-01 12:00:00.120000'], [$live->wrapped_key, (new \DateTimeImmutable((string) $live->created_at))->format('Y-m-d H:i:s.u')]);
        self::assertSame(['erased', null, null, '01932b4e-9000-7000-8000-000000000099'], array_values((array) $erased));
    }

    /**
     * An existing table is refused naming the setting, and keeps its keys.
     *
     * @return void
     */
    public function testAnExistingTableIsNeverReplaced(): void
    {
        DB::table(self::TABLE)->insert(self::row(1));

        try {
            $this->loadMigration(self::MIGRATION_PATH)->up(); // @phpstan-ignore method.notFound
            self::fail('Expected the migration to stop.');
        } catch (TableAlreadyExistsException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame(
                'Cannot install the laravel-audit-log migration for the \'' . self::TABLE . '\' table: a table with that name already exists on connection \''
                . self::CONNECTION . '\'. Set `privacy.subject_keys_table` in config/audit-log.php to a different name and re-run the migration.',
                $exception->getMessage(),
            );
        }

        self::assertTrue(Schema::hasTable(self::TABLE));
        self::assertSame([sprintf('01932b4e-9000-7000-8000-%012d', 1)], DB::table(self::TABLE)->pluck('id')->all());
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

        $this->loadMigration(self::MIGRATION_PATH)->up(); // @phpstan-ignore method.notFound

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
        $this->loadMigration(self::MIGRATION_PATH)->down(); // @phpstan-ignore method.notFound

        self::assertFalse(Schema::hasTable(self::TABLE));
    }

    /**
     * A live key of a tenant's unit, numbered so its id is its own.
     *
     * @param  int  $number
     * @param  array<string, int|string|null>  $columns
     * @return array<string, int|string|null>
     */
    private static function row(int $number, array $columns = []): array
    {
        return [
            'id'          => sprintf('01932b4e-9000-7000-8000-%012d', $number),
            'owner_type'  => 'customer',
            'owner_id'    => '42',
            'tenant_type' => 'organisation',
            'tenant_id'   => 'org_1',
            'category'    => 'billing',
            'unit'        => self::UNIT,
            'generation'  => 1,
            'state'       => 'live',
            'wrapped_key' => str_repeat('A', 80),
            'wrap_key_id' => 'k2026',
            'created_at'  => '2026-11-01 12:00:00.000000',
            'key_id'      => 'k2026',
            'hmac'        => str_repeat('c', 64),
            ...$columns,
        ];
    }
}
