<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Database\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Integration tests for the integrity state migration's table and seeded id; a
 * migration is an anonymous class, so they cover nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class IntegrityStateTableSchemaTest extends TestCase
{
    /** @var string Absolute path to the shipped integrity state migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000500_create_audit_log_integrity_state_table.php';

    /** @var string Configured table name the migration runs for: the longest one accepted, 47 characters. */
    private const string TABLE = 'audit_log_integrity_state_for_a_long_table_name';

    /** @var string A lower-case UUID version 7. */
    private const string UUID_V7 = '/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/';

    /**
     * Migrate `TABLE` with the builder's default precision at whole seconds.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('audit-log.integrity.state_table', self::TABLE);

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
     * A name, a value and a time, in order, none nullable.
     *
     * @return void
     */
    public function testCreatesEveryColumnWithItsNullability(): void
    {
        self::assertSame([
            'name'       => false,
            'value'      => false,
            'updated_at' => false,
        ], array_column(Schema::getColumns(self::TABLE), 'nullable', 'name'));
    }

    /**
     * The name alone is the primary key and the only index.
     *
     * @return void
     */
    public function testTheNameIsThePrimaryKey(): void
    {
        $indexes = Schema::getIndexes(self::TABLE);

        self::assertCount(1, $indexes);

        $key = reset($indexes);

        self::assertTrue($key['primary']);
        self::assertSame(['name'], $key['columns']);

        DB::table(self::TABLE)->insert(self::row('seal.last'));

        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row('seal.last'));
    }

    /**
     * The name has 64 characters and the value is uncut text.
     *
     * @return void
     */
    public function testTheValueIsText(): void
    {
        $columns = Schema::getColumns(self::TABLE);
        $names   = array_column($columns, 'type_name', 'name');

        self::assertSame('text', $names['value']);

        if (Schema::getConnection()->getDriverName() !== 'sqlite') {
            self::assertStringContainsString('(64)', array_column($columns, 'type', 'name')['name']);
        }

        $value = '{"cursor":"' . str_repeat('a', 4000) . '"}';

        DB::table(self::TABLE)->insert(self::row('sweep.cursor', ['value' => $value]));

        self::assertSame($value, DB::table(self::TABLE)->where('name', 'sweep.cursor')->value('value'));
    }

    /**
     * The time is stored to the microsecond, whatever the builder's default.
     *
     * @return void
     */
    public function testStoresTheTimeToTheMicrosecond(): void
    {
        if (Schema::getConnection()->getDriverName() !== 'sqlite') {
            self::assertStringContainsString('(6)', array_column(Schema::getColumns(self::TABLE), 'type', 'name')['updated_at']);
        }

        DB::table(self::TABLE)->insert(self::row('seal.last', ['updated_at' => '2026-11-01 12:00:00.123456']));

        self::assertSame('2026-11-01 12:00:00.123456', DB::table(self::TABLE)->where('name', 'seal.last')->value('updated_at'));
    }

    /**
     * The migration seeds the installation id once, a UUID v7 written in UTC.
     *
     * @return void
     */
    public function testTheMigrationSeedsTheInstallationIdOnce(): void
    {
        $rows = DB::table(self::TABLE)->get(['name', 'value', 'updated_at'])->all();

        self::assertCount(1, $rows);
        self::assertSame(InstallationIdentity::NAME, $rows[0]->name);

        $value = json_decode((string) $rows[0]->value, true);

        self::assertIsArray($value);
        self::assertSame(['id'], array_keys($value));
        self::assertIsString($value['id']);
        self::assertMatchesRegularExpression(self::UUID_V7, $value['id']);
        // PostgreSQL drops a fraction's trailing zeros when it returns a time
        $written = (string) $rows[0]->updated_at;

        self::assertMatchesRegularExpression('/\A\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d{1,6})?\z/', $written);

        $at = \DateTimeImmutable::createFromFormat('Y-m-d H:i:s.u', str_pad(str_contains($written, '.') ? $written : $written . '.', 26, '0'), new \DateTimeZone('UTC'));

        self::assertInstanceOf(\DateTimeImmutable::class, $at);
        self::assertSame((int) $at->format('Uv'), hexdec(substr(str_replace('-', '', $value['id']), 0, 12)));
    }

    /**
     * A second row under the seeded id's name is refused.
     *
     * @return void
     */
    public function testTheSeededIdIsNeverWrittenTwice(): void
    {
        $this->expectException(UniqueConstraintViolationException::class);

        DB::table(self::TABLE)->insert(self::row(InstallationIdentity::NAME));
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
    }

    /**
     * On MySQL the table is binary without padding and on InnoDB.
     *
     * @return void
     */
    public function testOnMySqlEveryCharacterColumnIsBinaryWithoutPadding(): void
    {
        if (Schema::getConnection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL compares by a collation the migration sets.');
        }

        $collations = array_filter(array_column(Schema::getColumns(self::TABLE), 'collation', 'name'), static fn (?string $collation): bool => $collation !== null);

        self::assertSame(['name' => 'utf8mb4_0900_bin', 'value' => 'utf8mb4_0900_bin'], $collations);

        $tables = Schema::getTables();

        self::assertSame('utf8mb4_0900_bin', array_column($tables, 'collation', 'name')[self::TABLE]);
        self::assertSame('InnoDB', array_column($tables, 'engine', 'name')[self::TABLE]);
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
        DB::table(self::TABLE)->insert(self::row('seal.last'));

        $rows = DB::table(self::TABLE)->orderBy('name')->get()->all();

        try {
            $this->loadMigration()->up(); // @phpstan-ignore method.notFound
            self::fail('Expected the migration to stop.');
        } catch (TableAlreadyExistsException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame(
                'Cannot install the laravel-audit-log migration for the \'' . self::TABLE . '\' table: a table with that name already exists on connection \''
                . self::CONNECTION . '\'. Set `integrity.state_table` in config/audit-log.php to a different name and re-run the migration.',
                $exception->getMessage(),
            );
        }

        self::assertEquals($rows, DB::table(self::TABLE)->orderBy('name')->get()->all());
    }

    /**
     * A progress row under the name, with the given columns replaced.
     *
     * @param  string  $name
     * @param  array<string, string>  $columns
     * @return array<string, string>
     */
    private static function row(string $name, array $columns = []): array
    {
        return [
            'name'       => $name,
            'value'      => '{"sequence":1}',
            'updated_at' => '2026-11-01 12:00:00.000000',
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
            self::fail('Integrity state migration file did not return a Migration instance.');
        }

        return $migration;
    }
}
