<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\SQLiteBuilder;
use Illuminate\Database\SQLiteConnection;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\SchemaChecks;
use Tests\Fixtures\Database\EntriesTableShape;
use Tests\TestCase;

/**
 * Feature tests for the schema checks of `audit-log:check`: the table the
 * shipped migration creates has no problem, and each way a table can differ
 * from it, one at a time, is the one problem reported.
 *
 * Each test runs the shipped migration under a table name of its own, then
 * changes the table in one way; Laravel rebuilds the table on SQLite for a
 * changed or dropped column. A change an engine cannot make is skipped there,
 * with the reason.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SchemaChecks::class)]
final class SchemaChecksTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The table each test migrates and checks. */
    private const string TABLE = 'audit_check_entries';

    /** @var string Absolute path to the shipped entries migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000000_create_audit_log_entries_table.php';

    /** @var string A table name that fits the setting but not beside the prefix. */
    private const string LONG_TABLE = 'audit_check_entries_under_a_long_table_name';

    /** @var string The table prefix of the prefixed connection. */
    private const string PREFIX = 'tenant_prefix_';

    /** @var array<string, array<string, array{0: string, 1: string}>> The type name and full type MySQL and PostgreSQL report for each column that is not a string, by name. */
    private const array REPORTED = [
        'mysql' => [
            'id'                => ['char', 'char(36)'],
            'import_batch_id'   => ['char', 'char(36)'],
            'record_version'    => ['smallint', 'smallint'],
            'event_version'     => ['smallint', 'smallint'],
            'integrity_version' => ['smallint', 'smallint'],
            'context'           => ['json', 'json'],
            'properties'        => ['json', 'json'],
            'occurred_at'       => ['datetime', 'datetime(6)'],
            'recorded_at'       => ['datetime', 'datetime(6)'],
        ],
        'pgsql' => [
            'id'                => ['uuid', 'uuid'],
            'import_batch_id'   => ['uuid', 'uuid'],
            'record_version'    => ['int2', 'smallint'],
            'event_version'     => ['int2', 'smallint'],
            'integrity_version' => ['int2', 'smallint'],
            'context'           => ['json', 'json'],
            'properties'        => ['json', 'json'],
            'occurred_at'       => ['timestamp', 'timestamp(6) without time zone'],
            'recorded_at'       => ['timestamp', 'timestamp(6) without time zone'],
        ],
    ];

    /**
     * Run the shipped migration for `TABLE` on the test's connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        app(ConfigRepository::class)->set('audit-log.entries.table', self::TABLE);

        $this->migrate();
    }

    /**
     * Drop the tables the test migrated.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::connection(self::CONNECTION)->dropIfExists(self::TABLE);

        if (app(ConfigRepository::class)->has('database.connections.prefixed')) {
            Schema::connection('prefixed')->dropIfExists(self::LONG_TABLE);
        }

        parent::tearDown();
    }

    /**
     * The table the shipped migration creates has no problem.
     *
     * @return void
     */
    public function testTheShippedMigrationHasNoProblems(): void
    {
        self::assertSame([], $this->problems());
    }

    /**
     * A table that does not exist is the one problem, naming the table, the
     * connection and how to create it.
     *
     * @return void
     */
    public function testAMissingTableIsTheOnlyProblem(): void
    {
        self::assertSame([
            'The entries table `audit_other_entries` does not exist on connection [testing]; publish and run the migrations'
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
        ], $this->problems('audit_other_entries'));
    }

    /**
     * A column the package writes that the table lacks is a problem.
     *
     * @return void
     */
    public function testAMissingColumnIsAProblem(): void
    {
        $this->alter(static function (Blueprint $table): void {
            $table->dropColumn('reason');
        });

        self::assertSame(['Column `reason` is missing.'], $this->problems());
    }

    /**
     * A column of another type family is a problem, naming both types.
     *
     * @return void
     */
    public function testAColumnOfTheWrongTypeIsAProblem(): void
    {
        $this->alter(static function (Blueprint $table): void {
            $table->text('user_agent')->nullable()->change();
        });

        $expected = $this->driver() === 'sqlite' ? 'varchar' : 'varchar(512)';

        self::assertSame(["Column `user_agent` is text; expected {$expected}."], $this->problems());
    }

    /**
     * On PostgreSQL a payload column of `jsonb`, which keeps no text, is a
     * problem.
     *
     * @return void
     */
    public function testJsonbIsAProblemOnPostgres(): void
    {
        if ($this->driver() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL has a jsonb type of its own.');
        }

        $this->alter(static function (Blueprint $table): void {
            $table->jsonb('context')->nullable()->change();
        });

        self::assertSame(['Column `context` is jsonb; expected json.'], $this->problems());
    }

    /**
     * A column that may be null and must not, and one that must be nullable and
     * is not, are each a problem.
     *
     * @return void
     */
    public function testAColumnWithTheWrongNullabilityIsAProblem(): void
    {
        $this->alter(static function (Blueprint $table): void {
            $table->string('event', 191)->nullable()->change();
            $table->string('reason', 64)->nullable(false)->change();
        });

        self::assertSame([
            'Column `event` is nullable; it must not be.',
            'Column `reason` is not nullable; it must be.',
        ], $this->problems());
    }

    /**
     * On MySQL and PostgreSQL a string column of another length is a problem;
     * SQLite records no length.
     *
     * @return void
     */
    public function testAColumnWithoutItsLengthIsAProblem(): void
    {
        $this->skipOnSqlite('SQLite records no length for a string column.');

        $this->alter(static function (Blueprint $table): void {
            $table->string('event', 255)->change();
        });

        self::assertSame(['Column `event` is varchar(255); expected varchar(191).'], $this->problems());
    }

    /**
     * On MySQL and PostgreSQL a time kept to the second rather than the
     * microsecond is a problem; SQLite records no precision.
     *
     * @return void
     */
    public function testATimeWithoutItsMicrosecondsIsAProblem(): void
    {
        $this->skipOnSqlite('SQLite records no precision for a time column.');

        $this->alter(static function (Blueprint $table): void {
            $table->dateTime('occurred_at', 0)->change();
        });

        $actual = $this->driver() === 'pgsql' ? 'timestamp(0)' : 'datetime';
        $type   = $this->driver() === 'pgsql' ? 'timestamp(6)' : 'datetime(6)';

        self::assertSame(["Column `occurred_at` is {$actual}; expected {$type}."], $this->problems());
    }

    /**
     * A column the package does not write is a problem, because no entry's HMAC
     * covers it.
     *
     * @return void
     */
    public function testAnUnexpectedColumnIsAProblem(): void
    {
        $this->alter(static function (Blueprint $table): void {
            $table->string('notes')->nullable();
        });

        self::assertSame(['Column `notes` is not one the package writes, so no entry\'s HMAC covers it.'], $this->problems());
    }

    /**
     * An index the migration creates that the table lacks is a problem.
     *
     * @return void
     */
    public function testAMissingIndexIsAProblem(): void
    {
        $this->alter(static function (Blueprint $table): void {
            $table->dropIndex(self::TABLE . '_event_index');
        });

        self::assertSame(['Index `audit_check_entries_event_index` is missing.'], $this->problems());
    }

    /**
     * An index under the migration's name over other columns is a problem,
     * naming both column lists.
     *
     * @return void
     */
    public function testAnIndexOverOtherColumnsIsAProblem(): void
    {
        $this->replaceIndex(self::TABLE . '_event_index', static function (Blueprint $table): void {
            $table->index(['event'], self::TABLE . '_event_index');
        });

        self::assertSame(['Index `audit_check_entries_event_index` covers (`event`); expected (`event`, `occurred_at`).'], $this->problems());
    }

    /**
     * An index over the right columns in another order is a problem, since the
     * order decides which lookups it serves.
     *
     * @return void
     */
    public function testAnIndexWhoseColumnsAreOutOfOrderIsAProblem(): void
    {
        $this->replaceIndex(self::TABLE . '_actor_index', static function (Blueprint $table): void {
            $table->index(['actor_id', 'actor_type', 'occurred_at'], self::TABLE . '_actor_index');
        });

        self::assertSame([
            'Index `audit_check_entries_actor_index` covers (`actor_id`, `actor_type`, `occurred_at`); expected (`actor_type`, `actor_id`, `occurred_at`).',
        ], $this->problems());
    }

    /**
     * A source identity index that is not unique is a problem, since it no
     * longer keeps a source's record id once.
     *
     * @return void
     */
    public function testASourceIndexThatIsNotUniqueIsAProblem(): void
    {
        $this->alter(static function (Blueprint $table): void {
            $table->dropUnique(self::TABLE . '_source_unique');
        });

        $this->alter(static function (Blueprint $table): void {
            $table->index(['source_id', 'source_record_id'], self::TABLE . '_source_unique');
        });

        self::assertSame(['Index `audit_check_entries_source_unique` must be unique.'], $this->problems());
    }

    /**
     * A lookup index made unique is a problem, since it would refuse entries
     * that share an actor and a time.
     *
     * @return void
     */
    public function testALookupIndexThatIsUniqueIsAProblem(): void
    {
        $this->replaceIndex(self::TABLE . '_occurred_index', static function (Blueprint $table): void {
            $table->unique(['occurred_at'], self::TABLE . '_occurred_index');
        });

        self::assertSame(['Index `audit_check_entries_occurred_index` must not be unique.'], $this->problems());
    }

    /**
     * An index over other columns that is also unique when it must not be is
     * two problems.
     *
     * @return void
     */
    public function testAnIndexWrongInBothWaysIsTwoProblems(): void
    {
        $this->replaceIndex(self::TABLE . '_correlate_index', static function (Blueprint $table): void {
            $table->unique(['correlation_id', 'occurred_at'], self::TABLE . '_correlate_index');
        });

        self::assertSame([
            'Index `audit_check_entries_correlate_index` covers (`correlation_id`, `occurred_at`); expected (`correlation_id`).',
            'Index `audit_check_entries_correlate_index` must not be unique.',
        ], $this->problems());
    }

    /**
     * A primary key over more than `id` is a problem.
     *
     * @return void
     */
    public function testAWrongPrimaryKeyIsAProblem(): void
    {
        $this->alter(static function (Blueprint $table): void {
            $table->dropPrimary();
        });

        $this->alter(static function (Blueprint $table): void {
            $table->primary(['id', 'occurred_at']);
        });

        self::assertSame(['The primary key must be (`id`).'], $this->problems());
    }

    /**
     * On MySQL a character column with a padding, case-insensitive collation is
     * a problem, since ids that differ by case or a trailing space would
     * compare equal.
     *
     * @return void
     */
    public function testOnMySqlAPaddedCollationIsAProblem(): void
    {
        if ($this->driver() !== 'mysql') {
            self::markTestSkipped('Only MySQL compares by a collation the migration sets.');
        }

        $this->alter(static function (Blueprint $table): void {
            $table->string('actor_id', 191)->nullable()->collation('utf8mb4_unicode_ci')->change();
        });

        self::assertSame(['Column `actor_id` uses collation utf8mb4_unicode_ci; expected utf8mb4_0900_bin.'], $this->problems());
    }

    /**
     * A table name the setting accepts is a problem when the connection's
     * prefix makes it longer than 47 characters, which no longer fits every
     * index name.
     *
     * @return void
     */
    public function testAPrefixedTableNameOver47CharactersIsAProblem(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.prefixed', [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => self::PREFIX]);
        $config->set('audit-log.storage.connection', 'prefixed');
        $config->set('audit-log.entries.table', self::LONG_TABLE);

        $this->migrate();

        $prefixed = self::PREFIX . self::LONG_TABLE;

        self::assertSame(57, strlen($prefixed));
        self::assertSame([sprintf('The prefixed table name `%s` is 57 characters; at most 47 fit every index name.', $prefixed)], $this->problems(self::LONG_TABLE, 'prefixed'));
    }

    /**
     * A prefixed table name of exactly 47 characters is not a problem.
     *
     * @return void
     */
    public function testAPrefixedTableNameOf47CharactersIsNotAProblem(): void
    {
        $config = app(ConfigRepository::class);
        $table  = 'audit_check_entries_of_exactly_33';

        $config->set('database.connections.prefixed', [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => self::PREFIX]);
        $config->set('audit-log.storage.connection', 'prefixed');
        $config->set('audit-log.entries.table', $table);

        $this->migrate();

        try {
            self::assertSame(47, strlen(self::PREFIX . $table));
            self::assertSame([], $this->problems($table, 'prefixed'));
        } finally {
            Schema::connection('prefixed')->dropIfExists($table);
        }
    }

    /**
     * An index the application added for its own lookups is not a problem.
     *
     * @return void
     */
    public function testAnApplicationIndexIsNotAProblem(): void
    {
        $this->alter(static function (Blueprint $table): void {
            $table->index(['ip', 'occurred_at'], self::TABLE . '_ip_index');
        });

        self::assertSame([], $this->problems());
    }

    /**
     * Every problem of a table is reported in one run, columns before indexes.
     *
     * @return void
     */
    public function testEveryProblemIsReportedTogether(): void
    {
        $this->alter(static function (Blueprint $table): void {
            $table->dropIndex(self::TABLE . '_tenant_index');
        });

        $this->alter(static function (Blueprint $table): void {
            $table->dropColumn(['hmac', 'tenant_id']);
        });

        self::assertSame([
            'Column `tenant_id` is missing.',
            'Column `hmac` is missing.',
            'Index `audit_check_entries_tenant_index` is missing.',
        ], $this->problems());
    }

    /**
     * A column of the wrong type that is also not nullable when it must be is
     * two problems.
     *
     * @return void
     */
    public function testAColumnWrongInBothWaysIsTwoProblems(): void
    {
        $this->alter(static function (Blueprint $table): void {
            $table->text('user_agent')->nullable(false)->change();
        });

        $expected = $this->driver() === 'sqlite' ? 'varchar' : 'varchar(512)';

        self::assertSame(["Column `user_agent` is text; expected {$expected}.", 'Column `user_agent` is not nullable; it must be.'], $this->problems());
    }

    /**
     * Rows of `[a driver]` whose reports carry lengths and precisions.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSizedDrivers(): iterable
    {
        yield from [
            'MySQL'      => ['mysql'],
            'PostgreSQL' => ['pgsql'],
        ];
    }

    /**
     * The shipped table as MySQL and PostgreSQL report it, lengths, precisions
     * and MySQL's collation included, has no problem; this runs on any engine
     * the suite runs against, through a connection that reports the table as
     * the engine would.
     *
     * @param  string  $driver
     * @return void
     */
    #[DataProvider('provideSizedDrivers')]
    public function testTheShippedTableAsEachEngineReportsItHasNoProblems(string $driver): void
    {
        $this->fake($driver, self::reported($driver));

        self::assertSame([], $this->problems(self::TABLE, 'fake'));
    }

    /**
     * Rows of
     * `[a driver, the column changed, its type name, its full type, its collation, the problem]`:
     * what MySQL or PostgreSQL could report for a column the package writes,
     * and how it is described.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: string, 4: ?string, 5: string}>
     */
    public static function provideReportedTypes(): iterable
    {
        yield from [
            'a string without its length on MySQL' => ['mysql', 'event', 'varchar', 'varchar', 'utf8mb4_0900_bin', 'Column `event` is varchar; expected varchar(191).'],
            'a uuid of another length on MySQL'    => ['mysql', 'id', 'char', 'char(32)', 'utf8mb4_0900_bin', 'Column `id` is char(32); expected char(36).'],
            'a time to the second on MySQL'        => ['mysql', 'occurred_at', 'datetime', 'datetime', null, 'Column `occurred_at` is datetime; expected datetime(6).'],
            'a padded collation on MySQL'          => [
                'mysql', 'actor_id', 'varchar', 'varchar(191)', 'utf8mb4_unicode_ci', 'Column `actor_id` uses collation utf8mb4_unicode_ci; expected utf8mb4_0900_bin.',
            ],
            'a small integer as an integer'     => ['mysql', 'record_version', 'int', 'int', null, 'Column `record_version` is int; expected smallint.'],
            'jsonb on PostgreSQL'               => ['pgsql', 'context', 'jsonb', 'jsonb', null, 'Column `context` is jsonb; expected json.'],
            'a type with a scale on PostgreSQL' => ['pgsql', 'ip', 'numeric', 'numeric(10, 2)', null, 'Column `ip` is numeric(10,2); expected varchar(255).'],
            'a uuid as text on PostgreSQL'      => ['pgsql', 'id', 'varchar', 'character varying(36)', null, 'Column `id` is varchar(36); expected uuid.'],
            'a collation PostgreSQL reports'    => ['pgsql', 'actor_id', 'varchar', 'character varying(191)', 'en_US.utf8', ''],
        ];
    }

    /**
     * Each column MySQL or PostgreSQL could report otherwise is the one
     * problem, described in the engine's own terms; a collation matters only on
     * MySQL.
     *
     * @param  string  $driver
     * @param  string  $column
     * @param  string  $typeName
     * @param  string  $type
     * @param  ?string  $collation
     * @param  string  $problem
     * @return void
     */
    #[DataProvider('provideReportedTypes')]
    public function testEachEngineReportsAColumnInItsOwnTerms(string $driver, string $column, string $typeName, string $type, ?string $collation, string $problem): void
    {
        $columns = array_map(static fn (array $reported): array => $reported['name'] === $column
            ? [...$reported, 'type_name' => $typeName, 'type' => $type, 'collation' => $collation]
            : $reported, self::reported($driver));

        $this->fake($driver, $columns);

        self::assertSame($problem === '' ? [] : [$problem], $this->problems(self::TABLE, 'fake'));
    }

    /**
     * The problems the checks find on the connection's table.
     *
     * @param  string  $table
     * @param  string  $connection
     * @return list<string>
     */
    private function problems(string $table = self::TABLE, string $connection = self::CONNECTION): array
    {
        $database = $this->app?->make(DatabaseManager::class);

        assert($database instanceof DatabaseManager);

        return (new SchemaChecks($database))->problems($connection, $table);
    }

    /**
     * The shipped table's columns as the driver reports them: their names and
     * nullability as the test's engine created them, their types and MySQL's
     * collation as the driver would report them.
     *
     * @param  string  $driver
     * @return list<array{name: string, type: string, type_name: string, collation: ?string, nullable: bool}>
     */
    private static function reported(string $driver): array
    {
        $columns = [];

        foreach (Schema::connection(self::CONNECTION)->getColumns(self::TABLE) as $column) {

            $name   = $column['name'];
            $length = EntriesTableShape::STRING_LENGTHS[$name] ?? null;
            $string = $driver === 'pgsql' ? "character varying({$length})" : "varchar({$length})";

            [$typeName, $type] = $length === null ? self::REPORTED[$driver][$name] : ['varchar', $string];

            $collation = $driver === 'mysql' && ($length !== null || $typeName === 'char') ? 'utf8mb4_0900_bin' : null;

            $columns[] = ['name' => $name, 'type' => $type, 'type_name' => $typeName, 'collation' => $collation, 'nullable' => $column['nullable']];
        }

        return $columns;
    }

    /**
     * Register a connection named `fake` that reports the driver and, for any
     * table, the columns given and the indexes of the table the test migrated,
     * with no server behind it.
     *
     * @param  string  $driver
     * @param  list<array{name: string, type: string, type_name: string, collation: ?string, nullable: bool}>  $columns
     * @return void
     */
    private function fake(string $driver, array $columns): void
    {
        $indexes = Schema::connection(self::CONNECTION)->getIndexes(self::TABLE);

        $schema = \Mockery::mock(SQLiteBuilder::class);

        $schema->shouldReceive('hasTable')->andReturnTrue();
        $schema->shouldReceive('getColumns')->andReturn($columns);
        $schema->shouldReceive('getIndexes')->andReturn($indexes);

        $connection = \Mockery::mock(SQLiteConnection::class . '[getSchemaBuilder]', [new \PDO('sqlite::memory:'), '', '', ['driver' => $driver]]);

        $connection->shouldReceive('getSchemaBuilder')->andReturn($schema);

        app(ConfigRepository::class)->set('database.connections.fake', ['driver' => $driver, 'database' => ':memory:', 'prefix' => '']);

        $this->app?->make(DatabaseManager::class)->extend('fake', static fn (): SQLiteConnection => $connection);
    }

    /**
     * Change the checked table on the test's connection.
     *
     * @param  \Closure(\Illuminate\Database\Schema\Blueprint): void  $change
     * @return void
     */
    private function alter(\Closure $change): void
    {
        Schema::connection(self::CONNECTION)->table(self::TABLE, $change);
    }

    /**
     * Drop an index the migration created and create another in its place.
     *
     * @param  string  $index
     * @param  \Closure(\Illuminate\Database\Schema\Blueprint): void  $create
     * @return void
     */
    private function replaceIndex(string $index, \Closure $create): void
    {
        $this->alter(static function (Blueprint $table) use ($index): void {
            $table->dropIndex($index);
        });

        $this->alter($create);
    }

    /**
     * The driver of the test's connection.
     *
     * @return string
     */
    private function driver(): string
    {
        return Schema::connection(self::CONNECTION)->getConnection()->getDriverName();
    }

    /**
     * Skip the test on SQLite, for the reason given.
     *
     * @param  string  $reason
     * @return void
     */
    private function skipOnSqlite(string $reason): void
    {
        if ($this->driver() !== 'sqlite') {
            return;
        }

        self::markTestSkipped($reason);
    }

    /**
     * Run the shipped migration with the settings as the test has them.
     *
     * @return void
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function migrate(): void
    {
        $migration = include self::MIGRATION_PATH;

        if (!$migration instanceof Migration) {
            self::fail('Entries migration file did not return a Migration instance.');
        }

        $migration->up(); // @phpstan-ignore method.notFound
    }
}
