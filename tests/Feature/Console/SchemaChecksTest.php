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
use SineMacula\Laravel\AuditLog\Console\TableShape;
use Tests\Fixtures\Database\EntriesTableShape;
use Tests\TestCase;

/**
 * Feature tests for the schema checks of `audit-log:check`: each table a
 * shipped migration creates, the entries, the artifacts, the outbox, the
 * deliveries, the checkpoints, the checkpoint members and the integrity state,
 * has no problem, and each way a table can differ from it, one at a time, is
 * the one problem reported.
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
#[CoversClass(TableShape::class)]
final class SchemaChecksTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The table each test migrates and checks. */
    private const string TABLE = 'audit_check_entries';

    /** @var string Absolute path to the shipped entries migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000000_create_audit_log_entries_table.php';

    /** @var string Absolute path to the shipped artifacts migration file. */
    private const string ARTIFACTS_MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000600_create_audit_log_artifacts_table.php';

    /** @var string Absolute path to the shipped outbox migration file. */
    private const string OUTBOX_MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000100_create_audit_log_outbox_table.php';

    /** @var string Absolute path to the shipped deliveries migration file. */
    private const string DELIVERIES_MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000200_create_audit_log_deliveries_table.php';

    /** @var string Absolute path to the shipped checkpoints migration file. */
    private const string CHECKPOINTS_MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000300_create_audit_log_checkpoints_table.php';

    /** @var string Absolute path to the shipped checkpoint members migration file. */
    private const string MEMBERS_MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000400_create_audit_log_checkpoint_members_table.php';

    /** @var string Absolute path to the shipped integrity state migration file. */
    private const string STATE_MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000500_create_audit_log_integrity_state_table.php';

    /** @var string The artifacts table a test migrates and checks. */
    private const string ARTIFACTS = 'audit_check_artifacts';

    /** @var string The checkpoints table a test migrates and checks. */
    private const string CHECKPOINTS = 'audit_check_checkpoints';

    /** @var string The checkpoint members table a test migrates and checks. */
    private const string MEMBERS = 'audit_check_members';

    /** @var string The integrity state table a test migrates and checks. */
    private const string STATE = 'audit_check_state';

    /** @var string The outbox table a test migrates and checks. */
    private const string OUTBOX = 'audit_check_outbox';

    /** @var string The deliveries table a test migrates and checks. */
    private const string DELIVERIES = 'audit_check_deliveries';

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

    /** @var array<string, array<string, array{0: string, 1: string, 2: ?string}>> The type name, full type and collation MySQL and PostgreSQL report for each outbox column, by name. */
    private const array OUTBOX_REPORTED = [
        'mysql' => [
            'id'               => ['char', 'char(36)', 'utf8mb4_0900_bin'],
            'payload'          => ['longtext', 'longtext', 'utf8mb4_0900_bin'],
            'attempts'         => ['int', 'int', null],
            'available_at'     => ['datetime', 'datetime(6)', null],
            'claimed_until'    => ['datetime', 'datetime(6)', null],
            'claimed_by'       => ['varchar', 'varchar(64)', 'utf8mb4_0900_bin'],
            'failed_at'        => ['datetime', 'datetime(6)', null],
            'last_error_class' => ['varchar', 'varchar(191)', 'utf8mb4_0900_bin'],
            'created_at'       => ['datetime', 'datetime(6)', null],
        ],
        'pgsql' => [
            'id'               => ['uuid', 'uuid', null],
            'payload'          => ['text', 'text', null],
            'attempts'         => ['int4', 'integer', null],
            'available_at'     => ['timestamp', 'timestamp(6) without time zone', null],
            'claimed_until'    => ['timestamp', 'timestamp(6) without time zone', null],
            'claimed_by'       => ['varchar', 'character varying(64)', null],
            'failed_at'        => ['timestamp', 'timestamp(6) without time zone', null],
            'last_error_class' => ['varchar', 'character varying(191)', null],
            'created_at'       => ['timestamp', 'timestamp(6) without time zone', null],
        ],
    ];

    /** @var array<string, array<string, array{0: string, 1: string, 2: ?string}>> The type name, full type and collation MySQL and PostgreSQL report for each artifacts column, by name. */
    private const array ARTIFACTS_REPORTED = [
        'mysql' => [
            'id'           => ['char', 'char(36)', 'utf8mb4_0900_bin'],
            'entry_id'     => ['char', 'char(36)', 'utf8mb4_0900_bin'],
            'kind'         => ['varchar', 'varchar(16)', 'utf8mb4_0900_bin'],
            'member_count' => ['int', 'int unsigned', null],
            'digest'       => ['varchar', 'varchar(64)', 'utf8mb4_0900_bin'],
            'members'      => ['longtext', 'longtext', 'utf8mb4_0900_bin'],
            'created_at'   => ['datetime', 'datetime(6)', null],
        ],
        'pgsql' => [
            'id'           => ['uuid', 'uuid', null],
            'entry_id'     => ['uuid', 'uuid', null],
            'kind'         => ['varchar', 'character varying(16)', null],
            'member_count' => ['int4', 'integer', null],
            'digest'       => ['varchar', 'character varying(64)', null],
            'members'      => ['text', 'text', null],
            'created_at'   => ['timestamp', 'timestamp(6) without time zone', null],
        ],
    ];

    /** @var array<string, array<string, array{0: string, 1: string, 2: ?string}>> The type name, full type and collation MySQL and PostgreSQL report for each checkpoints column, by name. */
    private const array CHECKPOINTS_REPORTED = [
        'mysql' => [
            'id'                 => ['char', 'char(36)', 'utf8mb4_0900_bin'],
            'sequence'           => ['bigint', 'bigint', null],
            'log_id'             => ['varchar', 'varchar(64)', 'utf8mb4_0900_bin'],
            'previous_id'        => ['char', 'char(36)', 'utf8mb4_0900_bin'],
            'previous_digest'    => ['varchar', 'varchar(64)', 'utf8mb4_0900_bin'],
            'member_count'       => ['int', 'int', null],
            'members_digest'     => ['varchar', 'varchar(64)', 'utf8mb4_0900_bin'],
            'seal_digest'        => ['varchar', 'varchar(64)', 'utf8mb4_0900_bin'],
            'first_recorded_at'  => ['datetime', 'datetime(6)', null],
            'last_recorded_at'   => ['datetime', 'datetime(6)', null],
            'sealed_at'          => ['datetime', 'datetime(6)', null],
            'signer'             => ['varchar', 'varchar(16)', 'utf8mb4_0900_bin'],
            'key_id'             => ['varchar', 'varchar(32)', 'utf8mb4_0900_bin'],
            'algorithm_version'  => ['smallint', 'smallint', null],
            'signature'          => ['varchar', 'varchar(64)', 'utf8mb4_0900_bin'],
            'anchor'             => ['varchar', 'varchar(64)', 'utf8mb4_0900_bin'],
            'anchor_receipt'     => ['json', 'json', null],
            'anchored_at'        => ['datetime', 'datetime(6)', null],
            'anchor_error_class' => ['varchar', 'varchar(191)', 'utf8mb4_0900_bin'],
        ],
        'pgsql' => [
            'id'                 => ['uuid', 'uuid', null],
            'sequence'           => ['int8', 'bigint', null],
            'log_id'             => ['varchar', 'character varying(64)', null],
            'previous_id'        => ['uuid', 'uuid', null],
            'previous_digest'    => ['varchar', 'character varying(64)', null],
            'member_count'       => ['int4', 'integer', null],
            'members_digest'     => ['varchar', 'character varying(64)', null],
            'seal_digest'        => ['varchar', 'character varying(64)', null],
            'first_recorded_at'  => ['timestamp', 'timestamp(6) without time zone', null],
            'last_recorded_at'   => ['timestamp', 'timestamp(6) without time zone', null],
            'sealed_at'          => ['timestamp', 'timestamp(6) without time zone', null],
            'signer'             => ['varchar', 'character varying(16)', null],
            'key_id'             => ['varchar', 'character varying(32)', null],
            'algorithm_version'  => ['int2', 'smallint', null],
            'signature'          => ['varchar', 'character varying(64)', null],
            'anchor'             => ['varchar', 'character varying(64)', null],
            'anchor_receipt'     => ['json', 'json', null],
            'anchored_at'        => ['timestamp', 'timestamp(6) without time zone', null],
            'anchor_error_class' => ['varchar', 'character varying(191)', null],
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
        Schema::connection(self::CONNECTION)->dropIfExists(self::ARTIFACTS);
        Schema::connection(self::CONNECTION)->dropIfExists(self::OUTBOX);
        Schema::connection(self::CONNECTION)->dropIfExists(self::DELIVERIES);
        Schema::connection(self::CONNECTION)->dropIfExists(self::CHECKPOINTS);
        Schema::connection(self::CONNECTION)->dropIfExists(self::MEMBERS);
        Schema::connection(self::CONNECTION)->dropIfExists(self::STATE);

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

        self::assertSame(['Index `audit_check_entries_event_index` covers (`event`); expected (`event`, `occurred_at`, `id`).'], $this->problems());
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
            $table->index(['actor_id', 'actor_type', 'occurred_at', 'id'], self::TABLE . '_actor_index');
        });

        self::assertSame([
            'Index `audit_check_entries_actor_index` covers (`actor_id`, `actor_type`, `occurred_at`, `id`); expected (`actor_type`, `actor_id`, `occurred_at`, `id`).',
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
            $table->unique(['occurred_at', 'id'], self::TABLE . '_occurred_index');
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
     * Rows of `[a driver, the column changed, its type name, its full type, its
     * collation, the problem]`: what MySQL or PostgreSQL could report for a
     * column the package writes, and how it is described.
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
     * The outbox table the shipped migration creates has no problem.
     *
     * @return void
     */
    public function testTheShippedOutboxMigrationHasNoProblems(): void
    {
        $this->migrateDeliveryTables();

        self::assertSame([], $this->problems(self::OUTBOX, self::CONNECTION, TableShape::outbox()));
    }

    /**
     * The deliveries table the shipped migration creates has no problem.
     *
     * @return void
     */
    public function testTheShippedDeliveriesMigrationHasNoProblems(): void
    {
        $this->migrateDeliveryTables();

        self::assertSame([], $this->problems(self::DELIVERIES, self::CONNECTION, TableShape::deliveries()));
    }

    /**
     * Rows of `[the table, its shape, how it is named]`: a delivery table that
     * does not exist is named by its own label.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\AuditLog\Console\TableShape, 2: string}>
     */
    public static function provideMissingDeliveryTables(): iterable
    {
        yield from [
            'the outbox'     => ['audit_absent_outbox', TableShape::outbox(), 'outbox'],
            'the deliveries' => ['audit_absent_deliveries', TableShape::deliveries(), 'deliveries'],
        ];
    }

    /**
     * A delivery table that does not exist is the one problem, naming the table
     * by its label, the connection and how to create it.
     *
     * @param  string  $table
     * @param  \SineMacula\Laravel\AuditLog\Console\TableShape  $shape
     * @param  string  $label
     * @return void
     */
    #[DataProvider('provideMissingDeliveryTables')]
    public function testAMissingDeliveryTableIsNamedByItsLabel(string $table, TableShape $shape, string $label): void
    {
        self::assertSame([
            sprintf('The %s table `%s` does not exist on connection [testing]; publish and run the migrations', $label, $table)
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
        ], $this->problems($table, self::CONNECTION, $shape));
    }

    /**
     * The index a drain claims outbox rows by is a problem when it is missing.
     *
     * @return void
     */
    public function testAMissingOutboxIndexIsAProblem(): void
    {
        $this->migrateDeliveryTables();

        Schema::connection(self::CONNECTION)->table(self::OUTBOX, static function (Blueprint $table): void {
            $table->dropIndex(self::OUTBOX . '_due_index');
        });

        self::assertSame(['Index `audit_check_outbox_due_index` is missing.'], $this->problems(self::OUTBOX, self::CONNECTION, TableShape::outbox()));
    }

    /**
     * A deliveries table keyed by the entry alone is a problem, since it would
     * keep one receipt for a record however many destinations it has.
     *
     * @return void
     */
    public function testAWrongDeliveriesKeyIsAProblem(): void
    {
        $this->migrateDeliveryTables();

        Schema::connection(self::CONNECTION)->table(self::DELIVERIES, static function (Blueprint $table): void {
            $table->dropPrimary(self::DELIVERIES . '_primary');
        });

        Schema::connection(self::CONNECTION)->table(self::DELIVERIES, static function (Blueprint $table): void {
            $table->primary(['entry_id'], self::DELIVERIES . '_primary');
        });

        self::assertSame(['The primary key must be (`entry_id`, `destination`).'], $this->problems(self::DELIVERIES, self::CONNECTION, TableShape::deliveries()));
    }

    /**
     * A deliveries table keyed by its columns in another order is a problem.
     *
     * @return void
     */
    public function testADeliveriesKeyOutOfOrderIsAProblem(): void
    {
        $this->migrateDeliveryTables();

        Schema::connection(self::CONNECTION)->table(self::DELIVERIES, static function (Blueprint $table): void {
            $table->dropPrimary(self::DELIVERIES . '_primary');
        });

        Schema::connection(self::CONNECTION)->table(self::DELIVERIES, static function (Blueprint $table): void {
            $table->primary(['destination', 'entry_id'], self::DELIVERIES . '_primary');
        });

        self::assertSame(['The primary key must be (`entry_id`, `destination`).'], $this->problems(self::DELIVERIES, self::CONNECTION, TableShape::deliveries()));
    }

    /**
     * A column of the outbox the package does not write is a problem, in the
     * outbox's own words, which say nothing of an HMAC.
     *
     * @return void
     */
    public function testAnUnknownOutboxColumnIsAProblem(): void
    {
        $this->migrateDeliveryTables();

        Schema::connection(self::CONNECTION)->table(self::OUTBOX, static function (Blueprint $table): void {
            $table->string('notes')->nullable();
        });

        self::assertSame(['Column `notes` is not one the package writes.'], $this->problems(self::OUTBOX, self::CONNECTION, TableShape::outbox()));
    }

    /**
     * A receipt column the deliveries table lacks, and one made nullable that
     * must not be, are each a problem.
     *
     * @return void
     */
    public function testADeliveriesColumnMissingOrNullableIsAProblem(): void
    {
        $this->migrateDeliveryTables();

        Schema::connection(self::CONNECTION)->table(self::DELIVERIES, static function (Blueprint $table): void {
            $table->dropColumn('delivered_at');
        });

        Schema::connection(self::CONNECTION)->table(self::DELIVERIES, static function (Blueprint $table): void {
            $table->integer('attempts')->nullable()->change();
        });

        self::assertSame(
            ['Column `attempts` is nullable; it must not be.', 'Column `delivered_at` is missing.'],
            $this->problems(self::DELIVERIES, self::CONNECTION, TableShape::deliveries()),
        );
    }

    /**
     * The entries shape is what the checks use when none is given, so the
     * outbox table checked without one is a table of the wrong shape.
     *
     * @return void
     */
    public function testTheEntriesShapeIsTheDefault(): void
    {
        $this->migrateDeliveryTables();

        self::assertSame($this->problems(self::OUTBOX, self::CONNECTION, TableShape::entries()), $this->problems(self::OUTBOX));
        self::assertContains('Column `payload` is not one the package writes, so no entry\'s HMAC covers it.', $this->problems(self::OUTBOX));
    }

    /**
     * The shipped outbox table as MySQL and PostgreSQL report it, its long text
     * and integer columns included, has no problem; this runs on any engine the
     * suite runs against.
     *
     * @param  string  $driver
     * @return void
     */
    #[DataProvider('provideSizedDrivers')]
    public function testTheShippedOutboxTableAsEachEngineReportsItHasNoProblems(string $driver): void
    {
        $this->migrateDeliveryTables();

        $this->fake($driver, self::reportedOutbox($driver), self::OUTBOX);

        self::assertSame([], $this->problems(self::OUTBOX, 'fake', TableShape::outbox()));
    }

    /**
     * Rows of `[a driver, the column changed, its type name, its full type, the
     * problem]`: what MySQL or PostgreSQL could report for an outbox column of
     * the long text or integer families, and how it is described.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: string, 4: string}>
     */
    public static function provideReportedOutboxTypes(): iterable
    {
        yield from [
            'a payload of text on MySQL'            => ['mysql', 'payload', 'text', 'text', 'Column `payload` is text; expected longtext.'],
            'a payload of json on PostgreSQL'       => ['pgsql', 'payload', 'json', 'json', 'Column `payload` is json; expected text.'],
            'attempts as a small integer on MySQL'  => ['mysql', 'attempts', 'smallint', 'smallint', 'Column `attempts` is smallint; expected int.'],
            'attempts as a big integer on Postgres' => ['pgsql', 'attempts', 'int8', 'bigint', 'Column `attempts` is int8; expected int4.'],
        ];
    }

    /**
     * Each outbox column of a new type family that MySQL or PostgreSQL could
     * report otherwise is the one problem, in the engine's own terms.
     *
     * @param  string  $driver
     * @param  string  $column
     * @param  string  $typeName
     * @param  string  $type
     * @param  string  $problem
     * @return void
     */
    #[DataProvider('provideReportedOutboxTypes')]
    public function testEachEngineReportsAnOutboxColumnInItsOwnTerms(string $driver, string $column, string $typeName, string $type, string $problem): void
    {
        $this->migrateDeliveryTables();

        $columns = array_map(static fn (array $reported): array => $reported['name'] === $column
            ? [...$reported, 'type_name' => $typeName, 'type' => $type]
            : $reported, self::reportedOutbox($driver));

        $this->fake($driver, $columns, self::OUTBOX);

        self::assertSame([$problem], $this->problems(self::OUTBOX, 'fake', TableShape::outbox()));
    }

    /**
     * The index sealing pages the entries by is a problem when it is missing.
     *
     * @return void
     */
    public function testAMissingRecordedIndexIsAProblem(): void
    {
        $this->alter(static function (Blueprint $table): void {
            $table->dropIndex(self::TABLE . '_recorded_index');
        });

        self::assertSame(['Index `audit_check_entries_recorded_index` is missing.'], $this->problems());
    }

    /**
     * An index under the recorded index's name over the time alone is a
     * problem, since entries recorded in the same microsecond would have no
     * order to page by.
     *
     * @return void
     */
    public function testARecordedIndexWithoutTheIdIsAProblem(): void
    {
        $this->replaceIndex(self::TABLE . '_recorded_index', static function (Blueprint $table): void {
            $table->index(['recorded_at'], self::TABLE . '_recorded_index');
        });

        self::assertSame(['Index `audit_check_entries_recorded_index` covers (`recorded_at`); expected (`recorded_at`, `id`).'], $this->problems());
    }

    /**
     * Rows of `[an index's suffix, the columns an install migrated before each
     * lookup ended in the id gave it]`: the seven lookups of the trail.
     *
     * @return iterable<string, array{0: string, 1: non-empty-list<string>}>
     */
    public static function provideIndexesWithoutTheirId(): iterable
    {
        yield from [
            'the actor'     => ['_actor_index', ['actor_type', 'actor_id', 'occurred_at']],
            'the subject'   => ['_subject_index', ['subject_type', 'subject_id', 'occurred_at']],
            'the principal' => ['_principal_index', ['principal_type', 'principal_id', 'occurred_at']],
            'the tenant'    => ['_tenant_index', ['tenant_type', 'tenant_id', 'occurred_at']],
            'the event'     => ['_event_index', ['event', 'occurred_at']],
            'the category'  => ['_category_index', ['category', 'occurred_at']],
            'the time'      => ['_occurred_index', ['occurred_at']],
        ];
    }

    /**
     * A lookup index of the trail that does not end in the id is a problem,
     * naming both column lists, since a keyset page could not read it in order
     * and the engine would sort every match.
     *
     * @param  string  $suffix
     * @param  non-empty-list<string>  $columns
     * @return void
     */
    #[DataProvider('provideIndexesWithoutTheirId')]
    public function testAnIndexWithoutItsIdIsReported(string $suffix, array $columns): void
    {
        $this->replaceIndex(self::TABLE . $suffix, static function (Blueprint $table) use ($suffix, $columns): void {
            $table->index($columns, self::TABLE . $suffix);
        });

        $listed = static fn (array $names): string => implode(', ', array_map(static fn (string $name): string => '`' . $name . '`', $names));

        self::assertSame([
            sprintf('Index `%s%s` covers (%s); expected (%s).', self::TABLE, $suffix, $listed($columns), $listed([...$columns, 'id'])),
        ], $this->problems());
    }

    /**
     * An install migrated with every lookup index of the trail as it was before
     * each ended in the id is reported once for each of the seven, in the
     * migration's order, and for nothing else: the correlation, recorded and
     * source indexes are unchanged.
     *
     * @return void
     */
    public function testAnInstallWithTheOldIndexesReportsEachOfThem(): void
    {
        $old = iterator_to_array(self::provideIndexesWithoutTheirId(), false);

        $this->alter(static function (Blueprint $table) use ($old): void {
            foreach ($old as [$suffix]) {
                $table->dropIndex(self::TABLE . $suffix);
            }
        });

        $this->alter(static function (Blueprint $table) use ($old): void {
            foreach ($old as [$suffix, $columns]) {
                $table->index($columns, self::TABLE . $suffix);
            }
        });

        self::assertSame([
            'Index `audit_check_entries_actor_index` covers (`actor_type`, `actor_id`, `occurred_at`); expected (`actor_type`, `actor_id`, `occurred_at`, `id`).',
            'Index `audit_check_entries_subject_index` covers (`subject_type`, `subject_id`, `occurred_at`); expected (`subject_type`, `subject_id`, `occurred_at`, `id`).',
            'Index `audit_check_entries_principal_index` covers (`principal_type`, `principal_id`, `occurred_at`);'
                . ' expected (`principal_type`, `principal_id`, `occurred_at`, `id`).',
            'Index `audit_check_entries_tenant_index` covers (`tenant_type`, `tenant_id`, `occurred_at`); expected (`tenant_type`, `tenant_id`, `occurred_at`, `id`).',
            'Index `audit_check_entries_event_index` covers (`event`, `occurred_at`); expected (`event`, `occurred_at`, `id`).',
            'Index `audit_check_entries_category_index` covers (`category`, `occurred_at`); expected (`category`, `occurred_at`, `id`).',
            'Index `audit_check_entries_occurred_index` covers (`occurred_at`); expected (`occurred_at`, `id`).',
        ], $this->problems());
    }

    /**
     * The artifacts table the shipped migration creates has no problem.
     *
     * @return void
     */
    public function testTheShippedArtifactsMigrationHasNoProblems(): void
    {
        $this->migrateArtifactsTable();

        self::assertSame([], $this->problems(self::ARTIFACTS, self::CONNECTION, TableShape::artifacts()));
    }

    /**
     * Rows of `[the column dropped]`: each column of the artifacts table.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideArtifactsColumns(): iterable
    {
        foreach (['entry_id', 'kind', 'member_count', 'digest', 'members', 'created_at'] as $column) {
            yield $column => [$column];
        }
    }

    /**
     * An artifacts table without a column the package writes is a problem,
     * naming the column.
     *
     * @param  string  $column
     * @return void
     */
    #[DataProvider('provideArtifactsColumns')]
    public function testAMissingArtifactsColumnIsAProblem(string $column): void
    {
        $this->migrateArtifactsTable();

        if ($column === 'entry_id') {
            Schema::connection(self::CONNECTION)->table(self::ARTIFACTS, static function (Blueprint $table): void {
                $table->dropUnique(self::ARTIFACTS . '_entry_unique');
            });
        }

        Schema::connection(self::CONNECTION)->table(self::ARTIFACTS, static function (Blueprint $table) use ($column): void {
            $table->dropColumn($column);
        });

        $missing = [sprintf('Column `%s` is missing.', $column)];

        self::assertSame(
            $column === 'entry_id' ? [...$missing, 'Index `audit_check_artifacts_entry_unique` is missing.'] : $missing,
            $this->problems(self::ARTIFACTS, self::CONNECTION, TableShape::artifacts()),
        );
    }

    /**
     * A missing artifacts table is the one problem, naming the table by its
     * label, the connection and how to create it.
     *
     * @return void
     */
    public function testAMissingArtifactsTableIsNamedByItsLabel(): void
    {
        self::assertSame([
            'The artifacts table `audit_absent_artifacts` does not exist on connection [testing]; publish and run the migrations'
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
        ], $this->problems('audit_absent_artifacts', self::CONNECTION, TableShape::artifacts()));
    }

    /**
     * An artifacts table whose entry index is not unique is a problem, since an
     * entry could then have two artifacts.
     *
     * @return void
     */
    public function testAnArtifactsTableWithoutItsUniqueEntryIsAProblem(): void
    {
        $this->migrateArtifactsTable();

        Schema::connection(self::CONNECTION)->table(self::ARTIFACTS, static function (Blueprint $table): void {
            $table->dropUnique(self::ARTIFACTS . '_entry_unique');
        });

        Schema::connection(self::CONNECTION)->table(self::ARTIFACTS, static function (Blueprint $table): void {
            $table->index(['entry_id'], self::ARTIFACTS . '_entry_unique');
        });

        self::assertSame(['Index `audit_check_artifacts_entry_unique` must be unique.'], $this->problems(self::ARTIFACTS, self::CONNECTION, TableShape::artifacts()));
    }

    /**
     * Nullable members and a column the package does not write are each a
     * problem, the latter in the artifacts' own words.
     *
     * @return void
     */
    public function testNullableMembersAndAnUnknownArtifactsColumnAreProblems(): void
    {
        $this->migrateArtifactsTable();

        Schema::connection(self::CONNECTION)->table(self::ARTIFACTS, static function (Blueprint $table): void {
            $table->longText('members')->nullable()->change();
            $table->string('notes')->nullable();
        });

        self::assertSame([
            'Column `members` is nullable; it must not be.',
            'Column `notes` is not one the package writes.',
        ], $this->problems(self::ARTIFACTS, self::CONNECTION, TableShape::artifacts()));
    }

    /**
     * The shipped artifacts table as MySQL and PostgreSQL report it, its
     * unsigned count and its long encrypted members included, has no problem;
     * this runs on any engine the suite runs against.
     *
     * @param  string  $driver
     * @return void
     */
    #[DataProvider('provideSizedDrivers')]
    public function testTheShippedArtifactsTableAsEachEngineReportsItHasNoProblems(string $driver): void
    {
        $this->migrateArtifactsTable();

        $columns = [];

        foreach (Schema::connection(self::CONNECTION)->getColumns(self::ARTIFACTS) as $column) {

            [$typeName, $type, $collation] = self::ARTIFACTS_REPORTED[$driver][$column['name']];

            $columns[] = ['name' => $column['name'], 'type' => $type, 'type_name' => $typeName, 'collation' => $collation, 'nullable' => $column['nullable']];
        }

        $this->fake($driver, $columns, self::ARTIFACTS);

        self::assertSame([], $this->problems(self::ARTIFACTS, 'fake', TableShape::artifacts()));
    }

    /**
     * Members MySQL reports as `text`, which holds 64 KiB and no more, are a
     * problem, in the engine's own terms.
     *
     * @return void
     */
    public function testMembersThatAreNotLongTextOnMySqlAreAProblem(): void
    {
        $this->migrateArtifactsTable();

        $columns = [];

        foreach (Schema::connection(self::CONNECTION)->getColumns(self::ARTIFACTS) as $column) {

            [$typeName, $type, $collation] = $column['name'] === 'members' ? ['text', 'text', 'utf8mb4_0900_bin'] : self::ARTIFACTS_REPORTED['mysql'][$column['name']];

            $columns[] = ['name' => $column['name'], 'type' => $type, 'type_name' => $typeName, 'collation' => $collation, 'nullable' => $column['nullable']];
        }

        $this->fake('mysql', $columns, self::ARTIFACTS);

        self::assertSame(['Column `members` is text; expected longtext.'], $this->problems(self::ARTIFACTS, 'fake', TableShape::artifacts()));
    }

    /**
     * The checkpoints table the shipped migration creates has no problem.
     *
     * @return void
     */
    public function testTheShippedCheckpointsMigrationHasNoProblems(): void
    {
        $this->migrateIntegrityTables();

        self::assertSame([], $this->problems(self::CHECKPOINTS, self::CONNECTION, TableShape::checkpoints()));
    }

    /**
     * The checkpoint members table the shipped migration creates has no
     * problem.
     *
     * @return void
     */
    public function testTheShippedMembersMigrationHasNoProblems(): void
    {
        $this->migrateIntegrityTables();

        self::assertSame([], $this->problems(self::MEMBERS, self::CONNECTION, TableShape::members()));
    }

    /**
     * The integrity state table the shipped migration creates has no problem.
     *
     * @return void
     */
    public function testTheShippedStateMigrationHasNoProblems(): void
    {
        $this->migrateIntegrityTables();

        self::assertSame([], $this->problems(self::STATE, self::CONNECTION, TableShape::state()));
    }

    /**
     * Rows of `[the table, its shape, how it is named]`: an integrity table
     * that does not exist is named by its own label.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\AuditLog\Console\TableShape, 2: string}>
     */
    public static function provideMissingIntegrityTables(): iterable
    {
        yield from [
            'the checkpoints'        => ['audit_absent_checkpoints', TableShape::checkpoints(), 'checkpoints'],
            'the checkpoint members' => ['audit_absent_members', TableShape::members(), 'checkpoint members'],
            'the integrity state'    => ['audit_absent_state', TableShape::state(), 'integrity state'],
        ];
    }

    /**
     * An integrity table that does not exist is the one problem, naming the
     * table by its label, the connection and how to create it.
     *
     * @param  string  $table
     * @param  \SineMacula\Laravel\AuditLog\Console\TableShape  $shape
     * @param  string  $label
     * @return void
     */
    #[DataProvider('provideMissingIntegrityTables')]
    public function testAMissingIntegrityTableIsNamedByItsLabel(string $table, TableShape $shape, string $label): void
    {
        self::assertSame([
            sprintf('The %s table `%s` does not exist on connection [testing]; publish and run the migrations', $label, $table)
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
        ], $this->problems($table, self::CONNECTION, $shape));
    }

    /**
     * A members table whose entry index is not unique is a problem, since an
     * entry could then be held by two seals.
     *
     * @return void
     */
    public function testAMembersTableWithoutItsUniqueEntryIsAProblem(): void
    {
        $this->migrateIntegrityTables();

        Schema::connection(self::CONNECTION)->table(self::MEMBERS, static function (Blueprint $table): void {
            $table->dropUnique(self::MEMBERS . '_entry_unique');
        });

        Schema::connection(self::CONNECTION)->table(self::MEMBERS, static function (Blueprint $table): void {
            $table->index(['entry_id'], self::MEMBERS . '_entry_unique');
        });

        self::assertSame(['Index `audit_check_members_entry_unique` must be unique.'], $this->problems(self::MEMBERS, self::CONNECTION, TableShape::members()));
    }

    /**
     * A members table keyed by the entry alone is a problem, in the order the
     * key must take.
     *
     * @return void
     */
    public function testAMembersTableKeyedOtherwiseIsAProblem(): void
    {
        $this->migrateIntegrityTables();

        Schema::connection(self::CONNECTION)->table(self::MEMBERS, static function (Blueprint $table): void {
            $table->dropPrimary(self::MEMBERS . '_primary');
        });

        Schema::connection(self::CONNECTION)->table(self::MEMBERS, static function (Blueprint $table): void {
            $table->primary(['entry_id', 'checkpoint_id'], self::MEMBERS . '_primary');
        });

        self::assertSame(['The primary key must be (`checkpoint_id`, `entry_id`).'], $this->problems(self::MEMBERS, self::CONNECTION, TableShape::members()));
    }

    /**
     * A checkpoints table without its unique sequence is a problem, since two
     * sealers could then both extend the head.
     *
     * @return void
     */
    public function testACheckpointsTableWithoutItsUniqueSequenceIsAProblem(): void
    {
        $this->migrateIntegrityTables();

        Schema::connection(self::CONNECTION)->table(self::CHECKPOINTS, static function (Blueprint $table): void {
            $table->dropUnique(self::CHECKPOINTS . '_sequence_unique');
        });

        self::assertSame(['Index `audit_check_checkpoints_sequence_unique` is missing.'], $this->problems(self::CHECKPOINTS, self::CONNECTION, TableShape::checkpoints()));
    }

    /**
     * A column of the checkpoints table the package does not write is a
     * problem, in the seals' own words.
     *
     * @return void
     */
    public function testAnUnknownCheckpointsColumnIsAProblem(): void
    {
        $this->migrateIntegrityTables();

        Schema::connection(self::CONNECTION)->table(self::CHECKPOINTS, static function (Blueprint $table): void {
            $table->string('notes')->nullable();
        });

        self::assertSame(['Column `notes` is not one the package writes, so no seal covers it.'], $this->problems(self::CHECKPOINTS, self::CONNECTION, TableShape::checkpoints()));
    }

    /**
     * A state value that is not text is a problem, in the engine's own terms.
     *
     * @return void
     */
    public function testAStateValueThatIsNotTextIsAProblem(): void
    {
        $this->migrateIntegrityTables();

        Schema::connection(self::CONNECTION)->table(self::STATE, static function (Blueprint $table): void {
            $table->string('value', 100)->change();
        });

        $type = $this->driver() === 'sqlite' ? 'varchar' : 'varchar(100)';

        self::assertSame(["Column `value` is {$type}; expected text."], $this->problems(self::STATE, self::CONNECTION, TableShape::state()));
    }

    /**
     * The shipped checkpoints table as MySQL and PostgreSQL report it, its big
     * integer sequence and its receipt included, has no problem; this runs on
     * any engine the suite runs against.
     *
     * @param  string  $driver
     * @return void
     */
    #[DataProvider('provideSizedDrivers')]
    public function testTheShippedCheckpointsTableAsEachEngineReportsItHasNoProblems(string $driver): void
    {
        $this->migrateIntegrityTables();

        $this->fake($driver, self::reportedCheckpoints($driver), self::CHECKPOINTS);

        self::assertSame([], $this->problems(self::CHECKPOINTS, 'fake', TableShape::checkpoints()));
    }

    /**
     * Rows of `[a driver, the column changed, its type name, its full type, the
     * problem]`: what MySQL or PostgreSQL could report for a checkpoints column
     * of the big integer family or a digest, and how it is described.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: string, 4: string}>
     */
    public static function provideReportedCheckpointsTypes(): iterable
    {
        yield from [
            'a sequence as an integer on MySQL'      => ['mysql', 'sequence', 'int', 'int', 'Column `sequence` is int; expected bigint.'],
            'a sequence as an integer on PostgreSQL' => ['pgsql', 'sequence', 'int4', 'integer', 'Column `sequence` is int4; expected int8.'],
            'a longer digest on MySQL'               => ['mysql', 'seal_digest', 'varchar', 'varchar(128)', 'Column `seal_digest` is varchar(128); expected varchar(64).'],
            'a receipt as jsonb on PostgreSQL'       => ['pgsql', 'anchor_receipt', 'jsonb', 'jsonb', 'Column `anchor_receipt` is jsonb; expected json.'],
        ];
    }

    /**
     * Each checkpoints column MySQL or PostgreSQL could report otherwise is the
     * one problem, in the engine's own terms.
     *
     * @param  string  $driver
     * @param  string  $column
     * @param  string  $typeName
     * @param  string  $type
     * @param  string  $problem
     * @return void
     */
    #[DataProvider('provideReportedCheckpointsTypes')]
    public function testEachEngineReportsACheckpointsColumnInItsOwnTerms(string $driver, string $column, string $typeName, string $type, string $problem): void
    {
        $this->migrateIntegrityTables();

        $columns = array_map(static fn (array $reported): array => $reported['name'] === $column
            ? [...$reported, 'type_name' => $typeName, 'type' => $type]
            : $reported, self::reportedCheckpoints($driver));

        $this->fake($driver, $columns, self::CHECKPOINTS);

        self::assertSame([$problem], $this->problems(self::CHECKPOINTS, 'fake', TableShape::checkpoints()));
    }

    /**
     * The problems the checks find on the connection's table, against the shape
     * given or, when none is, the entries table's.
     *
     * @param  string  $table
     * @param  string  $connection
     * @param  ?\SineMacula\Laravel\AuditLog\Console\TableShape  $shape
     * @return list<string>
     */
    private function problems(string $table = self::TABLE, string $connection = self::CONNECTION, ?TableShape $shape = null): array
    {
        $database = $this->app?->make(DatabaseManager::class);

        assert($database instanceof DatabaseManager);

        return (new SchemaChecks($database))->problems($connection, $table, $shape);
    }

    /**
     * The shipped outbox table's columns as the driver reports them: their
     * names and nullability as the test's engine created them, their types and
     * MySQL's collation as the driver would report them.
     *
     * @param  string  $driver
     * @return list<array{name: string, type: string, type_name: string, collation: ?string, nullable: bool}>
     */
    private static function reportedOutbox(string $driver): array
    {
        $columns = [];

        foreach (Schema::connection(self::CONNECTION)->getColumns(self::OUTBOX) as $column) {

            [$typeName, $type, $collation] = self::OUTBOX_REPORTED[$driver][$column['name']];

            $columns[] = ['name' => $column['name'], 'type' => $type, 'type_name' => $typeName, 'collation' => $collation, 'nullable' => $column['nullable']];
        }

        return $columns;
    }

    /**
     * The shipped checkpoints table's columns as the driver reports them: their
     * names and nullability as the test's engine created them, their types and
     * MySQL's collation as the driver would report them.
     *
     * @param  string  $driver
     * @return list<array{name: string, type: string, type_name: string, collation: ?string, nullable: bool}>
     */
    private static function reportedCheckpoints(string $driver): array
    {
        $columns = [];

        foreach (Schema::connection(self::CONNECTION)->getColumns(self::CHECKPOINTS) as $column) {

            [$typeName, $type, $collation] = self::CHECKPOINTS_REPORTED[$driver][$column['name']];

            $columns[] = ['name' => $column['name'], 'type' => $type, 'type_name' => $typeName, 'collation' => $collation, 'nullable' => $column['nullable']];
        }

        return $columns;
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
     * table, the columns given and the indexes of the table the test migrated
     * under the name given, with no server behind it.
     *
     * @param  string  $driver
     * @param  list<array{name: string, type: string, type_name: string, collation: ?string, nullable: bool}>  $columns
     * @param  string  $table
     * @return void
     */
    private function fake(string $driver, array $columns, string $table = self::TABLE): void
    {
        $indexes = Schema::connection(self::CONNECTION)->getIndexes($table);

        $schema = \Mockery::mock(SQLiteBuilder::class);

        $schema->shouldReceive('hasTable')->andReturnTrue();
        $schema->shouldReceive('getColumns')->andReturn($columns);
        $schema->shouldReceive('getIndexes')->andReturn($indexes);

        $connection = \Mockery::mock(SQLiteConnection::class . '[getSchemaBuilder]', [new \PDO('sqlite::memory:'), '', '', ['driver' => $driver, 'name' => 'fake']]);

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
     * Run the shipped outbox and deliveries migrations under the tables' names
     * of this test, on the test's connection.
     *
     * @return void
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function migrateDeliveryTables(): void
    {
        app(ConfigRepository::class)->set([
            'audit-log.delivery.outbox.table'     => self::OUTBOX,
            'audit-log.delivery.deliveries_table' => self::DELIVERIES,
        ]);

        foreach ([self::OUTBOX_MIGRATION_PATH, self::DELIVERIES_MIGRATION_PATH] as $path) {

            $migration = include $path;

            if (!$migration instanceof Migration) {
                self::fail('A delivery migration file did not return a Migration instance.');
            }

            $migration->up(); // @phpstan-ignore method.notFound
        }
    }

    /**
     * Run the shipped artifacts migration under the table's name of this test,
     * on the test's connection.
     *
     * @return void
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function migrateArtifactsTable(): void
    {
        app(ConfigRepository::class)->set('audit-log.entries.artifacts_table', self::ARTIFACTS);

        $migration = include self::ARTIFACTS_MIGRATION_PATH;

        if (!$migration instanceof Migration) {
            self::fail('The artifacts migration file did not return a Migration instance.');
        }

        $migration->up(); // @phpstan-ignore method.notFound
    }

    /**
     * Run the shipped checkpoints, checkpoint members and integrity state
     * migrations under the tables' names of this test, on the test's
     * connection.
     *
     * @return void
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function migrateIntegrityTables(): void
    {
        app(ConfigRepository::class)->set([
            'audit-log.integrity.checkpoints_table' => self::CHECKPOINTS,
            'audit-log.integrity.members_table'     => self::MEMBERS,
            'audit-log.integrity.state_table'       => self::STATE,
        ]);

        foreach ([self::CHECKPOINTS_MIGRATION_PATH, self::MEMBERS_MIGRATION_PATH, self::STATE_MIGRATION_PATH] as $path) {

            $migration = include $path;

            if (!$migration instanceof Migration) {
                self::fail('An integrity migration file did not return a Migration instance.');
            }

            $migration->up(); // @phpstan-ignore method.notFound
        }
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
