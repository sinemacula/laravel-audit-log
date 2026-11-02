<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\MySqlConnection;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\MySqlBuilder;
use Illuminate\Database\SQLiteDatabaseDoesNotExistException;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use Tests\Fixtures\Database\VersionReportingPdo;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:check`: it reads the settings, the connections
 * and guards they name, the entries table and the integrity keys, lists every
 * problem it finds as `[<subject>] <message>` and every subject without one as
 * `[<subject>] OK`, exits `1` when there is a problem and `0` when there is
 * none, covers every leaf of the shipped configuration, and prints no secret,
 * setting's value, statement or binding.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckCommand::class)]
final class CheckCommandTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var list<string> What a run prints when nothing has a problem. */
    private const array EVERY_SUBJECT_OK = ['[config] OK', '[connections] OK', '[schema] OK', '[integrity] OK'];

    /** @var string Absolute path to the shipped entries migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000000_create_audit_log_entries_table.php';

    /** @var string The table a test migrates under a name of its own. */
    private const string CUSTOM_TABLE = 'audit_custom_entries';

    /** @var string A secret one byte short of the 32 an integrity key needs. */
    private const string SHORT_SECRET = 'a-secret-one-byte-short-of-32!!';

    /** @var string The configured table no test migrates. */
    private const string ABSENT_TABLE = 'audit_absent_entries';

    /** @var array<string, int|string> A value the check refuses for each leaf of the package's configuration, by its path under `audit-log`. */
    private const array BAD_LEAVES = [
        'storage.connection'             => 123,
        'storage.maintenance_connection' => 123,
        'entries.table'                  => 'audit-log',
        'integrity.keys'                 => 'x',
        'integrity.current'              => 'k1',
        'actor.guards'                   => 'web',
        'context.trust_request_id'       => 'yes',
        'context.request_id_header'      => 'X Request',
        'context.trust_traceparent'      => 'yes',
        'definitions.require_registered' => '1',
        'source.id'                      => 42,
        'source.region'                  => 42,
    ];

    /** @var string What a test's bad value carries, and the output must never hold. */
    private const string SENTINEL = 'sentinel-7f3a9c';

    /** @var string The message of a malformed list of guards. */
    private const string MALFORMED_GUARDS = '[config] `audit-log.actor.guards` must be null, or a list of guard names of 1 to 64 characters.';

    /** @var string The message of a malformed source id. */
    private const string MALFORMED_SOURCE_ID = '[config] `audit-log.source.id` must be from 1 to 64 characters, with no control characters.';

    /** @var string The message of a malformed source region. */
    private const string MALFORMED_SOURCE_REGION = '[config] `audit-log.source.region` must be null or empty, or from 1 to 32 characters, with no control characters.';

    /** @var string The message of a malformed header name. */
    private const string MALFORMED_HEADER = '[config] `audit-log.context.request_id_header` must be a header name of 1 to 64 characters.';

    /** @var string The message of a malformed flag trusting a request id. */
    private const string MALFORMED_TRUST_REQUEST_ID = '[config] `audit-log.context.trust_request_id` must be true or false.';

    /** @var string The message of a malformed flag trusting a `traceparent`. */
    private const string MALFORMED_TRUST_TRACEPARENT = '[config] `audit-log.context.trust_traceparent` must be true or false.';

    /** @var string The message of a malformed flag requiring a registered definition. */
    private const string MALFORMED_REQUIRE_REGISTERED = '[config] `audit-log.definitions.require_registered` must be true or false.';

    /** @var list<string> Files a test created, removed when it ends. */
    private array $files = [];

    /**
     * Register the command with the console kernel, which keeps the tests
     * independent of the provider, whose registration
     * `AuditLogServiceProviderTest::testTheCheckCommandIsRegistered` pins.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new CheckCommand);
    }

    /**
     * Drop the table a test migrated under a name of its own and remove the
     * files it created.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if (app(ConfigRepository::class)->has('database.connections.custom')) {
            Schema::connection('custom')->dropIfExists(self::CUSTOM_TABLE);
        }

        foreach ($this->files as $file) {

            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        parent::tearDown();
    }

    /**
     * An install the shipped migration created, with the derived integrity key,
     * passes, saying so for each subject in order.
     *
     * @return void
     */
    public function testAGoodInstallPasses(): void
    {
        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame(self::EVERY_SUBJECT_OK, $output);
    }

    /**
     * A table of another name on a connection of its own, with a table prefix
     * and an explicit key ring, passes once the migration has run there.
     *
     * @return void
     */
    public function testACustomTableAndConnectionPass(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.custom', [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'app_']);
        $config->set('audit-log.storage.connection', 'custom');
        $config->set('audit-log.storage.maintenance_connection', 'custom');
        $config->set('audit-log.entries.table', self::CUSTOM_TABLE);
        $config->set('audit-log.integrity.keys', ['k1' => 'base64:' . base64_encode(str_repeat('k', 32))]);
        $config->set('audit-log.integrity.current', 'k1');

        $this->migrate();

        [$code, $output] = $this->check();

        self::assertTrue(Schema::connection('custom')->hasTable(self::CUSTOM_TABLE));
        self::assertSame(0, $code);
        self::assertSame(self::EVERY_SUBJECT_OK, $output);
    }

    /**
     * Rows of `[the settings changed, the one problem the change causes]`, one
     * for each setting and each way of getting it wrong a run reports.
     *
     * @return iterable<string, array{0: array<string, array<array-key, int|string>|int|string|null>, 1: string}>
     */
    public static function provideBadSettings(): iterable
    {
        $driver = getenv('DB_CONNECTION') ?: 'sqlite';
        $other  = $driver === 'sqlite' ? 'pgsql' : 'sqlite';

        yield from [
            'a storage connection that is not a name' => [
                ['audit-log.storage.connection' => 123],
                '[config] `audit-log.storage.connection` must be a connection name, or null or empty for the default connection.',
            ],
            'a storage connection that is not a name beside a maintenance connection' => [
                ['audit-log.storage.connection' => 123, 'audit-log.storage.maintenance_connection' => 'testing'],
                '[config] `audit-log.storage.connection` must be a connection name, or null or empty for the default connection.',
            ],
            'a storage connection that is not configured' => [
                ['audit-log.storage.connection' => 'missing'],
                '[connections] The connection [missing] that `audit-log.storage.connection` names is not configured in `database.connections`.',
            ],
            'a maintenance connection that is not a name' => [
                ['audit-log.storage.maintenance_connection' => []],
                '[config] `audit-log.storage.maintenance_connection` must be a connection name, or null or empty for the storage connection.',
            ],
            'a maintenance connection that is not configured' => [
                ['audit-log.storage.maintenance_connection' => 'missing'],
                '[connections] The connection [missing] that `audit-log.storage.maintenance_connection` names is not configured in `database.connections`.',
            ],
            'a maintenance connection on another driver' => [
                ['database.connections.other' => ['driver' => $other, 'database' => 'elsewhere'], 'audit-log.storage.maintenance_connection' => 'other'],
                "[connections] The maintenance connection [other] uses the {$other} driver and the storage connection [testing] the {$driver} driver;"
                    . ' both must reach the same database.',
            ],
            'a table name of 48 characters' => [
                ['audit-log.entries.table' => str_repeat('a', 48)],
                '[config] `audit-log.entries.table` must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.',
            ],
            'a table name with a hyphen' => [
                ['audit-log.entries.table' => 'audit-log'],
                '[config] `audit-log.entries.table` must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.',
            ],
            'a table name with capitals, whose index names no engine reports as written' => [
                ['audit-log.entries.table' => 'AuditEntries'],
                '[config] `audit-log.entries.table` must be a table name of 1 to 47 lower-case letters, digits and underscores that does not start with a digit.',
            ],
            'a key ring that is not a map' => [
                ['audit-log.integrity.keys' => 'x'],
                '[config] `audit-log.integrity.keys` must be a map of key ids to secrets, or empty to derive the key from `app.key`.',
            ],
            'a secret of 31 bytes' => [
                ['audit-log.integrity.keys' => ['k1' => self::SHORT_SECRET], 'audit-log.integrity.current' => 'k1'],
                '[config] `audit-log.integrity.keys.k1` must be a secret of at least 32 bytes, or `base64:` followed by the encoding of one.',
            ],
            'a current key that is not in the ring' => [
                ['audit-log.integrity.keys' => ['k1' => str_repeat('k', 32)], 'audit-log.integrity.current' => 'k2'],
                '[config] `audit-log.integrity.current` must name a key in `audit-log.integrity.keys`.',
            ],
            'a current key without a ring' => [
                ['audit-log.integrity.current' => 'k1'],
                '[config] `audit-log.integrity.current` names a key, but `audit-log.integrity.keys` is empty; set both, or neither to derive the key from `app.key`.',
            ],
            'no application key to derive from' => [
                ['app.key' => ''],
                '[config] `app.key` must be set to derive the integrity key when `audit-log.integrity.keys` is empty.',
            ],
            'an empty list of guards'                  => [['audit-log.actor.guards' => []], self::MALFORMED_GUARDS],
            'guards that are a string'                 => [['audit-log.actor.guards' => 'web'], self::MALFORMED_GUARDS],
            'a guard that is not a string'             => [['audit-log.actor.guards' => [42]], self::MALFORMED_GUARDS],
            'guards that are a map'                    => [['audit-log.actor.guards' => ['first' => 'web']], self::MALFORMED_GUARDS],
            'an empty guard name'                      => [['audit-log.actor.guards' => ['']], self::MALFORMED_GUARDS],
            'a guard name of 65 characters'            => [['audit-log.actor.guards' => [str_repeat('g', 65)]], self::MALFORMED_GUARDS],
            'a guard name with a control character'    => [['audit-log.actor.guards' => ["web\x07"]], self::MALFORMED_GUARDS],
            'a request id flag that is a word'         => [['audit-log.context.trust_request_id' => 'yes'], self::MALFORMED_TRUST_REQUEST_ID],
            'a request id flag that is a number'       => [['audit-log.context.trust_request_id' => 1], self::MALFORMED_TRUST_REQUEST_ID],
            'a request id flag that is null'           => [['audit-log.context.trust_request_id' => null], self::MALFORMED_TRUST_REQUEST_ID],
            'a traceparent flag that is a word'        => [['audit-log.context.trust_traceparent' => 'yes'], self::MALFORMED_TRUST_TRACEPARENT],
            'a traceparent flag that is a number'      => [['audit-log.context.trust_traceparent' => 1], self::MALFORMED_TRUST_TRACEPARENT],
            'a traceparent flag that is null'          => [['audit-log.context.trust_traceparent' => null], self::MALFORMED_TRUST_TRACEPARENT],
            'a header name with a space'               => [['audit-log.context.request_id_header' => 'X Request'], self::MALFORMED_HEADER],
            'a header name that is not a string'       => [['audit-log.context.request_id_header' => 42], self::MALFORMED_HEADER],
            'an empty header name'                     => [['audit-log.context.request_id_header' => ''], self::MALFORMED_HEADER],
            'a header name of 65 characters'           => [['audit-log.context.request_id_header' => str_repeat('h', 65)], self::MALFORMED_HEADER],
            'a registered flag that is a digit'        => [['audit-log.definitions.require_registered' => '1'], self::MALFORMED_REQUIRE_REGISTERED],
            'a registered flag that is a word'         => [['audit-log.definitions.require_registered' => 'yes'], self::MALFORMED_REQUIRE_REGISTERED],
            'a registered flag that is a number'       => [['audit-log.definitions.require_registered' => 1], self::MALFORMED_REQUIRE_REGISTERED],
            'a source id that is not a string'         => [['audit-log.source.id' => 42], self::MALFORMED_SOURCE_ID],
            'a source id of 65 characters'             => [['audit-log.source.id' => str_repeat('s', 65)], self::MALFORMED_SOURCE_ID],
            'a source id with a control character'     => [['audit-log.source.id' => "app\x07"], self::MALFORMED_SOURCE_ID],
            'a source region that is not a string'     => [['audit-log.source.region' => 42], self::MALFORMED_SOURCE_REGION],
            'a source region of 33 characters'         => [['audit-log.source.region' => str_repeat('r', 33)], self::MALFORMED_SOURCE_REGION],
            'a source region with a control character' => [['audit-log.source.region' => "eu\x07"], self::MALFORMED_SOURCE_REGION],
            'an application name that gives no slug'   => [['app.name' => '!!!'], '[config] `audit-log.source.id` must be set, because `app.name` gives no slug.'],
            'an application name that is not a string' => [['app.name' => 42], '[config] `audit-log.source.id` must be set, because `app.name` gives no slug.'],
        ];
    }

    /**
     * Each bad setting is the one problem of its run, named by its full path,
     * and the run fails.
     *
     * @param  array<string, array<array-key, int|string>|int|string|null>  $settings
     * @param  string  $problem
     * @return void
     */
    #[DataProvider('provideBadSettings')]
    public function testEachBadSettingIsReportedByItsFullPath(array $settings, string $problem): void
    {
        app(ConfigRepository::class)->set($settings);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([$problem], self::problemsIn($output));
    }

    /**
     * A malformed setting leaves out the subjects that depend on it, so a
     * malformed storage connection is reported once, by `config`, and neither
     * the connections nor the schema are checked.
     *
     * @return void
     */
    public function testASubjectWhoseSettingsAreMalformedIsLeftOut(): void
    {
        app(ConfigRepository::class)->set('audit-log.storage.connection', 123);

        [, $output] = $this->check();

        self::assertSame([
            '[config] `audit-log.storage.connection` must be a connection name, or null or empty for the default connection.',
            '[integrity] OK',
        ], $output);
    }

    /**
     * A malformed maintenance connection leaves the connections out, but the
     * schema, which lives on the storage connection, is still checked.
     *
     * @return void
     */
    public function testAMalformedMaintenanceConnectionStillChecksTheSchema(): void
    {
        app(ConfigRepository::class)->set('audit-log.storage.maintenance_connection', []);

        [, $output] = $this->check();

        self::assertSame([
            '[config] `audit-log.storage.maintenance_connection` must be a connection name, or null or empty for the storage connection.',
            '[schema] OK',
            '[integrity] OK',
        ], $output);
    }

    /**
     * A storage connection that is not configured is reported once, by
     * `connections`, and the schema is not checked on it.
     *
     * @return void
     */
    public function testAnUnconfiguredStorageConnectionIsNotCheckedForItsSchema(): void
    {
        app(ConfigRepository::class)->set('audit-log.storage.connection', 'missing');

        [, $output] = $this->check();

        self::assertSame([
            '[config] OK',
            '[connections] The connection [missing] that `audit-log.storage.connection` names is not configured in `database.connections`.',
            '[integrity] OK',
        ], $output);
    }

    /**
     * An empty storage setting means the default connection, which is checked
     * the same way when it is not configured.
     *
     * @return void
     */
    public function testAnUnconfiguredDefaultConnectionIsAProblem(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.storage.connection', '');
        $config->set('database.default', 'nowhere');

        [$code, $output] = $this->check();

        // The rollback when the test ends runs on the default connection
        $config->set('database.default', self::CONNECTION);

        self::assertSame(1, $code);
        self::assertSame([
            '[connections] The connection [nowhere] that `audit-log.storage.connection` names is not configured in `database.connections`.',
        ], self::problemsIn($output));
    }

    /**
     * A maintenance connection of its own that is configured with the storage
     * connection's driver passes.
     *
     * @return void
     */
    public function testAMaintenanceConnectionOnTheSameDriverPasses(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.maintenance', $config->array('database.connections.' . self::CONNECTION));
        $config->set('audit-log.storage.maintenance_connection', 'maintenance');

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame(self::EVERY_SUBJECT_OK, $output);
    }

    /**
     * The engine's problems are listed with the table's: here a MySQL session
     * that is not strict, on a connection that answers as MySQL would and holds
     * no table.
     *
     * @return void
     */
    public function testTheEnginesProblemsAreListedWithTheTables(): void
    {
        $schema = \Mockery::mock(MySqlBuilder::class);

        $schema->shouldReceive('hasTable')->andReturnFalse();

        $connection = \Mockery::mock(MySqlConnection::class . '[getSchemaBuilder,scalar]', [new VersionReportingPdo('8.4.11'), '', '', ['driver' => 'mysql']]);

        $connection->shouldReceive('getSchemaBuilder')->andReturn($schema);
        $connection->shouldReceive('scalar')->andReturnUsing(static fn (string $query): string => str_contains($query, 'sql_mode') ? 'NO_ENGINE_SUBSTITUTION' : 'InnoDB');

        $config = app(ConfigRepository::class);

        $config->set('database.connections.fake', ['driver' => 'mysql', 'database' => ':memory:', 'prefix' => '']);
        $config->set('audit-log.storage.connection', 'fake');

        $this->app?->make(DatabaseManager::class)->extend('fake', static fn (): MySqlConnection => $connection);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[schema] The storage connection does not run in strict mode; set `strict` to true on the connection, so a value that does not fit fails instead of'
                . ' being cut.',
            '[schema] The entries table `audit_log_entries` does not exist on connection [fake]; publish and run the migrations'
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
        ], self::problemsIn($output));
    }

    /**
     * A missing entries table is one problem, not one for each column and index
     * it lacks.
     *
     * @return void
     */
    public function testAMissingTableIsReportedOnce(): void
    {
        app(ConfigRepository::class)->set('audit-log.entries.table', self::ABSENT_TABLE);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] OK',
            '[connections] OK',
            '[schema] The entries table `audit_absent_entries` does not exist on connection [testing]; publish and run the migrations'
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
            '[integrity] OK',
        ], $output);
    }

    /**
     * Every check runs, so bad settings in two subjects and a table missing a
     * column and holding another are all listed by one run, each subject's in
     * order.
     *
     * @return void
     */
    public function testEveryProblemIsListedInOneRun(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.storage.maintenance_connection', 'missing');
        $config->set('audit-log.integrity.keys', 'x');

        Schema::table('audit_log_entries', static function (Blueprint $table): void {
            $table->dropColumn('reason');
            $table->string('notes')->nullable();
        });

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] `audit-log.integrity.keys` must be a map of key ids to secrets, or empty to derive the key from `app.key`.',
            '[connections] The connection [missing] that `audit-log.storage.maintenance_connection` names is not configured in `database.connections`.',
            '[schema] Column `reason` is missing.',
            '[schema] Column `notes` is not one the package writes, so no entry\'s HMAC covers it.',
        ], $output);
    }

    /**
     * Neither a short secret, nor its `base64:` form, nor the application key,
     * nor the statement a broken database fails, nor the path it binds, is ever
     * printed.
     *
     * @return void
     */
    public function testNoSecretOrBindingIsPrinted(): void
    {
        $path = $this->garbageFile();

        $config = app(ConfigRepository::class);
        $secret = 'base64:' . base64_encode(self::SHORT_SECRET);

        $config->set('database.connections.garbage', ['driver' => 'sqlite', 'database' => $path, 'prefix' => '']);
        $config->set('audit-log.storage.connection', 'garbage');
        $config->set('audit-log.integrity.keys', ['k1' => $secret]);
        $config->set('audit-log.integrity.current', 'k1');

        [$code, $output] = $this->check();

        $printed = implode("\n", $output);

        self::assertSame(1, $code);
        self::assertSame([
            '[config] `audit-log.integrity.keys.k1` must be a secret of at least 32 bytes, or `base64:` followed by the encoding of one.',
            '[connections] OK',
            '[schema] The storage connection [garbage] could not be read (Illuminate\Database\QueryException).',
        ], $output);

        foreach ([self::SHORT_SECRET, $secret, $config->string('app.key'), $path, 'select', 'sqlite_master', 'SQL'] as $hidden) {
            self::assertStringNotContainsString($hidden, $printed);
        }
    }

    /**
     * A storage connection that cannot be opened is a problem named by the
     * class of what was thrown, never by its message, and the other subjects
     * are still checked.
     *
     * @return void
     */
    public function testAnUnreachableConnectionIsAProblemNotACrash(): void
    {
        $path   = sys_get_temp_dir() . '/audit-log-missing-' . getmypid() . '.sqlite';
        $config = app(ConfigRepository::class);

        $config->set('database.connections.broken', ['driver' => 'sqlite', 'database' => $path, 'prefix' => '']);
        $config->set('audit-log.storage.connection', 'broken');

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] OK',
            '[connections] OK',
            '[schema] The storage connection [broken] could not be opened (' . SQLiteDatabaseDoesNotExistException::class . ').',
            '[integrity] OK',
        ], $output);
        self::assertStringNotContainsString($path, implode("\n", $output));
    }

    /**
     * Every name in the list must be configured, so one that is not is the one
     * problem of its run, named because a guard's name is no secret, and the
     * run fails.
     *
     * @return void
     */
    public function testAGuardNotInAuthGuardsIsAProblem(): void
    {
        app(ConfigRepository::class)->set('audit-log.actor.guards', ['web', 'missing']);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] The guard [missing] that `audit-log.actor.guards` names is not configured in `auth.guards`.',
            '[connections] OK',
            '[schema] OK',
            '[integrity] OK',
        ], $output);
    }

    /**
     * Each guard the list names and `auth.guards` does not is listed, in the
     * list's order and once, however many times the list names it.
     *
     * @return void
     */
    public function testEveryMissingGuardIsListedOnceInOrder(): void
    {
        app(ConfigRepository::class)->set('audit-log.actor.guards', ['second', 'web', 'first', 'second']);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] The guard [second] that `audit-log.actor.guards` names is not configured in `auth.guards`.',
            '[config] The guard [first] that `audit-log.actor.guards` names is not configured in `auth.guards`.',
        ], self::problemsIn($output));
    }

    /**
     * With no list the actor is read from the default guard, so a default guard
     * `auth.guards` does not configure is a problem.
     *
     * @return void
     */
    public function testADefaultGuardNotInAuthGuardsIsAProblem(): void
    {
        app(ConfigRepository::class)->set('auth.defaults.guard', 'nowhere');

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[config] The default guard [nowhere] is not configured in `auth.guards`, and the actor is read from it.',
            '[connections] OK',
            '[schema] OK',
            '[integrity] OK',
        ], $output);
    }

    /**
     * Rows of `[the settings changed, how the default guard is named]`: a
     * default guard `AuthManager` would refuse, each named by its type when it
     * is not a name.
     *
     * @return iterable<string, array{0: array<string, array<array-key, array<string, string>|string>|string|null>, 1: string}>
     */
    public static function provideUnusableDefaultGuards(): iterable
    {
        yield from [
            'no default guard'                     => [['auth.defaults.guard' => null], 'null'],
            'a default guard that is not a name'   => [['auth.defaults.guard' => ['web']], 'array'],
            'an empty default guard'               => [['auth.defaults.guard' => ''], ''],
            'a guard configured as a string'       => [['auth.guards' => ['web' => 'session']], 'web'],
            'no guards at all'                     => [['auth.guards' => null], 'web'],
            'a dotted name AuthManager cannot see' => [['auth.defaults.guard' => 'api.v1', 'auth.guards' => ['api.v1' => ['driver' => 'session']]], 'api.v1'],
        ];
    }

    /**
     * A default guard that cannot be resolved is the one problem of its run,
     * looked up the way `AuthManager` looks it up: protects against a mutation
     * that reads the guard's key as a literal or accepts anything set.
     *
     * @param  array<string, array<array-key, array<string, string>|string>|string|null>  $settings
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideUnusableDefaultGuards')]
    public function testAnUnusableDefaultGuardIsAProblem(array $settings, string $name): void
    {
        app(ConfigRepository::class)->set($settings);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([sprintf('[config] The default guard [%s] is not configured in `auth.guards`, and the actor is read from it.', $name)], self::problemsIn($output));
    }

    /**
     * A list whose every guard is configured passes, and the default guard,
     * which a list stops the actor being read from, is then not checked.
     *
     * @return void
     */
    public function testAConfiguredGuardListPasses(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('auth.guards.api', ['driver' => 'token', 'provider' => 'users']);
        $config->set('auth.defaults.guard', 'nowhere');
        $config->set('audit-log.actor.guards', ['api', 'web']);

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame(self::EVERY_SUBJECT_OK, $output);
    }

    /**
     * A malformed list is reported once, by the context settings: the guard
     * check neither repeats it nor falls back to the default guard, which is
     * not the guard the application asked for.
     *
     * @return void
     */
    public function testAMalformedGuardListIsReportedOnce(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.actor.guards', 'web');
        $config->set('auth.defaults.guard', 'nowhere');

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([self::MALFORMED_GUARDS], self::problemsIn($output));
    }

    /**
     * Every value at the edge of what a new setting accepts passes: a real
     * boolean either way, the longest guard, header, source id and region,
     * counted in characters, and an id and a region left empty.
     *
     * @return void
     */
    public function testTheNewSettingsAcceptEveryGoodValue(): void
    {
        $config = app(ConfigRepository::class);
        $guard  = str_repeat('g', 64);

        $config->set("auth.guards.{$guard}", ['driver' => 'session', 'provider' => 'users']);
        $config->set('audit-log.actor.guards', [$guard]);
        $config->set('audit-log.context.trust_request_id', true);
        $config->set('audit-log.context.request_id_header', str_repeat('h', 64));
        $config->set('audit-log.context.trust_traceparent', false);
        $config->set('audit-log.definitions.require_registered', true);
        $config->set('audit-log.source.id', str_repeat('é', 64));
        $config->set('audit-log.source.region', str_repeat('é', 32));

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());

        $config->set('audit-log.source.id', '');
        $config->set('audit-log.source.region', '');

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * The values the configuration ships pass: no list of guards, neither
     * header trusted, the usual header name, and no source of its own, which
     * `app.name` then gives.
     *
     * @return void
     */
    public function testTheShippedDefaultsOfTheNewSettingsPass(): void
    {
        app(ConfigRepository::class)->set([
            'audit-log.actor.guards'                   => null,
            'audit-log.context.trust_request_id'       => false,
            'audit-log.context.request_id_header'      => 'X-Request-Id',
            'audit-log.context.trust_traceparent'      => false,
            'audit-log.definitions.require_registered' => false,
            'audit-log.source.id'                      => null,
            'audit-log.source.region'                  => null,
        ]);

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * Each group of new settings reports in one run, after the settings before
     * them and ahead of the guards, and none of them leaves out a later
     * subject, since none of those reads it.
     *
     * @return void
     */
    public function testEveryNewSettingProblemIsListedAndNoSubjectIsLeftOut(): void
    {
        app(ConfigRepository::class)->set([
            'audit-log.actor.guards'                   => ['missing'],
            'audit-log.context.trust_traceparent'      => 'yes',
            'audit-log.definitions.require_registered' => 'yes',
            'audit-log.entries.table'                  => self::ABSENT_TABLE,
            'audit-log.source.region'                  => 42,
        ]);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            self::MALFORMED_TRUST_TRACEPARENT,
            self::MALFORMED_SOURCE_REGION,
            self::MALFORMED_REQUIRE_REGISTERED,
            '[config] The guard [missing] that `audit-log.actor.guards` names is not configured in `auth.guards`.',
            '[connections] OK',
            '[schema] The entries table `audit_absent_entries` does not exist on connection [testing]; publish and run the migrations'
                . ' (`vendor:publish --tag=audit-log-migrations`, then `migrate`).',
            '[integrity] OK',
        ], $output);
    }

    /**
     * Every malformed setting a settings group holds is listed by the one run,
     * by its full path and in the order the settings are read, so a deploy
     * pipeline never has to fix them one run at a time.
     *
     * @return void
     */
    public function testEveryMalformedNewLeafIsReportedInOneRun(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.actor.guards', 'web');
        $config->set('audit-log.context.trust_request_id', 'yes');
        $config->set('audit-log.context.request_id_header', 'X Request');
        $config->set('audit-log.context.trust_traceparent', 'yes');
        $config->set('audit-log.source.id', 42);
        $config->set('audit-log.source.region', 42);
        $config->set('audit-log.definitions.require_registered', '1');

        self::assertSame([
            '[config] `audit-log.actor.guards` must be null, or a list of guard names of 1 to 64 characters.',
            self::MALFORMED_TRUST_REQUEST_ID,
            '[config] `audit-log.context.request_id_header` must be a header name of 1 to 64 characters.',
            self::MALFORMED_TRUST_TRACEPARENT,
            '[config] `audit-log.source.id` must be from 1 to 64 characters, with no control characters.',
            '[config] `audit-log.source.region` must be null or empty, or from 1 to 32 characters, with no control characters.',
            '[config] `audit-log.definitions.require_registered` must be true or false.',
        ], self::problemsIn($this->check()[1]));
    }

    /**
     * A malformed current key id and a malformed explicit ring are each listed
     * by the one run, and an explicit ring reads no application key.
     *
     * @return void
     */
    public function testEveryMalformedIntegritySettingIsReportedInOneRun(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('app.key', 'not a key');
        $config->set('audit-log.integrity.current', 42);
        $config->set('audit-log.integrity.keys', 'x');

        $problems = self::problemsIn($this->check()[1]);

        self::assertCount(2, $problems);
        self::assertStringContainsString('`audit-log.integrity.current`', $problems[0]);
        self::assertStringContainsString('`audit-log.integrity.keys`', $problems[1]);
    }

    /**
     * With no ring set the application's keys are what the ring is derived
     * from, so a malformed one is listed with a malformed current key id.
     *
     * @return void
     */
    public function testAMalformedApplicationKeyIsListedWithACurrentKeyId(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('app.key', '');
        $config->set('audit-log.integrity.current', 'k1');

        self::assertCount(2, self::problemsIn($this->check()[1]));
    }

    /**
     * Walks the leaves of the merged configuration, which must each have a bad
     * value here, then plants each value in turn and asserts a `[config]` line
     * naming that leaf, so a leaf added without a check fails this test instead
     * of being missed silently.
     *
     * @return void
     */
    public function testEveryNewLeafIsCoveredByACheck(): void
    {
        $config   = app(ConfigRepository::class);
        $settings = $config->array('audit-log');
        $leaves   = self::leavesOf($settings);

        self::assertContains('storage.connection', $leaves);
        self::assertContains('integrity.keys', $leaves);
        self::assertSame([], array_values(array_diff($leaves, array_keys(self::BAD_LEAVES))), 'A leaf of the configuration has no bad value, so no check is known to cover it.');

        foreach (self::BAD_LEAVES as $leaf => $bad) {

            $config->set("audit-log.{$leaf}", $bad);

            [$code, $output] = $this->check();

            $config->set('audit-log', $settings);

            $named = array_filter($output, static fn (string $line): bool => str_starts_with($line, "[config] `audit-log.{$leaf}` "));

            self::assertSame(1, $code, "A bad `{$leaf}` must fail the run.");
            self::assertCount(1, $named, "A bad `{$leaf}` must be named by one `[config]` line.");
        }

        self::assertSame([0, self::EVERY_SUBJECT_OK], $this->check());
    }

    /**
     * The walk finds a leaf at any depth, and takes an empty map, a list and
     * `null` for leaves, so the test above cannot pass by finding nothing.
     *
     * @return void
     */
    public function testTheWalkFindsEveryLeaf(): void
    {
        self::assertSame(
            ['top.deep.leaf', 'top.empty', 'top.list', 'unset', 'plain'],
            self::leavesOf(['top' => ['deep' => ['leaf' => 1], 'empty' => [], 'list' => ['a', 'b']], 'unset' => null, 'plain' => 'value']),
        );
    }

    /**
     * Rows of `[the setting, the bad value, the text in it]`, with the value in
     * each shape a setting refuses it in.
     *
     * @return iterable<string, array{0: string, 1: array<array-key, string>|string, 2: string}>
     */
    public static function provideValuesThatMustNotBePrinted(): iterable
    {
        $long = str_repeat(self::SENTINEL, 8);

        yield from [
            'guards that are a string'                 => ['audit-log.actor.guards', self::SENTINEL, self::SENTINEL],
            'guards that are a map'                    => ['audit-log.actor.guards', [self::SENTINEL => self::SENTINEL], self::SENTINEL],
            'a guard name too long'                    => ['audit-log.actor.guards', [$long], self::SENTINEL],
            'a guard name with a control character'    => ['audit-log.actor.guards', [self::SENTINEL . "\x07"], self::SENTINEL],
            'a request id flag'                        => ['audit-log.context.trust_request_id', self::SENTINEL, self::SENTINEL],
            'a header name'                            => ['audit-log.context.request_id_header', self::SENTINEL . ' X', self::SENTINEL],
            'a traceparent flag'                       => ['audit-log.context.trust_traceparent', self::SENTINEL, self::SENTINEL],
            'a registered flag'                        => ['audit-log.definitions.require_registered', self::SENTINEL, self::SENTINEL],
            'a source id too long'                     => ['audit-log.source.id', $long, self::SENTINEL],
            'a source id with a control character'     => ['audit-log.source.id', self::SENTINEL . "\x07", self::SENTINEL],
            'a source region too long'                 => ['audit-log.source.region', $long, self::SENTINEL],
            'a source region with a control character' => ['audit-log.source.region', self::SENTINEL . "\x07", self::SENTINEL],
            'an application name that gives no slug'   => ['app.name', '!~!~!~', '!~!~!~'],
            'an application name that is not a string' => ['app.name', [self::SENTINEL], self::SENTINEL],
            'a default guard that is not a name'       => ['auth.defaults.guard', [self::SENTINEL], self::SENTINEL],
        ];
    }

    /**
     * A bad value fails the run and never appears in its output: the setting is
     * named by its key, or, for a default guard that is not a name, by its
     * type.
     *
     * @param  string  $setting
     * @param  array<array-key, string>|string  $value
     * @param  string  $sentinel
     * @return void
     */
    #[DataProvider('provideValuesThatMustNotBePrinted')]
    public function testNoSettingValueIsPrinted(string $setting, array|string $value, string $sentinel): void
    {
        app(ConfigRepository::class)->set($setting, $value);

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertNotSame([], self::problemsIn($output));
        self::assertStringNotContainsString($sentinel, implode("\n", $output));
    }

    /**
     * The check writes nothing: the table's rows are as they were.
     *
     * @return void
     */
    public function testTheCheckWritesNothing(): void
    {
        $before = DB::table('audit_log_entries')->count();

        $this->check();

        self::assertSame(0, $before);
        self::assertSame(0, DB::table('audit_log_entries')->count());
    }

    /**
     * Run the command and return its exit code and its output lines.
     *
     * @return array{0: int, 1: list<string>}
     */
    private function check(): array
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        $code = $kernel->call('audit-log:check');

        return [$code, array_values(array_filter(array_map(trim(...), explode("\n", $kernel->output())), static fn (string $line): bool => $line !== ''))];
    }

    /**
     * The lines of the output that are not a subject's `OK`.
     *
     * @param  list<string>  $output
     * @return list<string>
     */
    private static function problemsIn(array $output): array
    {
        return array_values(array_filter($output, static fn (string $line): bool => preg_match('/\A\[[a-z]+\] OK\z/', $line) !== 1));
    }

    /**
     * The paths of the leaves under the settings: a value that is not a map, or
     * is empty or a list, is a leaf.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $settings
     * @param  string  $prefix
     * @return list<string>
     */
    private static function leavesOf(array $settings, string $prefix = ''): array
    {
        $leaves = [];

        foreach ($settings as $key => $value) {
            $leaves = is_array($value) && $value !== [] && !array_is_list($value)
                ? [...$leaves, ...self::leavesOf($value, "{$prefix}{$key}.")]
                : [...$leaves, "{$prefix}{$key}"];
        }

        return $leaves;
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

    /**
     * A file that exists but is not a database, removed when the test ends.
     *
     * @return string
     */
    private function garbageFile(): string
    {
        $path = sys_get_temp_dir() . '/audit-log-garbage-' . getmypid() . '.sqlite';

        file_put_contents($path, str_repeat('not a database ', 512));

        $this->files[] = $path;

        return $path;
    }
}
