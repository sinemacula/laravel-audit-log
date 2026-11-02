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
 * they name, the entries table and the integrity keys, lists every problem it
 * finds as `[<subject>] <message>` and every subject without one as
 * `[<subject>] OK`, exits `1` when there is a problem and `0` when there is
 * none, and prints no secret, statement or binding.
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
     * @return iterable<string, array{0: array<string, array<array-key, string>|int|string|null>, 1: string}>
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
        ];
    }

    /**
     * Each bad setting is the one problem of its run, named by its full path,
     * and the run fails.
     *
     * @param  array<string, array<array-key, string>|int|string|null>  $settings
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
