<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\ExportSnapshot;
use Tests\Concerns\InteractsWithReadWriteSplit;
use Tests\TestCase;

/**
 * Feature tests for the snapshot an export is read in, on each engine.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExportSnapshot::class)]
final class ExportSnapshotTest extends TestCase
{
    use InteractsWithReadWriteSplit;

    /** @var string What a dedicated session's name starts with. */
    private const string SESSION_PREFIX = 'audit_log_export_';

    /** @var string A table that exists on the replica alone. */
    private const string REPLICA_ONLY = 'replica_only';

    /** @var string A table the testing transaction writes a row to. */
    private const string HELD_ROWS = 'export_snapshot_held_rows';

    /** @var string A connection to in-memory SQLite. */
    private const string MEMORY_CONNECTION = 'memory';

    /** @var list<array{0: string, 1: string}> Each statement run since the test began listening, with its connection's name. */
    private array $statements = [];

    /**
     * Close the split's connections and delete their files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeReadWriteSplit();

        DB::purge(self::MEMORY_CONNECTION);

        parent::tearDown();
    }

    /**
     * Each engine opens its snapshot with its own statements.
     *
     * @return void
     */
    public function testEachEngineOpensItsSnapshot(): void
    {
        self::assertSame([
            'pgsql'  => ['START TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'],
            'mysql'  => ['SET TRANSACTION ISOLATION LEVEL REPEATABLE READ', 'START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY'],
            'sqlite' => ['BEGIN DEFERRED'],
        ], ExportSnapshot::BEGIN);

        self::assertSame([
            'pgsql'  => 'repeatable_read_read_only',
            'mysql'  => 'consistent_snapshot_read_only',
            'sqlite' => 'deferred_read_transaction',
        ], ExportSnapshot::CONSISTENCY);

        $this->onAFileDatabase();
        $this->listen();

        $snapshot = $this->open();
        $session  = $snapshot->connection()->getName();

        self::assertSame([[$session, 'BEGIN DEFERRED']], $this->statements);
        self::assertTrue(self::isInSqliteTransaction($snapshot->connection()));

        $snapshot->close();

        self::assertSame([[$session, 'BEGIN DEFERRED'], [$session, 'COMMIT']], $this->statements);
    }

    /**
     * Over a read/write split the session is dedicated and reads the replica.
     *
     * @return void
     */
    public function testTheSessionIsDedicatedAndReadsTheReader(): void
    {
        $this->useReadWriteSplit();

        Schema::connection(self::REPLICA_CONNECTION)->create(self::REPLICA_ONLY, static function ($table): void {
            $table->id();
        });

        $replica  = app(ConfigRepository::class)->string('database.connections.' . self::REPLICA_CONNECTION . '.database');
        $snapshot = $this->open();
        $session  = $snapshot->connection();

        self::assertStringStartsWith(self::SESSION_PREFIX, (string) $session->getName());
        self::assertNotSame(DB::connection(self::SPLIT_CONNECTION), $session);
        self::assertSame($session->getPdo(), $session->getReadPdo());
        self::assertSame($replica, $session->getConfig('database'));
        self::assertNull($session->getConfig('read'));
        self::assertNull($session->getConfig('write'));
        self::assertSame($session->getName(), $session->getConfig('name'));
        self::assertTrue(self::hasTable($session, self::REPLICA_ONLY));
        self::assertFalse(self::hasTable(DB::connection(self::PRIMARY_CONNECTION), self::REPLICA_ONLY));
        self::assertSame(0, DB::connection(self::SPLIT_CONNECTION)->transactionLevel());

        $snapshot->close();
    }

    /**
     * The session reads the database a `url` names, never the fallback.
     *
     * @return void
     */
    public function testTheSessionReadsTheDatabaseTheUrlNames(): void
    {
        $this->useReadWriteSplit();

        $config  = app(ConfigRepository::class);
        $replica = $config->string('database.connections.' . self::REPLICA_CONNECTION . '.database');

        $config->set('database.connections.by_url', [
            'driver'   => 'sqlite',
            'url'      => 'sqlite:///' . $replica,
            'database' => sys_get_temp_dir() . '/' . uniqid('audit-fallback-', true) . '/fallback.sqlite',
            'prefix'   => '',
        ]);

        $config->set('audit-log.storage.connection', 'by_url');

        try {
            self::assertSame($replica, DB::connection('by_url')->getDatabaseName());

            $snapshot = $this->open();

            self::assertSame($replica, $snapshot->connection()->getDatabaseName());
            self::assertSame($replica, $snapshot->semantics()['database']);
            self::assertNull($snapshot->connection()->getConfig('url'));

            $snapshot->close();
        } finally {
            DB::purge('by_url');
        }
    }

    /**
     * Session configuration resolves every `url` as the database manager does.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testTheSessionConfigurationResolvesEveryUrl(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.by_url', [
            'driver'   => 'mysql',
            'url'      => 'mysql://auditor@url-host:3307/actual_db',
            'host'     => '127.0.0.1',
            'port'     => 3306,
            'database' => 'fallback_db',
            'read'     => ['url' => 'mysql://auditor@replica-host:3308/actual_db'],
        ]);

        $method = new \ReflectionMethod(ExportSnapshot::class, 'sessionConfig');
        $plain  = $method->invoke(null, 'by_url', DB::connection(self::CONNECTION));

        self::assertIsArray($plain);
        self::assertSame(['replica-host', 3308, 'actual_db'], [$plain['host'] ?? null, $plain['port'] ?? null, $plain['database'] ?? null]);
        self::assertArrayNotHasKey('url', $plain);
        self::assertArrayNotHasKey('read', $plain);

        $config->set('database.connections.by_url.read', ['host' => 'replica-host']);

        $merged = $method->invoke(null, 'by_url', DB::connection(self::CONNECTION));

        self::assertIsArray($merged);
        self::assertSame(['replica-host', 3307, 'actual_db'], [$merged['host'] ?? null, $merged['port'] ?? null, $merged['database'] ?? null]);
    }

    /**
     * A list of readers gives one, picked as Laravel picks a reader.
     *
     * @return void
     */
    public function testAListOfReadersGivesOne(): void
    {
        $this->useReadWriteSplit();

        $config  = app(ConfigRepository::class);
        $replica = $config->string('database.connections.' . self::REPLICA_CONNECTION . '.database');

        $config->set('database.connections.' . self::SPLIT_CONNECTION . '.read', [['database' => $replica], ['database' => $replica]]);

        DB::purge(self::SPLIT_CONNECTION);

        $snapshot = $this->open();

        self::assertSame($replica, $snapshot->connection()->getConfig('database'));
        self::assertNull($snapshot->connection()->getConfig('read'));

        $snapshot->close();
    }

    /**
     * A run-time connection is copied from the settings it was made with.
     *
     * @return void
     */
    public function testAConnectionWithoutConfigurationIsCopiedFromItsOwnSettings(): void
    {
        $this->useReadWriteSplit();

        $replica = app(ConfigRepository::class)->string('database.connections.' . self::REPLICA_CONNECTION . '.database');

        DB::connectUsing('made_at_run_time', ['driver' => 'sqlite', 'database' => $replica, 'prefix' => '']);

        app(ConfigRepository::class)->set('audit-log.storage.connection', 'made_at_run_time');

        try {
            $snapshot = $this->open();

            self::assertStringStartsWith(self::SESSION_PREFIX, (string) $snapshot->connection()->getName());
            self::assertSame($replica, $snapshot->connection()->getConfig('database'));
            self::assertSame('made_at_run_time', $snapshot->semantics()['connection']);

            $snapshot->close();
        } finally {
            DB::purge('made_at_run_time');
        }
    }

    /**
     * In-memory SQLite, invisible to a second PDO, shares the connection.
     *
     * @return void
     */
    public function testInMemorySqliteSharesTheConnection(): void
    {
        $storage = $this->onInMemorySqlite();

        $this->listen();

        $snapshot = $this->open();

        self::assertSame($storage, $snapshot->connection());
        self::assertSame([[self::MEMORY_CONNECTION, 'BEGIN DEFERRED']], $this->statements);
        self::assertTrue(self::isInSqliteTransaction($storage));
        self::assertSame(0, $storage->transactionLevel());
        self::assertSame('deferred_read_transaction', $snapshot->semantics()['consistency']);
        self::assertSame([], $this->sessions());

        $snapshot->close();

        self::assertSame([[self::MEMORY_CONNECTION, 'BEGIN DEFERRED'], [self::MEMORY_CONNECTION, 'COMMIT']], $this->statements);
        self::assertFalse(self::isInSqliteTransaction($storage));
        self::assertSame($storage, DB::connection(self::MEMORY_CONNECTION));
    }

    /**
     * Rows of `[database]`: in-memory SQLite named as a URI.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideInMemoryUris(): iterable
    {
        yield from [
            'the mode first'           => ['file:audit_export_first?mode=memory&cache=shared'],
            'the mode after the cache' => ['file:audit_export_after?cache=shared&mode=memory'],
        ];
    }

    /**
     * In-memory SQLite named as a URI shares the connection as `:memory:` does.
     *
     * @param  string  $database
     * @return void
     */
    #[DataProvider('provideInMemoryUris')]
    public function testAnInMemoryUriSharesTheConnection(string $database): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.shared_memory', ['driver' => 'sqlite', 'database' => $database, 'prefix' => '']);
        $config->set('audit-log.storage.connection', 'shared_memory');

        try {
            $snapshot = $this->open();

            self::assertSame(DB::connection('shared_memory'), $snapshot->connection());
            self::assertSame([], $this->sessions());

            $snapshot->close();
        } finally {
            DB::purge('shared_memory');
        }
    }

    /**
     * A testing base transaction is read inside, named `testing_transaction`.
     *
     * @return void
     */
    public function testAnOpenTestingTransactionIsReadInside(): void
    {
        $storage = DB::connection(self::CONNECTION);
        $schema  = Schema::connection(self::CONNECTION);

        $schema->create(self::HELD_ROWS, static function ($table): void {
            $table->id();
        });

        try {
            $this->testingManager();

            $storage->beginTransaction();
            $storage->table(self::HELD_ROWS)->insert(['id' => 1]);

            $this->listen();

            $snapshot = $this->open();

            self::assertSame($storage, $snapshot->connection());
            self::assertSame('testing_transaction', $snapshot->semantics()['consistency']);
            self::assertSame(1, $snapshot->connection()->table(self::HELD_ROWS)->count());

            $snapshot->close();
            $snapshot->abandon();

            self::assertSame([], array_filter($this->statements, static fn (array $statement): bool => !str_starts_with($statement[1], 'select')));
            self::assertSame([], $this->sessions());
            self::assertSame(1, $storage->transactionLevel());
            self::assertTrue($storage->getPdo()->inTransaction());

            $storage->rollBack();
        } finally {
            $schema->dropIfExists(self::HELD_ROWS);
        }
    }

    /**
     * Any other transaction open on the storage connection is refused first.
     *
     * @return void
     */
    public function testAnyOtherOpenTransactionIsRefused(): void
    {
        $storage = DB::connection(self::CONNECTION);

        $storage->beginTransaction();

        $this->assertRefusedInTransaction();

        $storage->rollBack();

        $this->testingManager();

        $storage->beginTransaction();
        $storage->beginTransaction();

        $this->assertRefusedInTransaction();

        $storage->rollBack();
        $storage->rollBack();
    }

    /**
     * With no transactions manager bound, any open transaction is refused.
     *
     * @return void
     */
    public function testWithoutATransactionsManagerAnOpenTransactionIsRefused(): void
    {
        $storage = DB::connection(self::CONNECTION);

        $storage->beginTransaction();

        $this->app?->forgetInstance('db.transactions');
        $this->app?->offsetUnset('db.transactions');

        $this->assertRefusedInTransaction();

        $storage->rollBack();
    }

    /**
     * Closing commits and purges the session; closing again does nothing.
     *
     * @return void
     */
    public function testCloseCommitsAndPurges(): void
    {
        $this->onAFileDatabase();

        $snapshot = $this->open();
        $session  = (string) $snapshot->connection()->getName();

        self::assertSame([$session], $this->sessions());

        $this->listen();

        $snapshot->close();
        $snapshot->close();
        $snapshot->abandon();

        self::assertSame([[$session, 'COMMIT']], $this->statements);
        self::assertSame([], $this->sessions());
    }

    /**
     * Abandoning rolls back and purges, swallowing a failed rollback.
     *
     * @return void
     */
    public function testAbandonRollsBackAndNeverThrows(): void
    {
        $this->onAFileDatabase();

        $snapshot = $this->open();
        $session  = (string) $snapshot->connection()->getName();

        $this->listen();

        $snapshot->abandon();
        $snapshot->abandon();
        $snapshot->close();

        self::assertSame([[$session, 'ROLLBACK']], $this->statements);
        self::assertSame([], $this->sessions());

        $failing = $this->open();

        $failing->connection()->getPdo()->exec('ROLLBACK');
        $failing->abandon();

        self::assertSame([], $this->sessions());
    }

    /**
     * A commit that fails is thrown, and the session is purged all the same.
     *
     * @return void
     */
    public function testAFailedCommitStillPurges(): void
    {
        $this->onAFileDatabase();

        $snapshot = $this->open();

        $snapshot->connection()->getPdo()->exec('ROLLBACK');

        try {
            $snapshot->close();
            self::fail('Expected the commit to fail.');
        } catch (\Throwable $exception) {
            self::assertInstanceOf(QueryException::class, $exception);
            self::assertSame([], $this->sessions());
        }
    }

    /**
     * A silent failed begin is refused, a commit thrown, a rollback swallowed.
     *
     * @return void
     */
    public function testAStatementTheConnectionSaysDidNotRunIsRefused(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.silent', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'options' => [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_SILENT]]);
        $config->set('audit-log.storage.connection', 'silent');

        try {
            $pdo = DB::connection('silent')->getPdo();

            $pdo->exec('BEGIN');

            $this->assertRefusedToRun('BEGIN DEFERRED', function (): void {
                $this->open();
            });

            $pdo->exec('ROLLBACK');

            $closing = $this->open();

            $pdo->exec('ROLLBACK');

            $this->assertRefusedToRun('COMMIT', static function () use ($closing): void {
                $closing->close();
            });

            $abandoning = $this->open();

            $pdo->exec('ROLLBACK');
            $abandoning->abandon();
            $abandoning->close();

            self::assertFalse(self::isInSqliteTransaction(DB::connection('silent')));
        } finally {
            DB::purge('silent');
        }
    }

    /**
     * A session that cannot begin is purged before the failure is thrown.
     *
     * @return void
     */
    public function testASessionThatCannotBeginIsPurged(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.gone', ['driver' => 'sqlite', 'database' => sys_get_temp_dir() . '/' . uniqid('audit-gone-', true) . '/gone.sqlite', 'prefix' => '']);
        $config->set('audit-log.storage.connection', 'gone');

        try {
            $this->open();
            self::fail('Expected the session not to begin.');
        } catch (\Throwable $exception) {
            self::assertInstanceOf(QueryException::class, $exception);
            self::assertSame('BEGIN DEFERRED', $exception->getSql());
            self::assertStringStartsWith(self::SESSION_PREFIX, $exception->getConnectionName());
            self::assertSame([], $this->sessions());
        }
    }

    /**
     * An unsupported engine is refused before any session or statement.
     *
     * @return void
     */
    public function testAnUnsupportedDriverIsRefusedBeforeAnything(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.elsewhere', ['driver' => 'sqlsrv', 'host' => '127.0.0.1', 'database' => 'audit', 'prefix' => '']);
        $config->set('audit-log.storage.connection', 'elsewhere');

        $this->listen();

        try {
            $this->open();
            self::fail('Expected the driver to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('An export reads MySQL, PostgreSQL or SQLite, and the [elsewhere] connection is sqlsrv.', $exception->getMessage());
        }

        self::assertSame([], $this->statements);
        self::assertSame([], $this->sessions());
    }

    /**
     * The engine can be checked alone, with no statement or session.
     *
     * @return void
     */
    public function testTheEngineCanBeCheckedAlone(): void
    {
        $this->listen();

        ExportSnapshot::check(app('db'));

        $config = app(ConfigRepository::class);

        $config->set('database.connections.elsewhere', ['driver' => 'pgsql', 'host' => '127.0.0.1', 'database' => 'audit', 'prefix' => '']);
        $config->set('audit-log.storage.connection', 'elsewhere');

        ExportSnapshot::check(app('db'));

        $config->set('database.connections.other', ['driver' => 'sqlsrv', 'host' => '127.0.0.1', 'database' => 'audit', 'prefix' => '']);
        $config->set('audit-log.storage.connection', 'other');

        try {
            ExportSnapshot::check(app('db'));
            self::fail('Expected the driver to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('An export reads MySQL, PostgreSQL or SQLite, and the [other] connection is sqlsrv.', $exception->getMessage());
        }

        self::assertSame([], $this->statements);
        self::assertSame([], $this->sessions());
    }

    /**
     * The manifest describes the snapshot on each engine.
     *
     * @return void
     */
    public function testTheSemantics(): void
    {
        app(ConfigRepository::class)->set('audit-log.entries.table', 'activity');

        $storage  = DB::connection(self::CONNECTION);
        $engine   = $storage->getDriverName();
        $snapshot = $this->open();

        self::assertSame([
            'connection'  => self::CONNECTION,
            'consistency' => match ($engine) {
                'mysql' => 'consistent_snapshot_read_only',
                'pgsql' => 'repeatable_read_read_only',
                default => 'deferred_read_transaction',
            },
            'database' => $engine === 'sqlite' ? ':memory:' : $storage->getDatabaseName(),
            'engine'   => $engine,
            'table'    => 'activity',
        ], $snapshot->semantics());

        $snapshot->close();

        app(ConfigRepository::class)->set('audit-log.entries.table', EntrySettings::DEFAULT_TABLE);

        $this->useReadWriteSplit();

        $split = $this->open();

        self::assertSame([
            'connection'  => self::SPLIT_CONNECTION,
            'consistency' => 'deferred_read_transaction',
            'database'    => app(ConfigRepository::class)->string('database.connections.' . self::REPLICA_CONNECTION . '.database'),
            'engine'      => 'sqlite',
            'table'       => 'audit_log_entries',
        ], $split->semantics());

        $split->close();
    }

    /**
     * Assert the snapshot is refused for the open transaction, with no session.
     *
     * @return void
     */
    private function assertRefusedInTransaction(): void
    {
        try {
            $this->open();
            self::fail('Expected the open transaction to be refused.');
        } catch (AuditReadRefusedException $exception) {
            self::assertSame(AuditReadRefusedException::inTransaction(self::CONNECTION)->getMessage(), $exception->getMessage());
        }

        self::assertSame([], $this->sessions());
    }

    /**
     * Assert the work is refused for a statement the connection did not run.
     *
     * @param  string  $statement
     * @param  \Closure(): void  $work
     * @return void
     */
    private function assertRefusedToRun(string $statement, \Closure $work): void
    {
        try {
            $work();
            self::fail('Expected the statement to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame(sprintf('The export\'s snapshot could not run %s.', $statement), $exception->getMessage());
        }
    }

    /**
     * Make in-memory SQLite the storage connection, and return it.
     *
     * @return \Illuminate\Database\Connection
     */
    private function onInMemorySqlite(): Connection
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::MEMORY_CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('audit-log.storage.connection', self::MEMORY_CONNECTION);

        return DB::connection(self::MEMORY_CONNECTION);
    }

    /**
     * Put the storage connection on the replica's file, with no split.
     *
     * @return void
     */
    private function onAFileDatabase(): void
    {
        $this->useReadWriteSplit();

        app(ConfigRepository::class)->set('audit-log.storage.connection', self::REPLICA_CONNECTION);
    }

    /**
     * Keep each statement run from now on, with its connection's name.
     *
     * @return void
     */
    private function listen(): void
    {
        $this->statements = [];

        Event::listen(QueryExecuted::class, function (QueryExecuted $query): void {
            $this->statements[] = [$query->connectionName, $query->sql];
        });
    }

    /**
     * Open a snapshot on the database manager the container holds.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\ExportSnapshot
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function open(): ExportSnapshot
    {
        return ExportSnapshot::open(app('db'));
    }

    /**
     * The names of the dedicated sessions the manager holds.
     *
     * @return list<string>
     */
    private function sessions(): array
    {
        return array_values(array_filter(array_keys(DB::getConnections()), static fn (string $name): bool => str_starts_with($name, self::SESSION_PREFIX)));
    }

    /**
     * Bind the transactions manager Laravel's testing traits install.
     *
     * @return void
     */
    private function testingManager(): void
    {
        $manager = new DatabaseTransactionsManager([self::CONNECTION]);

        $this->app?->instance('db.transactions', $manager);

        DB::connection(self::CONNECTION)->setTransactionManager($manager);
    }

    /**
     * Whether the SQLite connection is in a transaction, by trying to begin
     * one: before PHP 8.4 `PDO::inTransaction()` misses one a statement began.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    private static function isInSqliteTransaction(Connection $connection): bool
    {
        $pdo   = $connection->getPdo();
        $error = null;

        try {
            $begun = $pdo->exec('BEGIN') !== false;
        } catch (\PDOException $exception) {
            $begun = false;
            $error = $exception->getMessage();
        }

        if ($begun) {
            $pdo->exec('ROLLBACK');

            return false;
        }

        self::assertStringContainsString('cannot start a transaction within a transaction', $error ?? (string) $pdo->errorInfo()[2]);

        return true;
    }

    /**
     * Whether the SQLite connection has the table, read with a `select`.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @return bool
     */
    private static function hasTable(Connection $connection, string $table): bool
    {
        return $connection->select('select name from sqlite_master where type = ? and name = ?', ['table', $table]) !== [];
    }
}
