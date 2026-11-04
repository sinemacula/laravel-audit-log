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
 * Feature tests for the snapshot an export is read in: the statements each
 * engine begins it with, the dedicated session made from the storage
 * connection's reader, in-memory SQLite read on the storage connection itself,
 * the testing manager's base transaction read inside and named honestly, any
 * other open transaction refused, the commit or rollback that ends it and the
 * purge of the session, an engine the export cannot read refused before
 * anything, and what the manifest says of it.
 *
 * SQLite runs here; the statements MySQL and PostgreSQL begin with are pinned
 * as strings, and run against those engines in the integration tests.
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

        parent::tearDown();
    }

    /**
     * Each engine begins its snapshot with its own statements: PostgreSQL a
     * repeatable read, read-only transaction, MySQL a consistent snapshot,
     * read-only, at repeatable read, and SQLite a deferred transaction, each
     * named in the manifest. On SQLite the session runs exactly its begin, and
     * its commit when the snapshot closes.
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
        self::assertTrue($snapshot->connection()->getPdo()->inTransaction());

        $snapshot->close();

        self::assertSame([[$session, 'BEGIN DEFERRED'], [$session, 'COMMIT']], $this->statements);
    }

    /**
     * Over a read/write split the session is a connection of its own, under a
     * name of its own, with one PDO, configured with the reader's settings and
     * with no `read` or `write` of its own, so it reads the replica, where a
     * table the primary does not have is found. The storage connection is left
     * as it was.
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
     * A storage connection configured by `url`, as `DB_URL` configures every
     * stock connection, is read through the database the URL names, as the
     * connection itself reads it, never the fallback `database` beside it.
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
     * The session's configuration takes the host, port and database from the
     * connection's `url` over the fallback keys, as the database manager does,
     * then a reader's own settings, its `url` resolved too, over those.
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
     * A reader given as a list is one of them, picked as Laravel picks a
     * reader.
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
     * A storage connection made at run time, with no configuration of its own,
     * is copied from the settings it was made with.
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
     * In-memory SQLite, which a second PDO cannot see, is read on the storage
     * connection itself, in a deferred transaction of its own begun outside
     * Laravel's transaction count, committed when the snapshot closes, and the
     * connection is kept.
     *
     * @return void
     */
    public function testInMemorySqliteSharesTheConnection(): void
    {
        $this->listen();

        $storage  = DB::connection(self::CONNECTION);
        $snapshot = $this->open();

        self::assertSame($storage, $snapshot->connection());
        self::assertSame([[self::CONNECTION, 'BEGIN DEFERRED']], $this->statements);
        self::assertTrue($storage->getPdo()->inTransaction());
        self::assertSame(0, $storage->transactionLevel());
        self::assertSame('deferred_read_transaction', $snapshot->semantics()['consistency']);
        self::assertSame([], $this->sessions());

        $snapshot->close();

        self::assertSame([[self::CONNECTION, 'BEGIN DEFERRED'], [self::CONNECTION, 'COMMIT']], $this->statements);
        self::assertFalse($storage->getPdo()->inTransaction());
        self::assertSame($storage, DB::connection(self::CONNECTION));
    }

    /**
     * Rows of `[database]`: in-memory SQLite named as a URI, its mode first or
     * after another parameter.
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
     * In-memory SQLite named as a URI is read on the storage connection itself,
     * as `:memory:` is.
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
     * A storage connection holding the testing manager's base transaction is
     * read inside it: no session is made, nothing is begun or committed, rows
     * the transaction holds are seen, the consistency is named
     * `testing_transaction`, and the transaction is still open once the
     * snapshot closes.
     *
     * @return void
     */
    public function testAnOpenTestingTransactionIsReadInside(): void
    {
        $storage = DB::connection(self::CONNECTION);

        $this->testingManager();

        $storage->beginTransaction();

        Schema::connection(self::CONNECTION)->create(self::REPLICA_ONLY, static function ($table): void {
            $table->id();
        });

        $this->listen();

        $snapshot = $this->open();

        self::assertSame($storage, $snapshot->connection());
        self::assertSame('testing_transaction', $snapshot->semantics()['consistency']);
        self::assertTrue(self::hasTable($snapshot->connection(), self::REPLICA_ONLY));

        $snapshot->close();
        $snapshot->abandon();

        self::assertSame([], array_filter($this->statements, static fn (array $statement): bool => !str_starts_with($statement[1], 'select')));
        self::assertSame([], $this->sessions());
        self::assertSame(1, $storage->transactionLevel());
        self::assertTrue($storage->getPdo()->inTransaction());

        $storage->rollBack();
    }

    /**
     * Any other transaction open on the storage connection is refused before
     * anything, as the read gate refuses it: under Laravel's own manager, and
     * one nested in the testing manager's base transaction.
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
     * Closing commits the snapshot and purges the session; closing again, or
     * abandoning once closed, does nothing.
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
     * Abandoning rolls the snapshot back and purges the session; abandoning
     * again, or closing once abandoned, does nothing. A rollback that fails is
     * swallowed, never thrown, and the session is purged all the same.
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
     * On a connection that reports errors silently, a begin the connection says
     * did not run is refused, so no snapshot is claimed that was not begun; a
     * commit it says did not run is thrown once the snapshot is ended, and a
     * rollback it says did not run is swallowed.
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

            self::assertFalse($pdo->inTransaction());
        } finally {
            DB::purge('silent');
        }
    }

    /**
     * A session that cannot begin, here because its database file is gone, is
     * purged before the failure is thrown, so no session is left behind.
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
     * An engine other than MySQL, PostgreSQL and SQLite is refused before any
     * session is made or any statement runs, naming the connection and the
     * driver.
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
     * The engine can be checked alone, before anything else, running no
     * statement and making no session: an engine the export reads passes, and
     * any other is refused as opening refuses it.
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
     * The manifest names the storage connection, the snapshot's consistency,
     * the database the session reads, the engine and the entries table as
     * configured.
     *
     * @return void
     */
    public function testTheSemantics(): void
    {
        app(ConfigRepository::class)->set('audit-log.entries.table', 'activity');

        $snapshot = $this->open();

        self::assertSame([
            'connection'  => self::CONNECTION,
            'consistency' => 'deferred_read_transaction',
            'database'    => ':memory:',
            'engine'      => 'sqlite',
            'table'       => 'activity',
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
     * Assert the snapshot is refused for the storage connection's open
     * transaction, opening no session.
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
     * Assert the work is refused for a statement the connection says did not
     * run.
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
     * Put the storage connection on the replica's file, a SQLite database a
     * second PDO can open, with no read/write split.
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
     * Bind the manager Laravel's testing traits install, over the storage
     * connection.
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
