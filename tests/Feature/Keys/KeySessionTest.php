<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Keys\KeySession;
use Tests\Concerns\InteractsWithReadWriteSplit;
use Tests\TestCase;

/**
 * Feature tests for the session a key is created on: in-memory SQLite created
 * on the storage connection itself, a file database given a session of its own
 * made from the storage connection's write configuration and purged once
 * closed, the testing manager's base transaction and SQLite inside any host
 * transaction kept on the storage connection, and an engine a key is not
 * created on refused before anything.
 *
 * The databases here are SQLite connections of their own, files or in-memory,
 * so they read the same on every engine the suite runs against; the testing
 * manager's transaction is opened on the storage connection itself, whichever
 * engine it is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeySession::class)]
final class KeySessionTest extends TestCase
{
    use InteractsWithReadWriteSplit;

    /** @var string A connection to in-memory SQLite. */
    private const string MEMORY_CONNECTION = 'key_session_memory';

    /** @var string A table written through a session and read through the storage connection. */
    private const string PROBE_TABLE = 'key_session_probe';

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
     * In-memory SQLite, which a second PDO cannot see, is the session itself:
     * no connection is made, and closing leaves the storage connection as it
     * was.
     *
     * @return void
     */
    public function testInMemorySqliteUsesTheStorageConnection(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::MEMORY_CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('audit-log.storage.connection', self::MEMORY_CONNECTION);

        $storage = DB::connection(self::MEMORY_CONNECTION);
        $session = KeySession::open(app('db'));

        self::assertSame($storage, $session->connection());
        self::assertFalse($session->isDedicated());
        self::assertSame([], self::sessions());

        $session->close();

        self::assertSame($storage, DB::connection(self::MEMORY_CONNECTION));
    }

    /**
     * Over a read/write split the session is the storage connection's write
     * configuration: the primary's database, no `read` or `write` of its own,
     * one PDO for reads and writes, and a name of its own, so a key is never
     * read from or written to the replica.
     *
     * @return void
     */
    public function testTheSessionIsTheWriteConfiguration(): void
    {
        $this->useReadWriteSplit();

        $primary = app(ConfigRepository::class)->string('database.connections.' . self::PRIMARY_CONNECTION . '.database');
        $session = KeySession::open(app('db'));
        $name    = (string) $session->connection()->getName();

        self::assertTrue($session->isDedicated());
        self::assertStringStartsWith(KeySession::SESSION_PREFIX, $name);
        self::assertMatchesRegularExpression('/\Aaudit_log_keys_[0-9a-f]{32}\z/', $name);
        self::assertSame($primary, $session->connection()->getDatabaseName());
        self::assertSame($primary, DB::connection(self::SPLIT_CONNECTION)->getConfig('database'));
        self::assertNull($session->connection()->getConfig('read'));
        self::assertNull($session->connection()->getConfig('write'));
        self::assertSame($name, $session->connection()->getConfig('name'));
        self::assertSame($session->connection()->getPdo(), $session->connection()->getReadPdo());
        self::assertNotSame(DB::connection(self::SPLIT_CONNECTION), $session->connection());

        $session->close();
    }

    /**
     * A file database is given a session of its own on its writer: another
     * connection to the same file, under its own name, whose writes the storage
     * connection reads.
     *
     * @return void
     */
    public function testAFileDatabaseGetsADedicatedSessionOnTheWriter(): void
    {
        $storage = $this->onAFileDatabase();
        $session = KeySession::open(app('db'));

        self::assertTrue($session->isDedicated());
        self::assertNotSame($storage, $session->connection());
        self::assertSame($storage->getDatabaseName(), $session->connection()->getDatabaseName());
        self::assertSame([(string) $session->connection()->getName()], self::sessions());

        $session->connection()->table(self::PROBE_TABLE)->insert(['id' => 1]);

        self::assertSame(1, $storage->table(self::PROBE_TABLE)->count());

        $session->close();
    }

    /**
     * A storage connection configured with persistent PDO connections still
     * gives the session a handle of its own, so a creation never runs on the
     * storage connection's own transaction nor disconnects it when purged; the
     * session keeps the other PDO options and drops the isolation level, which
     * the key creator sets.
     *
     * @return void
     */
    public function testTheSessionNeverSharesAPersistentHandle(): void
    {
        $this->onAFileDatabase();

        $config = app(ConfigRepository::class);
        $key    = 'database.connections.' . self::PRIMARY_CONNECTION;

        $config->set($key . '.options', [\PDO::ATTR_PERSISTENT => true, \PDO::ATTR_TIMEOUT => 7]);
        $config->set($key . '.isolation_level', 'serializable');

        DB::purge(self::PRIMARY_CONNECTION);

        $session = KeySession::open(app('db'));
        $options = $session->connection()->getConfig('options');

        self::assertTrue($session->isDedicated());
        self::assertIsArray($options);
        self::assertFalse($options[\PDO::ATTR_PERSISTENT]);
        self::assertSame(7, $options[\PDO::ATTR_TIMEOUT]);
        self::assertNull($session->connection()->getConfig('isolation_level'));
        self::assertFalse($session->connection()->getPdo()->getAttribute(\PDO::ATTR_PERSISTENT));
        self::assertTrue(DB::connection(self::PRIMARY_CONNECTION)->getPdo()->getAttribute(\PDO::ATTR_PERSISTENT));
        self::assertNotSame(DB::connection(self::PRIMARY_CONNECTION)->getPdo(), $session->connection()->getPdo());

        $session->close();
    }

    /**
     * Closing a dedicated session purges it from the manager, which disconnects
     * it; closing again does nothing, and the next session has a name of its
     * own.
     *
     * @return void
     */
    public function testTheDedicatedSessionIsPurgedWhenClosed(): void
    {
        $this->onAFileDatabase();

        $session = KeySession::open(app('db'));
        $name    = (string) $session->connection()->getName();

        self::assertSame([$name], self::sessions());

        $session->close();
        $session->close();

        self::assertSame([], self::sessions());

        $next = KeySession::open(app('db'));

        self::assertNotSame($name, $next->connection()->getName());

        $next->close();

        self::assertSame([], self::sessions());
    }

    /**
     * A storage connection holding the testing manager's base transaction,
     * whose rows no other session could see, is the session itself, so a key
     * created in a test rolls back with it; a transaction nested in that base
     * is a host's, given a session of its own on every engine but SQLite.
     *
     * @return void
     */
    public function testInsideTheTestingTransactionTheStorageConnectionIsUsed(): void
    {
        $storage = DB::connection(self::CONNECTION);
        $manager = new DatabaseTransactionsManager([self::CONNECTION]);

        $this->app?->instance('db.transactions', $manager);
        $storage->setTransactionManager($manager);

        $storage->beginTransaction();

        try {
            $session = KeySession::open(app('db'));

            self::assertSame($storage, $session->connection());
            self::assertFalse($session->isDedicated());

            $session->close();

            $storage->beginTransaction();

            $nested = KeySession::open(app('db'));

            self::assertSame($storage->getDriverName() !== 'sqlite', $nested->isDedicated());

            $nested->close();

            $storage->rollBack();
        } finally {
            $storage->rollBack();
        }

        self::assertSame([], self::sessions());
    }

    /**
     * On SQLite a storage connection inside any transaction is the session
     * itself, since a second writer would wait for the host's own lock; once
     * the transaction ends a session of its own is made again.
     *
     * @return void
     */
    public function testSqliteInsideAHostTransactionUsesTheStorageConnection(): void
    {
        $storage = $this->onAFileDatabase();

        $storage->beginTransaction();

        try {
            $session = KeySession::open(app('db'));

            self::assertSame($storage, $session->connection());
            self::assertFalse($session->isDedicated());
            self::assertSame([], self::sessions());
        } finally {
            $storage->rollBack();
        }

        $after = KeySession::open(app('db'));

        self::assertTrue($after->isDedicated());

        $after->close();
    }

    /**
     * A storage connection made at run time, with no configuration of its own,
     * is copied from the settings it was made with.
     *
     * @return void
     */
    public function testAConnectionMadeAtRunTimeIsCopiedFromItsOwnSettings(): void
    {
        $this->useReadWriteSplit();

        $primary = app(ConfigRepository::class)->string('database.connections.' . self::PRIMARY_CONNECTION . '.database');

        DB::connectUsing('keys_made_at_run_time', ['driver' => 'sqlite', 'database' => $primary, 'prefix' => '']);

        app(ConfigRepository::class)->set('audit-log.storage.connection', 'keys_made_at_run_time');

        try {
            $session = KeySession::open(app('db'));

            self::assertTrue($session->isDedicated());
            self::assertSame($primary, $session->connection()->getDatabaseName());

            $session->close();
        } finally {
            DB::purge('keys_made_at_run_time');
        }
    }

    /**
     * An engine other than MySQL, PostgreSQL and SQLite is refused before any
     * session is made or any statement runs, naming the connection and the
     * driver.
     *
     * @return void
     */
    public function testAnEngineAKeyIsNotCreatedOnIsRefused(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.elsewhere', ['driver' => 'sqlsrv', 'host' => '127.0.0.1', 'database' => 'audit', 'prefix' => '']);
        $config->set('audit-log.storage.connection', 'elsewhere');

        $statements = 0;

        Event::listen(QueryExecuted::class, static function () use (&$statements): void {
            $statements++;
        });

        try {
            KeySession::open(app('db'));
            self::fail('Expected the driver to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('A key is created on MySQL, PostgreSQL or SQLite, and the [elsewhere] connection is sqlsrv.', $exception->getMessage());
        } finally {
            DB::purge('elsewhere');
        }

        self::assertSame(0, $statements);
        self::assertSame([], self::sessions());
    }

    /**
     * Put the storage connection on the split's primary file alone, with the
     * probe table, and return it.
     *
     * @return \Illuminate\Database\Connection
     */
    private function onAFileDatabase(): Connection
    {
        $this->useReadWriteSplit();

        app(ConfigRepository::class)->set('audit-log.storage.connection', self::PRIMARY_CONNECTION);

        Schema::connection(self::PRIMARY_CONNECTION)->create(self::PROBE_TABLE, static function ($table): void {
            $table->integer('id');
        });

        return DB::connection(self::PRIMARY_CONNECTION);
    }

    /**
     * The names of the key sessions the manager holds.
     *
     * @return list<string>
     */
    private static function sessions(): array
    {
        return array_values(array_filter(array_keys(DB::getConnections()), static fn (string $name): bool => str_starts_with($name, KeySession::SESSION_PREFIX)));
    }
}
