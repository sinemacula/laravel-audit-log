<?php

declare(strict_types = 1);

namespace Tests\Integration\Keys;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Keys\KeySession;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\RunsKilledChildren;
use Tests\TestCase;

/**
 * Integration tests for the key session: it outlives a host rollback on MySQL
 * and PostgreSQL, rolls back with it on SQLite, and uses the writer alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeySession::class)]
final class KeySessionEnginesTest extends TestCase
{
    use MakesSubjectKeys, RunsKilledChildren;

    /** @var string A connection whose writer is the storage connection's and whose reader cannot be reached. */
    private const string SPLIT = 'key_session_split';

    /** @var string A connection to the storage connection's database over persistent PDO connections. */
    private const string PERSISTENT = 'key_session_persistent';

    /**
     * Forget the split and remove the shared files once the migrations have
     * rolled back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::purge(self::SPLIT);
        DB::purge(self::PERSISTENT);

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * A key created in a host transaction survives its rollback on MySQL and
     * PostgreSQL, and rolls back with it on SQLite.
     *
     * @return void
     */
    public function testAKeySurvivesTheHostTransactionsRollback(): void
    {
        $storage = DB::connection(StorageConnection::name());
        $owner   = Reference::of('App\Models\User', '42');

        $storage->beginTransaction();

        try {
            [$key] = $this->makeSubjectKey($owner);

            self::assertSame(1, $storage->transactionLevel());
        } finally {
            $storage->rollBack();
        }

        $kept = $storage->table(KeyTables::subjectKeysTable())->where('id', $key->id)->exists();

        if ($storage->getDriverName() === 'sqlite') {
            self::assertFalse($kept, 'On SQLite a key created inside a host transaction rolls back with it.');

            return;
        }

        self::assertTrue($kept, 'The key was lost with the host transaction.');
        self::assertSame([$key->id], array_keys($this->storedSubjectKeys()));
    }

    /**
     * Over persistent PDO connections the session still opens a handle of its
     * own, so a key survives the host's rollback.
     *
     * @return void
     */
    public function testAKeySurvivesTheHostsRollbackOverPersistentConnections(): void
    {
        $config = app(ConfigRepository::class);
        $base   = $config->array('database.connections.' . self::CONNECTION);

        if (($base['driver'] ?? null) === 'sqlite') {
            self::markTestSkipped('On SQLite the storage connection is the session inside any transaction.');
        }

        $config->set('database.connections.' . self::PERSISTENT, [...$base, 'options' => [\PDO::ATTR_PERSISTENT => true]]);
        $config->set('audit-log.storage.connection', self::PERSISTENT);

        $storage = DB::connection(self::PERSISTENT);
        $owner   = Reference::of('App\Models\User', '42');

        $storage->beginTransaction();

        try {
            [$key] = $this->makeSubjectKey($owner);

            self::assertSame(1, $storage->transactionLevel());
        } finally {
            $storage->rollBack();
        }

        self::assertTrue($storage->table(KeyTables::subjectKeysTable())->where('id', $key->id)->exists(), 'The key was lost with the host transaction.');
    }

    /**
     * Over a split writer and reader the session uses the writer alone and
     * never asks for the unreachable reader.
     *
     * @return void
     */
    public function testTheSessionWritesOnTheWriterNotAReplica(): void
    {
        $config = app(ConfigRepository::class);
        $writer = $config->array('database.connections.' . self::CONNECTION);
        $driver = $writer['driver'] ?? null;

        $config->set('database.connections.' . self::SPLIT, [
            ...$writer,
            'read'   => ['database' => $driver === 'sqlite' ? sys_get_temp_dir() . '/' . uniqid('audit-no-replica-', true) . '/replica.sqlite' : 'audit_log_no_such_replica'],
            'write'  => [],
            'sticky' => false,
        ]);
        $config->set('audit-log.storage.connection', self::SPLIT);

        $session = KeySession::open(app('db'));

        self::assertTrue($session->isDedicated());
        self::assertNull($session->connection()->getConfig('read'));
        self::assertSame(DB::connection(self::CONNECTION)->getDatabaseName(), $session->connection()->getDatabaseName());

        $session->close();

        [$key] = $this->makeSubjectKey(Reference::of('App\Models\User', '42'));

        self::assertTrue(DB::connection(self::CONNECTION)->table(KeyTables::subjectKeysTable())->where('id', $key->id)->exists());
        self::assertInstanceOf(\Closure::class, DB::connection(self::SPLIT)->getRawReadPdo(), 'The replica was asked for.');
    }

    /**
     * Put SQLite's database on a file, so the session is chosen for the host
     * transaction rather than for an in-memory database.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->useFileDatabaseOnSqlite($app);
    }
}
