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
 * Integration tests for the session a key is created on, on whichever engine
 * the suite runs against: a key created inside a host transaction survives that
 * transaction's rollback on MySQL and PostgreSQL, where the session is a
 * connection of its own, and rolls back with it on SQLite, where the storage
 * connection itself is the session, as the privacy guide documents; and the
 * session writes through the storage connection's writer, never asking its
 * replica for anything.
 *
 * SQLite runs on a file, so a second connection to its database could exist and
 * the session is chosen for the transaction, not for an in-memory database.
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
     * A key created inside a host transaction that then rolls back survives it
     * on MySQL and PostgreSQL, committed on a session of its own, so no
     * ciphertext already written under it is left without its key; on SQLite,
     * whose storage connection is the session inside any transaction, it rolls
     * back with the host.
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
     * Over a storage connection configured with persistent PDO connections, a
     * key created inside a host transaction that then rolls back still survives
     * it on MySQL and PostgreSQL: the session opens a handle of its own, never
     * the persistent one the host's transaction runs on, so neither commits nor
     * rolls back the other, and the host's connection still works once the
     * session is purged.
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
     * Over a storage connection split between a writer and a reader, the
     * session is the writer's configuration alone: a key is created and read on
     * the writer, and the storage connection's reader, which cannot be reached,
     * is never asked for.
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
