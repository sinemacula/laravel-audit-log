<?php

declare(strict_types = 1);

namespace Tests\Integration\Stores;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithReadWriteSplit;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for what the database store says of itself: it is durable,
 * and it joins a transaction on the storage connection and on no other, which
 * follows the storage setting; and, through a read/write split whose replica
 * refuses every write, that its insert goes to the writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAuditStore::class)]
final class DatabaseAuditStoreCapabilitiesTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithReadWriteSplit;

    /** @var string The id records are pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string A second connection to the worker's database, which a test may make the storage connection. */
    private const string AUDIT_CONNECTION = 'audit';

    /**
     * Close the split's connections and delete their files, when a test made
     * one.
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
     * A return is a durable acknowledgement, whatever the configuration.
     *
     * @return void
     */
    public function testIsDurable(): void
    {
        $store = $this->store();

        self::assertInstanceOf(DurableAuditStore::class, $store);
        self::assertTrue($store->isDurable());

        $this->useAnotherStorageConnection();

        self::assertTrue($this->store()->isDurable());
    }

    /**
     * With no storage connection configured, it joins a transaction on the
     * default connection, which is the storage connection; and a record it
     * stores inside one rolls back with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testParticipatesOnItsStorageConnection(): void
    {
        $store = $this->store();

        self::assertTrue($store->participatesIn(self::CONNECTION));

        try {
            $this->storageConnection()->transaction(function (Connection $connection) use ($store): never {
                $store->store($this->finaliser()->finalise(RecordFactory::captured(id: self::ID)));

                self::assertSame(1, $connection->table(EntrySettings::table())->where('id', self::ID)->count());

                throw new \RuntimeException('The business change failed.');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('The business change failed.', $exception->getMessage());
        }

        self::assertSame(0, $this->entryCount());
    }

    /**
     * Rows of `[connection]`: names that are not the storage connection, one
     * differing only in case and a selector Laravel would normalise among them,
     * since the name is compared exactly.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOtherConnections(): iterable
    {
        yield from [
            'another'         => [self::AUDIT_CONNECTION],
            'an empty name'   => [''],
            'upper case'      => ['TESTING'],
            'with a selector' => ['testing::write'],
            'with a space'    => ['testing '],
        ];
    }

    /**
     * It joins a transaction on no connection but the storage connection.
     *
     * @param  string  $connection
     * @return void
     */
    #[DataProvider('provideOtherConnections')]
    public function testParticipatesInNothingElse(string $connection): void
    {
        self::assertFalse($this->store()->participatesIn($connection));
    }

    /**
     * With a storage connection configured, it joins a transaction on that
     * connection, and no longer on the default one; an empty setting means the
     * default connection again.
     *
     * @return void
     */
    public function testFollowsAConfiguredStorageConnection(): void
    {
        $store = $this->store();

        $this->useAnotherStorageConnection();

        self::assertTrue($store->participatesIn(self::AUDIT_CONNECTION));
        self::assertFalse($store->participatesIn(self::CONNECTION));

        app(ConfigRepository::class)->set('audit-log.storage.connection', '');

        self::assertTrue($store->participatesIn(self::CONNECTION));
        self::assertFalse($store->participatesIn(self::AUDIT_CONNECTION));
    }

    /**
     * A malformed storage setting fails closed rather than naming a connection
     * the store would not write to.
     *
     * @return void
     */
    public function testAMalformedStorageSettingIsRefused(): void
    {
        $store = $this->store();

        app(ConfigRepository::class)->set('audit-log.storage.connection', ['testing']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.storage.connection` must be a connection name, or null or empty for the default connection.');

        $store->participatesIn(self::CONNECTION);
    }

    /**
     * Through a read/write split whose replica opens read-only, a write to the
     * replica is refused, and the store's insert still succeeds, on the primary
     * alone, because it goes to the writer.
     *
     * @return void
     */
    public function testReplicaWriteIsRefused(): void
    {
        $this->useReadWriteSplit();
        $this->makeTheReplicaReadOnly();

        $split = DB::connection(self::SPLIT_CONNECTION);

        try {
            $split->getReadPdo()->exec('delete from ' . EntrySettings::table());

            self::fail('Expected the replica to refuse a write.');
        } catch (\PDOException $exception) {
            self::assertStringContainsString('readonly', $exception->getMessage());
        }

        $this->store()->store($this->finaliser()->finalise(RecordFactory::captured(id: self::ID)));

        self::assertTrue($this->store()->participatesIn(self::SPLIT_CONNECTION));
        self::assertSame(1, DB::connection(self::PRIMARY_CONNECTION)->table(EntrySettings::table())->where('id', self::ID)->count());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table(EntrySettings::table())->count());
    }

    /**
     * Make a second connection to the worker's database, configured as the test
     * connection is, the storage connection.
     *
     * @return void
     */
    private function useAnotherStorageConnection(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::AUDIT_CONNECTION, $config->array('database.connections.' . self::CONNECTION));
        $config->set('audit-log.storage.connection', self::AUDIT_CONNECTION);
    }

    /**
     * Reopen the split's replica read-only, so any write it is sent fails.
     *
     * @return void
     */
    private function makeTheReplicaReadOnly(): void
    {
        $config = app(ConfigRepository::class);
        $key    = 'database.connections.' . self::SPLIT_CONNECTION . '.read.options';

        $config->set($key, [\PDO::SQLITE_ATTR_OPEN_FLAGS => \PDO::SQLITE_OPEN_READONLY]);

        DB::purge(self::SPLIT_CONNECTION);
    }
}
