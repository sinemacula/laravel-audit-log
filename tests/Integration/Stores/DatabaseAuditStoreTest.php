<?php

declare(strict_types = 1);

namespace Tests\Integration\Stores;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\PruneCoverage;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones;
use SineMacula\Laravel\AuditLog\Privacy\Minimised;
use SineMacula\Laravel\AuditLog\Records\Attachment;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RecordConflictException;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\PrunesByHand;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for the database store on the suite's engine.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAuditStore::class)]
final class DatabaseAuditStoreTest extends TestCase
{
    use InteractsWithAuditStore, MockeryPHPUnitIntegration, PrunesByHand, SealsEntries;

    /** @var string The id records are pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string A table the host transaction writes to. */
    private const string HOST_TABLE = 'audit_host_writes';

    /** @var string A table of the application's own for the entries. */
    private const string CUSTOM_TABLE = 'tenant_audit_entries';

    /** @var string Absolute path to the shipped entries migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000000_create_audit_log_entries_table.php';

    /** @var string The first key's secret, as its own 32 bytes. */
    private const string FIRST_SECRET = 'audit store first key secret 32!';

    /** @var string The second key's secret, as its own 32 bytes. */
    private const string SECOND_SECRET = 'audit store second key secret32!';

    /** @var string The key the first and third envelopes of an encrypted record name. */
    private const string FIRST_KEY = '01932b4e-8a40-7000-8000-0000000000a1';

    /** @var string The key the second envelope of an encrypted record names. */
    private const string SECOND_KEY = '01932b4e-8a40-7000-8000-0000000000a2';

    /** @var int The most bytes a bundle's manifest holds. */
    private const int BULK_MAX_BYTES = 65536;

    /** @var string A table that does not exist. */
    private const string MISSING_TABLE = 'audit_missing_key_uses';

    /**
     * Create the table the host transaction writes to.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::dropIfExists(self::HOST_TABLE);

        Schema::create(self::HOST_TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('name', 32);
        });
    }

    /**
     * Roll back any open transaction and drop what the test added.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = $this->storageConnection();

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        $this->removeProbeTable();
        $this->removeRequestIdUniqueIndex();

        Schema::dropIfExists(self::HOST_TABLE);
        Schema::dropIfExists(self::CUSTOM_TABLE);

        parent::tearDown();
    }

    /**
     * A finalised record is stored as one row that decodes to its envelope.
     *
     * @return void
     */
    public function testStoresTheFinalisedRecordAsOneRow(): void
    {
        $finalised = $this->finalised();

        $this->store()->store($finalised);

        $stored   = $this->storedRow(self::ID);
        $envelope = $finalised->toArray();

        self::assertSame(1, $this->entryCount());
        self::assertSame(array_keys($envelope), array_keys($stored));
        self::assertSame(CanonicalEncoder::encode($envelope), CanonicalEncoder::encode($stored));
        self::assertSame(array_diff_key($envelope, ['context' => true, 'properties' => true]), array_diff_key($stored, ['context' => true, 'properties' => true]));
        self::assertTrue(app(RecordSigner::class)->verifies($stored));
    }

    /**
     * An imported record keeps its source digest and re-stores as the same row.
     *
     * @return void
     */
    public function testStoresAnImportedRecordWithItsSourceDigest(): void
    {
        $finalised = $this->finaliser()->finalise(RecordFactory::imported(origin: null));
        $id        = $finalised->record->id;

        $this->store()->store($finalised);
        $this->store()->store($finalised);

        $stored = $this->storedRow($id);

        self::assertSame(1, $this->entryCount());
        self::assertSame(RecordFactory::source()->sourceDigest, $stored['source_digest']);
        self::assertSame(['imported', 'legacy-app', 'eu-west-1', 'legacy-0042', RecordFactory::IMPORT_BATCH_ID, null], [
            $stored['provenance'], $stored['source_id'], $stored['source_region'], $stored['source_record_id'], $stored['import_batch_id'], $stored['origin'],
        ]);
        self::assertSame(CanonicalEncoder::encode($finalised->toArray()), CanonicalEncoder::encode($stored));
        self::assertTrue(app(RecordSigner::class)->verifies($stored));
        self::assertFalse(app(RecordSigner::class)->verifies(['source_digest' => str_repeat('0', 64)] + $stored));
    }

    /**
     * Outside a transaction the store opens none.
     *
     * @return void
     */
    public function testOutsideATransactionTheStoreOpensNone(): void
    {
        $began  = 0;
        $levels = [];

        Event::listen(TransactionBeginning::class, static function () use (&$began): void {
            $began++;
        });

        $this->storageConnection()->beforeExecuting(static function (string $query, array $bindings, $connection) use (&$levels): void {
            $levels[] = $connection->transactionLevel();
        });

        $this->store()->store($this->finalised());

        self::assertSame(0, $began);
        self::assertSame([0], $levels);
        self::assertSame(0, $this->storageConnection()->transactionLevel());
        self::assertSame(1, $this->entryCount());
    }

    /**
     * A record without an attachment is one insert, never touching artifacts.
     *
     * @return void
     */
    public function testARecordWithoutAnAttachmentIsStillOneInsert(): void
    {
        $connection = $this->storageConnection();
        $statements = [];
        $began      = 0;

        Event::listen(TransactionBeginning::class, static function () use (&$began): void {
            $began++;
        });

        $connection->beforeExecuting(static function (string $query) use (&$statements): void {
            $statements[] = $query;
        });

        $this->store()->store($this->finalised());

        self::assertCount(1, $statements);
        self::assertStringStartsWith('insert into', $statements[0]);
        self::assertStringContainsString(EntrySettings::table(), $statements[0]);
        self::assertStringNotContainsString(EntrySettings::artifactsTable(), $statements[0]);
        self::assertSame(0, $began);
        self::assertSame(1, $this->entryCount());
        self::assertSame(0, $connection->table(EntrySettings::artifactsTable())->count());
    }

    /**
     * Inside a host transaction the insert runs in a savepoint.
     *
     * @return void
     */
    public function testInsideATransactionTheInsertRunsInASavepoint(): void
    {
        $connection = $this->storageConnection();
        $inserts    = [];

        $connection->beforeExecuting(static function (string $query, array $bindings, $connection) use (&$inserts): void {
            if (!str_starts_with($query, 'insert into')) {
                return;
            }

            $inserts[] = $connection->transactionLevel();
        });

        $connection->beginTransaction();
        $connection->beginTransaction();

        $this->store()->store($this->finalised());

        self::assertSame([3], $inserts);
        self::assertSame(2, $connection->transactionLevel());

        $connection->commit();
        $connection->commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * The same finalised record stored twice is one row, kept as first stored.
     *
     * @return void
     */
    public function testTheSameRecordStoredTwiceIsOneRow(): void
    {
        $finalised = $this->finalised();

        $this->store()->store($finalised);

        $first = $this->storedRow(self::ID);

        $this->store()->store($finalised);

        self::assertSame(1, $this->entryCount());
        self::assertSame(CanonicalEncoder::encode($first), CanonicalEncoder::encode($this->storedRow(self::ID)));
    }

    /**
     * The same content finalised later keeps the first row, time and HMAC.
     *
     * @return void
     */
    public function testTheSameContentWithADifferentRecordedAtKeepsTheFirstRow(): void
    {
        $record = RecordFactory::captured(id: self::ID);
        $first  = $this->finaliser('2026-11-01 12:00:00.200000')->finalise($record);
        $later  = $this->finaliser('2026-11-01 12:00:05.000000')->finalise($record);

        $this->store()->store($first);
        $this->store()->store($later);

        $stored = $this->storedRow(self::ID);

        self::assertNotSame($first->hmac, $later->hmac);
        self::assertSame(1, $this->entryCount());
        self::assertSame('2026-11-01T12:00:00.200000Z', $stored['recorded_at']);
        self::assertSame($first->hmac, $stored['hmac']);
    }

    /**
     * The same content signed under another key keeps the first row.
     *
     * @return void
     */
    public function testTheSameContentSignedWithAnotherKeyKeepsTheFirstRow(): void
    {
        $record = RecordFactory::captured(id: self::ID);

        $this->useRing(['k1' => self::FIRST_SECRET, 'k2' => self::SECOND_SECRET], 'k1');

        $first = $this->finaliser()->finalise($record);

        $this->store()->store($first);

        $this->useRing(['k1' => self::FIRST_SECRET, 'k2' => self::SECOND_SECRET], 'k2');

        $second = $this->finaliser()->finalise($record);

        $this->store()->store($second);

        $stored = $this->storedRow(self::ID);

        self::assertSame('k2', $second->keyId);
        self::assertSame(1, $this->entryCount());
        self::assertSame('k1', $stored['key_id']);
        self::assertSame($first->hmac, $stored['hmac']);
    }

    /**
     * Different content under the same id is a conflict; the first row stays.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDifferentContentUnderTheSameIdIsAConflict(): void
    {
        $first = $this->finaliser()->finalise(RecordFactory::captured(['amount' => '1200.00'], self::ID));
        $other = $this->finaliser()->finalise(RecordFactory::captured(['amount' => '1200.01'], self::ID));

        $this->store()->store($first);

        try {
            $this->store()->store($other);

            self::fail('Expected the record to conflict.');
        } catch (RecordConflictException $exception) {
            self::assertSame('An audit entry with id ' . self::ID . ' already exists with different captured content.', $exception->getMessage());
            self::assertSame(self::ID, $exception->id);
        }

        self::assertSame(1, $this->entryCount());
        self::assertSame($first->hmac, $this->storedRow(self::ID)['hmac']);
        self::assertEquals((object) ['amount' => '1200.00'], $this->storedRow(self::ID)['properties']);
    }

    /**
     * A tampered row with its old HMAC is a conflict, never a success.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATamperedRowWithItsOldHmacIsAConflict(): void
    {
        $finalised = $this->finalised();

        $this->store()->store($finalised);

        $this->storageConnection()->table(EntrySettings::table())->where('id', self::ID)->update(['properties' => '{"amount":"9999.00"}']);

        try {
            $this->store()->store($finalised);

            self::fail('Expected the tampered row to conflict.');
        } catch (RecordConflictException $exception) {
            self::assertSame('An audit entry with id ' . self::ID . ' already exists, and its stored row fails verification.', $exception->getMessage());
        }

        self::assertSame(1, $this->entryCount());
        self::assertEquals((object) ['amount' => '9999.00'], $this->storedRow(self::ID)['properties']);
    }

    /**
     * A row under an unknown key propagates the ring's `UnknownKeyException`.
     *
     * @return void
     */
    public function testAnExistingRowUnderAnUnknownKeyPropagates(): void
    {
        $record = RecordFactory::captured(id: self::ID);

        $this->useRing(['k1' => self::FIRST_SECRET], 'k1');

        $this->store()->store($this->finaliser()->finalise($record));

        $this->useRing(['k2' => self::SECOND_SECRET], 'k2');

        $this->expectException(UnknownKeyException::class);

        $this->store()->store($this->finaliser()->finalise($record));
    }

    /**
     * A row of an unknown integrity version propagates the signer's exception.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMalformedExistingRowPropagates(): void
    {
        $finalised = $this->finalised();

        $this->store()->store($finalised);

        $this->storageConnection()->table(EntrySettings::table())->where('id', self::ID)->update(['integrity_version' => 2]);

        try {
            $this->store()->store($finalised);

            self::fail('Expected the malformed row to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('Integrity version 2 is not supported by this release.', $exception->getMessage());
        }

        self::assertSame(1, $this->entryCount());
        self::assertSame(2, $this->storedRow(self::ID)['integrity_version']);
    }

    /**
     * A source identity violation propagates the insert's own exception.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASourceIdentityViolationPropagatesTheOriginalException(): void
    {
        $imported = ['provenance' => 'imported', 'source_id' => 'legacy-app', 'source_record_id' => 'legacy-77'];
        $first    = $this->finaliser()->finalise(RecordFactory::withFields($imported));
        $second   = $this->finaliser()->finalise(RecordFactory::withFields($imported));

        $this->store()->store($first);

        self::assertNotSame($first->record->id, $second->record->id);

        try {
            $this->store()->store($second);

            self::fail('Expected the source identity to be refused.');
        } catch (UniqueConstraintViolationException $exception) {
            self::assertStringStartsWith('insert into', $exception->getSql());
            self::assertInstanceOf(\PDOException::class, $exception->getPrevious());
        }

        self::assertSame(1, $this->entryCount());
        self::assertSame($first->hmac, $this->storedRow($first->record->id)['hmac']);
    }

    /**
     * Another unique index's violation propagates the insert's own exception.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAViolationOfAnotherUniqueIndexPropagates(): void
    {
        $this->addRequestIdUniqueIndex();

        $first  = $this->finaliser()->finalise(RecordFactory::withFields(['request_id' => 'req-1']));
        $second = $this->finaliser()->finalise(RecordFactory::withFields(['request_id' => 'req-1']));

        $this->store()->store($first);

        try {
            $this->store()->store($second);

            self::fail('Expected the request id to be refused.');
        } catch (UniqueConstraintViolationException $exception) {
            self::assertStringStartsWith('insert into', $exception->getSql());
        }

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A failed audit insert leaves a healthy host transaction usable.
     *
     * @return void
     */
    public function testAFailedAuditInsertLeavesAHealthyHostTransactionUsable(): void
    {
        $this->pointAtProbeTable();

        $connection = $this->storageConnection();

        $connection->beginTransaction();

        $this->hostWrite('before');

        $failure = $this->failedStore($this->finalised());

        $this->hostWrite('after');

        $connection->commit();

        // A failure before any SQL ran would prove nothing about the savepoint
        self::assertSame(QueryException::class, $failure::class);
        self::assertInstanceOf(QueryException::class, $failure);
        self::assertStringStartsWith('insert into', $failure->getSql());
        self::assertStringContainsString(self::PROBE_TABLE, $failure->getSql());
        self::assertSame(['before', 'after'], $this->hostRows());
        self::assertSame(0, $this->probeCount());
    }

    /**
     * A unique violation inside a host transaction leaves it usable.
     *
     * @return void
     */
    public function testAUniqueViolationInsideAHostTransactionLeavesItUsable(): void
    {
        $this->addRequestIdUniqueIndex();

        $connection = $this->storageConnection();
        $first      = $this->finaliser()->finalise(RecordFactory::withFields(['request_id' => 'req-1']));

        $connection->beginTransaction();

        $this->hostWrite('before');
        $this->store()->store($first);

        $failure = $this->failedStore($this->finaliser()->finalise(RecordFactory::withFields(['request_id' => 'req-1'])));

        $this->hostWrite('after');

        $connection->commit();

        self::assertInstanceOf(UniqueConstraintViolationException::class, $failure);
        self::assertSame(['before', 'after'], $this->hostRows());
        self::assertSame(1, $this->entryCount());
        self::assertSame($first->hmac, $this->storedRow($first->record->id)['hmac']);
    }

    /**
     * A duplicate is resolved after its savepoint rolls back, so the host stays
     * usable even on PostgreSQL.
     *
     * @return void
     */
    public function testADuplicateResolvedInsideAHostTransactionLeavesItUsable(): void
    {
        $committed  = $this->finalised();
        $connection = $this->storageConnection();

        $this->store()->store($committed);

        $connection->beginTransaction();

        $this->hostWrite('before');
        $this->store()->store($committed);

        $within = $this->finaliser()->finalise(RecordFactory::captured(['amount' => '5.00']));

        $this->store()->store($within);
        $this->store()->store($within);

        $this->hostWrite('after');

        $connection->commit();

        self::assertSame(['before', 'after'], $this->hostRows());
        self::assertSame(2, $this->entryCount());
    }

    /**
     * A conflict comes after the savepoint rolls back, leaving the host usable.
     *
     * @return void
     */
    public function testAConflictInsideAHostTransactionLeavesItUsable(): void
    {
        $first      = $this->finaliser()->finalise(RecordFactory::captured(['amount' => '1200.00'], self::ID));
        $connection = $this->storageConnection();

        $this->store()->store($first);

        $connection->beginTransaction();

        $this->hostWrite('before');

        $failure = $this->failedStore($this->finaliser()->finalise(RecordFactory::captured(['amount' => '1.00'], self::ID)));

        $this->hostWrite('after');

        $connection->commit();

        self::assertInstanceOf(RecordConflictException::class, $failure);
        self::assertSame(['before', 'after'], $this->hostRows());
        self::assertSame($first->hmac, $this->storedRow(self::ID)['hmac']);
    }

    /**
     * An aborted PostgreSQL host refuses the savepoint, and that propagates.
     *
     * @return void
     */
    public function testAnAlreadyAbortedPostgresHostTransactionPropagates(): void
    {
        $connection = $this->storageConnection();

        if ($connection->getDriverName() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL aborts a transaction on a failed statement.');
        }

        $connection->beginTransaction();

        $hostFailure = rescue(static fn () => $connection->statement('select * from audit_no_such_table'), static fn (\Throwable $exception): \Throwable => $exception, false);

        $failure = $this->failedStore($this->finalised());

        self::assertInstanceOf(QueryException::class, $hostFailure);
        self::assertInstanceOf(\PDOException::class, $failure);
        self::assertNotInstanceOf(UniqueConstraintViolationException::class, $failure);
        self::assertSame('25P02', $failure->getCode());
        self::assertSame(1, $connection->transactionLevel());

        $connection->rollBack();

        self::assertSame(0, $this->entryCount());
    }

    /**
     * An insert failure propagates unwrapped, with no lookup after it.
     *
     * @return void
     */
    public function testTheStoreCatchesNothingButADuplicate(): void
    {
        $this->pointAtProbeTable();

        $statements = [];

        $this->storageConnection()->beforeExecuting(static function (string $query) use (&$statements): void {
            $statements[] = $query;
        });

        $failure = $this->failedStore($this->finalised());

        self::assertSame(QueryException::class, $failure::class);
        self::assertInstanceOf(QueryException::class, $failure);
        self::assertStringStartsWith('insert into', $failure->getSql());
        self::assertInstanceOf(\PDOException::class, $failure->getPrevious());
        self::assertCount(1, $statements);
        self::assertStringStartsWith('insert into', $statements[0]);
        self::assertSame(0, $this->probeCount());
    }

    /**
     * A duplicate's lookup locks only on MySQL inside a transaction.
     *
     * @return void
     */
    public function testOnlyMySqlInsideATransactionTakesASharedLockOnTheLookup(): void
    {
        $finalised  = $this->finalised();
        $connection = $this->storageConnection();
        $reads      = [];

        $this->store()->store($finalised);

        $connection->beforeExecuting(static function (string $query) use (&$reads): void {
            if (!str_starts_with($query, 'select')) {
                return;
            }

            $reads[] = $query;
        });

        $this->store()->store($finalised);

        $connection->beginTransaction();
        $this->store()->store($finalised);
        $connection->commit();

        self::assertCount(2, $reads);
        self::assertDoesNotMatchRegularExpression('/\b(lock|for share|for update)\b/i', $reads[0]);

        if ($connection->getDriverName() === 'mysql') {
            self::assertStringEndsWith(' lock in share mode', $reads[1]);

            return;
        }

        self::assertDoesNotMatchRegularExpression('/\b(lock|for share|for update)\b/i', $reads[1]);
    }

    /**
     * The store writes where the settings name at the time it is called.
     *
     * @return void
     */
    public function testStoresInTheConfiguredTable(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.entries.table', self::CUSTOM_TABLE);

        $migration = require self::MIGRATION_PATH;

        assert(is_object($migration) && method_exists($migration, 'up'));

        $migration->up();

        $finalised = $this->finalised();

        $this->store()->store($finalised);
        $this->store()->store($finalised);

        self::assertSame(1, $this->storageConnection()->table(self::CUSTOM_TABLE)->count());

        $config->set('audit-log.entries.table', EntrySettings::DEFAULT_TABLE);

        self::assertSame(0, $this->entryCount());
    }

    /**
     * A connection without transaction support is refused before any write.
     *
     * @return void
     */
    public function testAConnectionWithoutTransactionsIsRefused(): void
    {
        $connections = \Mockery::mock(ConnectionResolverInterface::class);

        $connections->shouldReceive('connection')->once()->with(null)->andReturn(\Mockery::mock(ConnectionInterface::class));

        $store = new DatabaseAuditStore($connections, new RowCodec, app(RecordSigner::class), new PruneTombstones($connections, new NullPruneLedger, app(PruneCoverage::class)));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The storage connection [testing] is not a database connection that supports transactions.');

        $store->store($this->finalised());
    }

    /**
     * Rows of `[driver, level, locks]`: when the lookup takes a shared lock.
     *
     * @return iterable<string, array{0: string, 1: int, 2: bool}>
     */
    public static function provideLookupLocks(): iterable
    {
        yield from [
            'MySQL inside a transaction'      => ['mysql', 1, true],
            'MySQL inside a nested one'       => ['mysql', 2, true],
            'MySQL outside a transaction'     => ['mysql', 0, false],
            'PostgreSQL inside a transaction' => ['pgsql', 1, false],
            'SQLite inside a transaction'     => ['sqlite', 1, false],
        ];
    }

    /**
     * The lookup reads the writer and locks only on MySQL in a transaction;
     * SQLite compiles no lock, so the builder is observed.
     *
     * @param  string  $driver
     * @param  int  $level
     * @param  bool  $locks
     * @return void
     */
    #[DataProvider('provideLookupLocks')]
    public function testTheLookupTakesASharedLockOnlyOnMySqlInsideATransaction(string $driver, int $level, bool $locks): void
    {
        $finalised  = $this->finalised();
        $duplicate  = new UniqueConstraintViolationException('testing', 'insert into "audit_log_entries"', [], new \PDOException('duplicate'));
        $builder    = \Mockery::mock(Builder::class);
        $connection = \Mockery::mock(Connection::class);

        $connection->shouldReceive('transactionLevel')->andReturn($level);
        $connection->shouldReceive('getDriverName')->andReturn($driver);
        $connection->shouldReceive('table')->with(EntrySettings::DEFAULT_TABLE)->andReturn($builder);
        $connection->shouldReceive('transaction')->times($level > 0 ? 1 : 0)->andThrow($duplicate);

        $builder->shouldReceive('insert')->times($level > 0 ? 0 : 1)->andThrow($duplicate);
        $builder->shouldReceive('useWritePdo')->once()->andReturnSelf();
        $builder->shouldReceive('where')->once()->with('id', self::ID)->andReturnSelf();
        $builder->shouldReceive('sharedLock')->times($locks ? 1 : 0)->andReturnSelf();
        $builder->shouldReceive('first')->once()->andReturn((object) (new RowCodec)->encode($finalised));

        $connections = \Mockery::mock(ConnectionResolverInterface::class);

        $connections->shouldReceive('connection')->with(null)->andReturn($connection);

        $tombstones = new PruneTombstones($connections, new NullPruneLedger, app(PruneCoverage::class));

        (new DatabaseAuditStore($connections, new RowCodec, app(RecordSigner::class), $tombstones))->store($finalised);
    }

    /**
     * An encrypted record writes its entry and key uses in one transaction.
     *
     * @return void
     */
    public function testAnEncryptedRecordWritesItsKeyUsesWithIt(): void
    {
        $connection = $this->storageConnection();
        $statements = [];
        $began      = 0;

        Event::listen(TransactionBeginning::class, static function () use (&$began): void {
            $began++;
        });

        $connection->beforeExecuting(static function (string $query, array $bindings, $connection) use (&$statements): void {
            $statements[] = [self::tableOf($query), $connection->transactionLevel()];
        });

        $this->store()->store($this->encrypted());

        self::assertSame([[EntrySettings::table(), 1], [KeyTables::keyUsesTable(), 1]], $statements);
        self::assertSame(1, $began);
        self::assertSame(0, $connection->transactionLevel());
        self::assertSame(1, $this->entryCount());
        self::assertSame([[self::FIRST_KEY, self::ID], [self::SECOND_KEY, self::ID]], $this->keyUses());
    }

    /**
     * An envelope with no canonical UUID key has no key use: one insert.
     *
     * @return void
     */
    public function testAnEnvelopeWithoutAUuidKeyKeepsTheSingleInsert(): void
    {
        $statements = [];
        $began      = 0;

        Event::listen(TransactionBeginning::class, static function () use (&$began): void {
            $began++;
        });

        $this->storageConnection()->beforeExecuting(static function (string $query) use (&$statements): void {
            $statements[] = self::tableOf($query);
        });

        $this->store()->store($this->encrypted(['card' => ['v' => 1, 'k' => 'kms:card-key', 'c' => 'c2VhbGVk']]));

        self::assertSame([EntrySettings::table()], $statements);
        self::assertSame(0, $began);
        self::assertSame([], $this->keyUses());
    }

    /**
     * Rows of `[fault, thrown]`: a missing table, and an existing key use.
     *
     * @return iterable<string, array{0: string, 1: class-string<\Throwable>}>
     */
    public static function provideKeyUseFailures(): iterable
    {
        yield from [
            'a missing table'        => ['missing', QueryException::class],
            'a key use stored first' => ['stored', UniqueConstraintViolationException::class],
        ];
    }

    /**
     * A failed key use rolls back the entry and omits the record's bindings.
     *
     * @param  string  $fault
     * @param  class-string<\Throwable>  $thrown
     * @return void
     */
    #[DataProvider('provideKeyUseFailures')]
    public function testAFailedKeyUseRollsTheEntryBack(string $fault, string $thrown): void
    {
        if ($fault === 'missing') {
            app(ConfigRepository::class)->set('audit-log.privacy.key_uses_table', self::MISSING_TABLE);
        } else {
            $this->storageConnection()->table(KeyTables::keyUsesTable())->insert(['key_id' => self::SECOND_KEY, 'entry_id' => self::ID]);
        }

        $exception = $this->failedStore($this->encrypted());

        self::assertInstanceOf($thrown, $exception);
        self::assertStringNotContainsString(self::ID, $exception->getMessage());
        self::assertSame(0, $this->entryCount());
        self::assertSame(0, $this->storageConnection()->transactionLevel());
    }

    /**
     * Inside a host the entry and its key uses share one savepoint.
     *
     * @return void
     */
    public function testInsideAHostTheKeyUsesShareTheSavepoint(): void
    {
        $connection = $this->storageConnection();
        $inserts    = [];
        $began      = 0;

        $connection->beginTransaction();
        $connection->beginTransaction();

        $this->hostWrite('before');

        Event::listen(TransactionBeginning::class, static function () use (&$began): void {
            $began++;
        });

        $connection->beforeExecuting(static function (string $query, array $bindings, $connection) use (&$inserts): void {
            $inserts[] = [self::tableOf($query), $connection->transactionLevel()];
        });

        $this->store()->store($this->encrypted());

        self::assertSame([[EntrySettings::table(), 3], [KeyTables::keyUsesTable(), 3]], $inserts);
        self::assertSame(1, $began);
        self::assertSame(2, $connection->transactionLevel());

        $connection->rollBack();
        $connection->rollBack();

        self::assertSame(0, $this->entryCount());
        self::assertSame([], $this->keyUses());
        self::assertSame([], $this->hostRows());
    }

    /**
     * The same encrypted record stored twice keeps one entry and its key uses.
     *
     * @return void
     */
    public function testTheSameEncryptedRecordStoredTwiceIsOneRowWithItsKeyUses(): void
    {
        $finalised = $this->encrypted();

        $this->store()->store($finalised);
        $this->store()->store($finalised);

        self::assertSame(1, $this->entryCount());
        self::assertSame([[self::FIRST_KEY, self::ID], [self::SECOND_KEY, self::ID]], $this->keyUses());
    }

    /**
     * A bundle holding an envelope writes its artifact, entry and key uses in
     * one transaction.
     *
     * @return void
     */
    public function testABundleHoldingAnEnvelopeWritesItsArtifactEntryAndKeyUses(): void
    {
        $finalised  = $this->finaliser()->finalise(self::bundleHolding(['v' => 1, 'k' => self::FIRST_KEY, 'c' => 'c2VhbGVk']));
        $statements = [];
        $began      = 0;

        Event::listen(TransactionBeginning::class, static function () use (&$began): void {
            $began++;
        });

        $this->storageConnection()->beforeExecuting(static function (string $query) use (&$statements): void {
            $statements[] = self::tableOf($query);
        });

        $this->store()->store($finalised);

        self::assertSame([EntrySettings::artifactsTable(), EntrySettings::table(), KeyTables::keyUsesTable()], $statements);
        self::assertSame(1, $began);
        self::assertSame([[self::FIRST_KEY, $finalised->record->id]], $this->keyUses());
    }

    /**
     * A pruned encrypted record is refused as pruned, as its key uses remain.
     *
     * @return void
     */
    public function testAPrunedIdWithSurvivingKeyUsesIsAlreadyPruned(): void
    {
        $finalised = $this->encrypted();

        $this->store()->store($finalised);
        $this->sealAt('2026-11-01 12:30:00');

        self::assertSame(1, $this->sealAll()->entries());

        $this->pruneByHand(self::ID);

        $exception = $this->failedStore($finalised);

        self::assertInstanceOf(RecordConflictException::class, $exception);
        self::assertSame('The record `' . self::ID . '` was pruned; it is not stored again.', $exception->getMessage());
        self::assertSame(0, $this->entryCount());
        self::assertSame([[self::FIRST_KEY, self::ID], [self::SECOND_KEY, self::ID]], $this->keyUses());
    }

    /**
     * An approved invoice under the pinned id, finalised on the frozen clock.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function finalised(): FinalisedRecord
    {
        return $this->finaliser()->finalise(RecordFactory::captured(id: self::ID));
    }

    /**
     * Store the record, which must fail, and return what it threw.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return \Throwable
     */
    private function failedStore(FinalisedRecord $record): \Throwable
    {
        try {
            $this->store()->store($record);
        } catch (\Throwable $exception) {
            return $exception;
        }

        self::fail('Expected the store to fail.');
    }

    /**
     * The record holding the envelopes, by default three naming two keys.
     *
     * @param  ?array<string, array{v: int, k: string, c: string}>  $envelopes
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function encrypted(?array $envelopes = null): FinalisedRecord
    {
        $envelopes ??= [
            'card'  => ['v' => 1, 'k' => self::FIRST_KEY, 'c' => 'c2VhbGVkLWNhcmQ'],
            'iban'  => ['v' => 1, 'k' => self::SECOND_KEY, 'c' => 'c2VhbGVkLWliYW4'],
            'payee' => ['v' => 1, 'k' => self::FIRST_KEY, 'c' => 'c2VhbGVkLXBheWVl'],
        ];

        return $this->finaliser()->finalise(RecordFactory::captured(['amount' => '1200.00', ...$envelopes], self::ID));
    }

    /**
     * Every stored key use, as its key and entry, sorted.
     *
     * @return list<array{0: string, 1: string}>
     */
    private function keyUses(): array
    {
        $rows = $this->storageConnection()->table(KeyTables::keyUsesTable())->orderBy('key_id')->orderBy('entry_id')->get();

        return array_values(array_map(static fn (object $row): array => [(string) $row->key_id, (string) $row->entry_id], $rows->all()));
    }

    /**
     * A bulk record of three invoices holding the envelope as its card.
     *
     * @param  array{v: int, k: string, c: string}  $envelope
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function bundleHolding(array $envelope): AuditRecord
    {
        $manifest = Manifest::of(RecordFactory::members(3), 3, self::BULK_MAX_BYTES);
        $pending  = (new PendingRecord)->event('invoice.bulk_approved')->by(Reference::of('user', '42'))->withManifest($manifest);
        $id       = Str::uuid7()->toString();

        $pending->fillOrigin(Origin::HTTP);

        // Minimising strips sealed fields, so the envelope goes on what it left
        $minimised  = RecordFactory::minimisedOf($pending, null, $id);
        $minimised  = new Minimised(['card' => $envelope, ...$minimised->properties ?? []], $minimised->context, $minimised->ip);
        $attachment = Attachment::sealed($manifest, RecordFactory::encrypter());

        return AuditRecord::fromPending($pending, $minimised, $id, 1, 'finance', new \DateTimeImmutable(RecordFactory::OCCURRED_AT), 'app-eu-1', null, $attachment);
    }

    /**
     * The package table an insert writes to, or the statement itself otherwise.
     *
     * @param  string  $query
     * @return string
     */
    private static function tableOf(string $query): string
    {
        foreach ([EntrySettings::artifactsTable(), KeyTables::keyUsesTable(), EntrySettings::table()] as $table) {
            if (str_starts_with($query, 'insert into') && str_contains($query, $table)) {
                return $table;
            }
        }

        return $query;
    }

    /**
     * Write a row to the host's table on the storage connection.
     *
     * @param  string  $name
     * @return void
     */
    private function hostWrite(string $name): void
    {
        $this->storageConnection()->table(self::HOST_TABLE)->insert(['name' => $name]);
    }

    /**
     * The names in the host's table, in the order they were written.
     *
     * @return list<string>
     */
    private function hostRows(): array
    {
        /** @var list<string> */
        return $this->storageConnection()->table(self::HOST_TABLE)->orderBy('id')->pluck('name')->all();
    }
}
