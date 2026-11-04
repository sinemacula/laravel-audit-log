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
 * Integration tests for the database store on the engine the suite runs
 * against: one plain insert of the finalised record, alone outside a
 * transaction and in a savepoint inside one; a duplicate resolved to success
 * only when the existing row verifies with the same captured content, to a
 * conflict when it does not, and propagated when it cannot be verified or no
 * row holds the id; a record without an attachment written as before, never
 * touching the artifacts table; and a host transaction left usable by one
 * failed audit statement; and an imported record stored with its source digest;
 * and a record holding an envelope written with its key uses in one transaction
 * or savepoint, rolled back whole when they fail, and refused as already pruned
 * when its key uses outlived its entry, on SQLite, MySQL and PostgreSQL alike.
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
     * Roll back any transaction a failed test left open, then drop what the
     * test added: the host table, the probe table, the custom table and the
     * test-only index.
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
     * A finalised record is stored as one row, which decodes to its envelope:
     * every column, in table order, with the same canonical encoding.
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
     * An imported record is stored as one row with its source fields and its
     * source digest, which the engine returns as written and the row's
     * signature covers; storing it again is the same row, never a conflict.
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
     * Outside a transaction the store opens none: no transaction begins, and
     * the connection is at level 0 throughout.
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
     * A record without an attachment is still one insert into the entries
     * table, and outside a transaction the store opens none for it: nothing is
     * read from or written to the artifacts table.
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
     * Inside a host transaction the insert runs one level deeper, in a
     * savepoint, and the host is back at its own level once it succeeds; the
     * row is the host's to commit.
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
     * The same captured record finalised again later, so with another
     * `recorded_at` and HMAC, is the record stored already: the first row is
     * kept, its time and HMAC included.
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
     * The same captured record signed again after the ring's current key moved
     * is the record stored already: the first row is kept under the first key.
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
     * Another captured record under the same id, with different properties, is
     * a conflict naming the id, and the first row is left as it was.
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
     * A stored row whose properties were edited with its old HMAC left in place
     * fails verification, so storing the same record again is a conflict, and
     * never a success that would vouch for the edit.
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
     * An existing row signed under a key the ring no longer holds cannot be
     * verified, so the ring's `UnknownKeyException` propagates unchanged.
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
     * An existing row with an integrity version this release does not verify
     * cannot be judged: the signer's `\UnexpectedValueException` propagates,
     * never a success, and the row is left as it was.
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
     * Two imported records with distinct ids and one source identity violate
     * the source-identity index: no row holds the second's id, so the insert's
     * own `UniqueConstraintViolationException` propagates, and the first row is
     * the only one.
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
     * A violation of a unique index other than the id's, with no row under the
     * record's id, propagates the insert's own exception.
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
     * Inside a healthy host transaction an audit insert that fails on the probe
     * table's `NOT NULL` column propagates the engine's `QueryException`, and
     * the host writes again and commits: both host rows exist, and the probe
     * table holds nothing.
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

        // The failure is the probe insert itself, so the host transaction saw a
        // failed statement: one thrown before any SQL ran would prove nothing
        // about the savepoint
        self::assertSame(QueryException::class, $failure::class);
        self::assertInstanceOf(QueryException::class, $failure);
        self::assertStringStartsWith('insert into', $failure->getSql());
        self::assertStringContainsString(self::PROBE_TABLE, $failure->getSql());
        self::assertSame(['before', 'after'], $this->hostRows());
        self::assertSame(0, $this->probeCount());
    }

    /**
     * Inside a healthy host transaction a unique violation of another index
     * propagates, and the host keeps the record it stored before, writes again
     * and commits.
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
     * Inside a healthy host transaction a duplicate is resolved after its
     * savepoint is rolled back, so even on PostgreSQL the lookup runs in a
     * usable transaction, and the host writes again and commits; whether the
     * first row was committed before the host began or stored within it.
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
     * Inside a healthy host transaction a conflict is raised after the
     * savepoint is rolled back, so the host writes again and commits, and the
     * first row is left as it was.
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
     * On PostgreSQL a host transaction a failed host statement already aborted
     * stays aborted: the store's savepoint is refused, and that refusal
     * propagates as the driver raised it, neither masked as a duplicate nor
     * resolved; the host is left at its own level, to roll back.
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
     * Outside a transaction an insert that fails on the probe table's `NOT
     * NULL` column propagates exactly the `QueryException` the connection
     * threw, unwrapped, and no lookup follows it.
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
     * Outside a transaction a duplicate's lookup takes no lock, on every
     * engine; inside one it takes MySQL's shared lock, and no lock elsewhere.
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
     * The store writes to the table and connection the settings name when it is
     * called, so a table of the application's own holds the record and the
     * shipped one holds nothing.
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
     * A storage connection that is not a database connection supporting
     * transactions is refused before anything is written, naming the
     * connection.
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
     * Rows of `[driver, transaction level, whether the lookup takes a shared
     * lock]`: MySQL inside a transaction, and every case that takes none.
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
     * The duplicate's lookup reads the writer and takes a shared lock exactly
     * when the connection is MySQL's and a transaction is open, whatever engine
     * the suite runs on (SQLite compiles no lock, so the builder is observed
     * instead of the statement).
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
     * A record holding envelopes is written with its key uses, one for each
     * distinct key, in one transaction of its own: its entry's insert, then its
     * key uses' one insert, both inside the transaction, which commits.
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
     * An envelope whose key is not a canonical lower-case UUID has no key use,
     * so a record holding only such envelopes keeps its single insert, outside
     * any transaction.
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
     * Rows of `[what fails, the failure the store throws]`: the key uses'
     * insert refused by a missing table, and by a key use already stored for
     * the entry, which no pruned record explains.
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
     * A key use that fails rolls the entry back with it, so no entry is kept
     * without its key uses, and the failure propagates without a binding of the
     * record in its message.
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
     * Inside a host transaction the entry and its key uses are written in the
     * one savepoint, one level deeper than the host, which is back at its own
     * level once they succeed; the host's rollback takes both with it.
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
     * The same encrypted record stored twice is one entry with its key uses
     * once: the second's insert is refused, rolled back, and resolved to the
     * entry already stored.
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
     * A bulk record holding an envelope writes its artifact, its entry and its
     * key uses, in that order, in one transaction.
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
     * Retention leaves a pruned entry's key uses, so an encrypted record stored
     * again once pruned violates their key: the store finds the record in a
     * seal with its entry gone and refuses it as already pruned, storing
     * nothing and leaving the key uses as they were.
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
     * The captured record of an approved invoice under the pinned id, finalised
     * on the frozen clock.
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
     * The captured record under the pinned id holding the envelopes given, by
     * default three naming two keys, one of them twice, finalised on the frozen
     * clock.
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
     * A captured bulk record of three approved invoices holding the envelope as
     * its card, carrying its manifest sealed under the test encrypter.
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

        // The envelope stands for a field the record's own sealer sealed, which
        // minimising removes from what a record is given, so it is set on what
        // minimising left, before the package's metadata
        $minimised  = RecordFactory::minimisedOf($pending, null, $id);
        $minimised  = new Minimised(['card' => $envelope, ...$minimised->properties ?? []], $minimised->context, $minimised->ip);
        $attachment = Attachment::sealed($manifest, RecordFactory::encrypter());

        return AuditRecord::fromPending($pending, $minimised, $id, 1, 'finance', new \DateTimeImmutable(RecordFactory::OCCURRED_AT), 'app-eu-1', null, $attachment);
    }

    /**
     * The package table an insert writes to, or the statement itself when it is
     * anything else.
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
