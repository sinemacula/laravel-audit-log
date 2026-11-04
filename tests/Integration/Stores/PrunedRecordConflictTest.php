<?php

declare(strict_types = 1);

namespace Tests\Integration\Stores;

use Illuminate\Database\UniqueConstraintViolationException;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RecordConflictException;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\PrunesByHand;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for the store's conflict path against the tombstones of
 * pruned records, on whichever engine the suite runs against: an insert that
 * violates a unique index while nothing is stored under the record's ids is
 * `RecordConflictException::alreadyPruned()` when retention pruned the record,
 * a bundle's as a record's, and inside a host transaction too, which stays
 * usable; any other violation still propagates the insert's own exception; and
 * a fresh insert of a pruned id violates nothing, so it is not refused here.
 *
 * A unique index on `request_id`, which the shipped table does not have, makes
 * the violation of an index other than the id's. A test prunes a record as
 * retention does: its entry and its artifact are deleted, and its seal and its
 * member are kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAuditStore::class)]
#[CoversClass(PruneTombstones::class)]
final class PrunedRecordConflictTest extends TestCase
{
    use InteractsWithAuditStore, PrunesByHand, SealsEntries;

    /** @var string When every record is sealed: after each was recorded. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string The request id the pruned record and the record stored after it share. */
    private const string REQUEST_ID = 'req-1';

    /**
     * Add the unique index on `request_id`.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->addRequestIdUniqueIndex();
        $this->sealAt(self::SEALED_AT);
    }

    /**
     * Roll back any transaction a test left open, and drop the index.
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

        $this->removeRequestIdUniqueIndex();

        parent::tearDown();
    }

    /**
     * A pruned record stored again, whose insert violates another unique index
     * because a later record holds its request id, finds nothing under its id
     * and a sealed member with no entry: it is already pruned, never the raw
     * violation, and nothing is stored.
     *
     * @return void
     */
    public function testAUniqueViolationOfAPrunedIdIsAlreadyPruned(): void
    {
        $pruned = $this->prunedRecord(RecordFactory::withFields(['request_id' => self::REQUEST_ID]));

        $this->storeLaterRecordOfTheRequest();

        $this->expectExceptionObject(RecordConflictException::alreadyPruned($pruned->record->id));

        try {
            $this->store()->store($pruned);
        } finally {
            self::assertSame(1, $this->entryCount());
            self::assertSame(0, $this->entriesUnder($pruned->record->id));
        }
    }

    /**
     * Inside a host transaction on the storage connection the insert's
     * savepoint is rolled back before the tombstones are read, so the record is
     * already pruned there too and the host transaction goes on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideAHostTransactionAPrunedIdIsAlreadyPruned(): void
    {
        $pruned     = $this->prunedRecord(RecordFactory::withFields(['request_id' => self::REQUEST_ID]));
        $connection = $this->storageConnection();

        $this->storeLaterRecordOfTheRequest();

        $connection->beginTransaction();

        try {
            $this->store()->store($pruned);

            self::fail('Expected the pruned record to be refused.');
        } catch (RecordConflictException $conflict) {
            self::assertSame($pruned->record->id, $conflict->id);
        }

        self::assertSame(1, $this->entryCount());

        $connection->commit();

        self::assertSame(0, $connection->transactionLevel());
    }

    /**
     * A pruned bundle stored again is refused as already pruned once its
     * entry's insert fails, and its artifact's insert is rolled back with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrunedBundleIsAlreadyPruned(): void
    {
        $bundle = RecordFactory::bundled();
        $pruned = $this->prunedRecord(RecordFactory::withFields(['request_id' => self::REQUEST_ID, 'attachment' => $bundle->attachment], $bundle));

        $this->storeLaterRecordOfTheRequest();

        try {
            $this->store()->store($pruned);

            self::fail('Expected the pruned bundle to be refused.');
        } catch (RecordConflictException $conflict) {
            self::assertSame(RecordConflictException::alreadyPruned($pruned->record->id)->getMessage(), $conflict->getMessage());
        }

        self::assertSame(0, $this->storageConnection()->table(EntrySettings::artifactsTable())->count());
    }

    /**
     * A violation of another unique index by a record that was never sealed
     * still propagates the insert's own exception, whether or not its entry was
     * ever stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnyOtherViolationStillPropagates(): void
    {
        $this->storeLaterRecordOfTheRequest();

        $fresh = $this->finaliser()->finalise(RecordFactory::withFields(['request_id' => self::REQUEST_ID]));

        try {
            $this->store()->store($fresh);

            self::fail('Expected the request id to be refused.');
        } catch (UniqueConstraintViolationException $exception) {
            self::assertStringStartsWith('insert into', $exception->getSql());
        }

        self::assertSame(1, $this->entryCount());
    }

    /**
     * An unsealed record whose entry was deleted is no tombstone: its violation
     * propagates as any other.
     *
     * @return void
     */
    public function testADeletedUnsealedRecordIsNoTombstone(): void
    {
        $deleted = $this->finaliser()->finalise(RecordFactory::withFields(['request_id' => self::REQUEST_ID]));

        $this->store()->store($deleted);
        $this->deleteEntry($deleted->record->id);
        $this->storeLaterRecordOfTheRequest();

        $this->expectException(UniqueConstraintViolationException::class);

        $this->store()->store($deleted);
    }

    /**
     * A pruned record stored again directly with no violation is inserted: a
     * fresh insert of a pruned id violates no index, so the store cannot see it
     * without a statement on every write, and verification reports it.
     *
     * @return void
     */
    public function testAFreshInsertOfAPrunedIdIsNotRefused(): void
    {
        $pruned = $this->prunedRecord(RecordFactory::captured());

        $this->store()->store($pruned);

        self::assertSame(1, $this->entriesUnder($pruned->record->id));
    }

    /**
     * Finalise the record, store it, seal it and prune it as retention would:
     * its artifact and its entry deleted, its seal and member kept.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function prunedRecord(#[\SensitiveParameter] AuditRecord $record): FinalisedRecord
    {
        $finalised = $this->finaliser()->finalise($record);

        $this->store()->store($finalised);

        self::assertSame(1, $this->sealAll()->entries());

        $this->storageConnection()->table(EntrySettings::artifactsTable())->where('entry_id', $finalised->record->id)->delete();
        $this->pruneByHand($finalised->record->id);

        return $finalised;
    }

    /**
     * Store a later record of the same request, which takes the request id.
     *
     * @return void
     */
    private function storeLaterRecordOfTheRequest(): void
    {
        $this->store()->store($this->finaliser('2026-11-01 13:10:00.000000')->finalise(RecordFactory::withFields(['request_id' => self::REQUEST_ID])));
    }

    /**
     * Delete the entry under the id, which must be there.
     *
     * @param  string  $id
     * @return void
     */
    private function deleteEntry(string $id): void
    {
        self::assertSame(1, $this->storageConnection()->table(EntrySettings::table())->where('id', $id)->delete());
    }

    /**
     * The number of entries under the id.
     *
     * @param  string  $id
     * @return int
     */
    private function entriesUnder(string $id): int
    {
        return $this->storageConnection()->table(EntrySettings::table())->where('id', $id)->count();
    }
}
