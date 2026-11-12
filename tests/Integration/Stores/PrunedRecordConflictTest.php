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
 * Integration tests for the store's conflicts against pruned records'
 * tombstones; a test-only `request_id` unique index gives the other violation.
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
     * A pruned record whose insert violates another index is already pruned.
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
     * Inside a host a pruned id is already pruned, and the host goes on.
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
     * A pruned bundle is already pruned, its artifact insert rolled back.
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
     * Any other violation still propagates the insert's own exception.
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
     * A deleted unsealed record is no tombstone: its violation propagates.
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
     * A fresh insert of a pruned id violates nothing, so it is stored.
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
     * Store, seal and prune the record as retention would, keeping its seal.
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
