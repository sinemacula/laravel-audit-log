<?php

declare(strict_types = 1);

namespace Tests\Integration\Stores;

use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RecordConflictException;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for a bulk record's bundle in the database store, on the
 * engine the suite runs against: its artifact and its entry written together,
 * artifact first, in one transaction outside a host and one savepoint inside
 * one, so a failure between the inserts or a host's rollback leaves neither; a
 * duplicate resolved to a success only when its entry is the record's and its
 * artifact the bundle's, by everything but the sealed members, and to a
 * conflict when either is missing or different; and the ids and the time the
 * artifact is stored with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAuditStore::class)]
final class BundleAtomicityTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string An id no artifact or entry of the tests is stored under. */
    private const string OTHER_ID = '01932b4e-8a40-7000-8000-0000000000aa';

    /** @var string A lower-case UUID as every engine returns it. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string The refusal of a bundle stored with another artifact, or without its own, for the id. */
    private const string DIFFERENT_ARTIFACT = 'The record %s is stored with another artifact, or without its own.';

    /**
     * Roll back any transaction a failed test left open.
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

        parent::tearDown();
    }

    /**
     * A bundle is stored as its entry, which verifies, and its artifact, which
     * holds the attachment as it was sealed, naming the entry; the artifact is
     * inserted first, and outside a host the store opens one transaction of its
     * own for both.
     *
     * @return void
     */
    public function testABundleWritesTheArtifactAndTheEntryTogether(): void
    {
        $bundle  = $this->bundle();
        $inserts = [];
        $began   = 0;

        Event::listen(TransactionBeginning::class, static function () use (&$began): void {
            $began++;
        });

        $this->storageConnection()->beforeExecuting(static function (string $query, array $bindings, $connection) use (&$inserts): void {
            if (!str_starts_with($query, 'insert into')) {
                return;
            }

            $inserts[] = [self::tableOf($query), $connection->transactionLevel()];
        });

        $this->store()->store($bundle);

        self::assertSame([[EntrySettings::artifactsTable(), 1], [EntrySettings::table(), 1]], $inserts);
        self::assertSame(1, $began);
        self::assertSame(0, $this->storageConnection()->transactionLevel());
        self::assertSame(1, $this->entryCount());
        self::assertSame(1, $this->artifactCount());
        self::assertTrue(app(RecordSigner::class)->verifies($this->storedRow($bundle->record->id)));
        self::assertSame(self::expectedArtifact($bundle), $this->storedArtifact(self::attachmentId($bundle)));
    }

    /**
     * A failure of the entry's insert, after the artifact's succeeded, rolls
     * the artifact back: the failure propagates, and neither row is kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureBetweenTheInsertsLeavesNeither(): void
    {
        $this->failTheEntryInsert();

        try {
            $this->store()->store($this->bundle());

            self::fail('Expected the entry insert to fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The entry insert failed.', $exception->getMessage());
        }

        self::assertSame(0, $this->storageConnection()->transactionLevel());
        self::assertSame(0, $this->entryCount());
        self::assertSame(0, $this->artifactCount());
    }

    /**
     * Inside a host transaction a failure between the inserts rolls back the
     * bundle's savepoint alone: the host is at its own level, neither row is
     * kept, and the host goes on to store a record and commit it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureBetweenTheInsertsInsideAHostLeavesItUsable(): void
    {
        $connection = $this->storageConnection();
        $record     = $this->finaliser()->finalise(RecordFactory::captured(id: self::OTHER_ID));

        $connection->beginTransaction();

        $this->failTheEntryInsert(once: true);

        try {
            $this->store()->store($this->bundle());

            self::fail('Expected the entry insert to fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The entry insert failed.', $exception->getMessage());
        }

        self::assertSame(1, $connection->transactionLevel());

        $this->store()->store($record);

        $connection->commit();

        self::assertSame(1, $this->entryCount());
        self::assertSame(0, $this->artifactCount());
        self::assertSame($record->hmac, $this->storedRow(self::OTHER_ID)['hmac']);
    }

    /**
     * Inside a host transaction the bundle is one savepoint: both inserts run
     * one level deeper, no other transaction begins, and the host is back at
     * its own level with both rows its to commit.
     *
     * @return void
     */
    public function testInsideAHostTransactionTheBundleIsOneSavepoint(): void
    {
        $connection = $this->storageConnection();
        $levels     = [];
        $began      = [];

        $connection->beginTransaction();

        Event::listen(TransactionBeginning::class, static function (TransactionBeginning $event) use (&$began): void {
            $began[] = $event->connection->transactionLevel();
        });

        $connection->beforeExecuting(static function (string $query, array $bindings, $connection) use (&$levels): void {
            if (!str_starts_with($query, 'insert into')) {
                return;
            }

            $levels[] = $connection->transactionLevel();
        });

        $this->store()->store($this->bundle());

        self::assertSame([2], $began);
        self::assertSame([2, 2], $levels);
        self::assertSame(1, $connection->transactionLevel());

        $connection->commit();

        self::assertSame(1, $this->entryCount());
        self::assertSame(1, $this->artifactCount());
    }

    /**
     * A host's rollback undoes the bundle it stored, both rows of it.
     *
     * @return void
     */
    public function testAHostRollbackDropsBoth(): void
    {
        $connection = $this->storageConnection();

        $connection->beginTransaction();

        $this->store()->store($this->bundle());

        $connection->rollBack();

        self::assertSame(0, $this->entryCount());
        self::assertSame(0, $this->artifactCount());
    }

    /**
     * The same bundle stored again, outside a transaction and inside one, is a
     * success that writes nothing: one entry and one artifact, as first stored,
     * and the host left usable.
     *
     * @return void
     */
    public function testADuplicateWithEqualContentIsANoOp(): void
    {
        $bundle     = $this->bundle();
        $connection = $this->storageConnection();

        $this->store()->store($bundle);
        $this->store()->store($bundle);

        $connection->beginTransaction();

        $this->store()->store($bundle);

        self::assertSame(1, $connection->transactionLevel());

        $connection->commit();

        self::assertSame(1, $this->entryCount());
        self::assertSame(1, $this->artifactCount());
        self::assertSame(self::expectedArtifact($bundle), $this->storedArtifact(self::attachmentId($bundle)));
    }

    /**
     * An artifact is told by its description, never by its sealed members: an
     * artifact stored with other ciphertext but the bundle's id, entry, kind,
     * count and digest is the bundle's, so storing the bundle is a no-op.
     *
     * @return void
     */
    public function testADuplicateIsNeverComparedByItsSealedMembers(): void
    {
        $bundle = $this->bundle();

        $this->insertEntry($bundle);
        $this->insertArtifact($bundle, ['members' => 'sealed again']);

        $this->store()->store($bundle);

        self::assertSame(1, $this->entryCount());
        self::assertSame('sealed again', $this->storedArtifact(self::attachmentId($bundle))['members']);
    }

    /**
     * Rows of `[columns]`: the bundle's own entry stored beside an artifact
     * that differs from its own in one of the columns that tell it.
     *
     * @return iterable<string, array{0: array<string, int|string>}>
     */
    public static function provideDifferentArtifacts(): iterable
    {
        yield from [
            'another id, naming the entry' => [['id' => self::OTHER_ID]],
            'another entry'                => [['entry_id' => self::OTHER_ID]],
            'another kind'                 => [['kind' => 'export']],
            'another count'                => [['member_count' => 4]],
            'another digest'               => [['digest' => str_repeat('0', 64)]],
        ];
    }

    /**
     * The bundle's entry stored with an artifact other than its own is a
     * conflict naming the record, and what is stored is kept as it is.
     *
     * @param  array<string, int|string>  $columns
     * @return void
     */
    #[DataProvider('provideDifferentArtifacts')]
    public function testADuplicateWithADifferentArtifactIsAConflict(array $columns): void
    {
        $bundle = $this->bundle();
        $stored = $this->insertArtifact($bundle, $columns);

        $this->insertEntry($bundle);

        $this->assertConflict($bundle);

        self::assertSame(1, $this->entryCount());
        self::assertSame(1, $this->artifactCount());
        self::assertIsString($stored['id']);
        self::assertSame($stored, $this->storedArtifact($stored['id']));
    }

    /**
     * The bundle's entry stored without any artifact is a conflict: the
     * artifact the store inserted is rolled back with the entry's failed
     * insert, and only the entry is kept.
     *
     * @return void
     */
    public function testAnEntryWithoutItsArtifactIsAConflict(): void
    {
        $bundle = $this->bundle();

        $this->insertEntry($bundle);

        $this->assertConflict($bundle);

        self::assertSame(1, $this->entryCount());
        self::assertSame(0, $this->artifactCount());
    }

    /**
     * The bundle's artifact stored without its entry is a conflict, and no
     * entry is written beside it.
     *
     * @return void
     */
    public function testAnArtifactWithoutItsEntryIsAConflict(): void
    {
        $bundle = $this->bundle();

        $this->insertArtifact($bundle);

        $this->assertConflict($bundle);

        self::assertSame(0, $this->entryCount());
        self::assertSame(1, $this->artifactCount());
    }

    /**
     * An entry under the bundle's id with other captured content is the entry's
     * own conflict, as for any record, before its artifact is asked about.
     *
     * @return void
     */
    public function testAnEntryWithOtherContentIsAConflictOfContent(): void
    {
        $bundle = $this->bundle();
        $other  = $this->finaliser()->finalise(RecordFactory::captured(id: $bundle->record->id));

        $this->storageConnection()->table(EntrySettings::table())->insert((new RowCodec)->encode($other));
        $this->insertArtifact($bundle);

        $this->expectException(RecordConflictException::class);
        $this->expectExceptionMessage(sprintf('An audit entry with id %s already exists with different captured content.', $bundle->record->id));

        $this->store()->store($bundle);
    }

    /**
     * A violation of another index, with neither the entry nor the artifact
     * stored under the bundle's ids, propagates the original exception: an
     * artifact of another id naming the bundle's entry, which is not stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAViolationWithNothingStoredUnderTheIdsPropagates(): void
    {
        $bundle = $this->bundle();

        $this->insertArtifact($bundle, ['id' => self::OTHER_ID]);

        try {
            $this->store()->store($bundle);

            self::fail('Expected the violation to propagate.');
        } catch (UniqueConstraintViolationException $exception) {
            self::assertStringStartsWith('insert into', $exception->getSql());
        }

        self::assertSame(0, $this->entryCount());
        self::assertSame(1, $this->artifactCount());
    }

    /**
     * Inside a host transaction a conflict rolls back the bundle's savepoint
     * alone: the host is at its own level and goes on to store a record and
     * commit it.
     *
     * @return void
     */
    public function testAConflictInsideAHostTransactionLeavesItUsable(): void
    {
        $bundle     = $this->bundle();
        $connection = $this->storageConnection();
        $record     = $this->finaliser()->finalise(RecordFactory::captured(id: self::OTHER_ID));

        $this->insertEntry($bundle);

        $connection->beginTransaction();

        $this->assertConflict($bundle);

        self::assertSame(1, $connection->transactionLevel());

        $this->store()->store($record);

        $connection->commit();

        self::assertSame(2, $this->entryCount());
        self::assertSame(0, $this->artifactCount());
    }

    /**
     * A duplicate's two reads, of the entry and of the artifact, take MySQL's
     * shared lock inside a transaction, and no lock outside one or on another
     * engine.
     *
     * @return void
     */
    public function testTheDuplicatesReadsTakeASharedLockOnlyOnMySqlInsideATransaction(): void
    {
        $bundle     = $this->bundle();
        $connection = $this->storageConnection();
        $reads      = [];

        $this->store()->store($bundle);

        $connection->beforeExecuting(static function (string $query) use (&$reads): void {
            if (!str_starts_with($query, 'select')) {
                return;
            }

            $reads[] = $query;
        });

        $this->store()->store($bundle);

        $connection->beginTransaction();
        $this->store()->store($bundle);
        $connection->commit();

        self::assertCount(4, $reads);
        self::assertSame([EntrySettings::table(), EntrySettings::artifactsTable()], array_map(self::fromTableOf(...), array_slice($reads, 0, 2)));
        self::assertDoesNotMatchRegularExpression('/\b(lock|for share|for update)\b/i', $reads[0] . $reads[1]);

        foreach (array_slice($reads, 2) as $read) {
            if ($connection->getDriverName() === 'mysql') {
                self::assertStringEndsWith(' lock in share mode', $read);

                continue;
            }

            self::assertDoesNotMatchRegularExpression('/\b(lock|for share|for update)\b/i', $read);
        }
    }

    /**
     * The artifact's id and its entry's are stored and read back as the
     * lower-case UUIDs they were written as, on every engine.
     *
     * @return void
     */
    public function testTheIdsRoundTripAsLowerCaseUuids(): void
    {
        $bundle = $this->bundle();

        $this->store()->store($bundle);

        $stored = $this->storedArtifact(self::attachmentId($bundle));

        self::assertSame(self::attachmentId($bundle), $stored['id']);
        self::assertSame($bundle->record->id, $stored['entry_id']);
        self::assertMatchesRegularExpression(self::UUID_PATTERN, $stored['id']);
        self::assertMatchesRegularExpression(self::UUID_PATTERN, $stored['entry_id']);
        self::assertSame($bundle->record->id, $this->storedRow($bundle->record->id)['id']);
    }

    /**
     * The artifact is stored with its entry's recorded time, to the
     * microsecond, never the time the activity occurred.
     *
     * @return void
     */
    public function testTheArtifactsTimeIsTheEntrysRecordedTime(): void
    {
        $bundle = $this->finaliser('2026-11-01 12:00:00.654321')->finalise(RecordFactory::bundled());

        $this->store()->store($bundle);

        $stored = $this->storedArtifact(self::attachmentId($bundle));

        self::assertSame('2026-11-01T12:00:00.654321Z', $stored['created_at']);
        self::assertSame($this->storedRow($bundle->record->id)['recorded_at'], $stored['created_at']);
        self::assertNotSame($bundle->record->occurredAt, $stored['created_at']);
    }

    /**
     * Assert that storing the bundle is a conflict of its artifact, naming its
     * record.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $bundle
     * @return void
     *
     * @throws \Throwable
     */
    private function assertConflict(FinalisedRecord $bundle): void
    {
        try {
            $this->store()->store($bundle);

            self::fail('Expected the bundle to conflict.');
        } catch (RecordConflictException $exception) {
            self::assertSame(sprintf(self::DIFFERENT_ARTIFACT, $bundle->record->id), $exception->getMessage());
            self::assertSame($bundle->record->id, $exception->id);
        }
    }

    /**
     * Make the next inserts of the entries table fail before they run, or only
     * the next one.
     *
     * @param  bool  $once
     * @return void
     */
    private function failTheEntryInsert(bool $once = false): void
    {
        $armed = true;

        $this->storageConnection()->beforeExecuting(static function (string $query) use (&$armed, $once): void {
            if (!$armed || !str_starts_with($query, 'insert into') || self::tableOf($query) !== EntrySettings::table()) {
                return;
            }

            $armed = !$once;

            throw new \RuntimeException('The entry insert failed.');
        });
    }

    /**
     * Insert the bundle's entry row directly, without its artifact.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $bundle
     * @return void
     */
    private function insertEntry(FinalisedRecord $bundle): void
    {
        $this->storageConnection()->table(EntrySettings::table())->insert((new RowCodec)->encode($bundle));
    }

    /**
     * Insert the bundle's artifact row directly, without its entry, with the
     * columns given in place of its own, and return the row as it is read back.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $bundle
     * @param  array<string, int|string>  $columns
     * @return array<string, int|string>
     */
    private function insertArtifact(FinalisedRecord $bundle, array $columns = []): array
    {
        $row = [...(new RowCodec)->encodeAttachment($bundle), ...$columns];

        $this->storageConnection()->table(EntrySettings::artifactsTable())->insert($row);

        return $this->storedArtifact((string) $row['id']);
    }

    /**
     * The artifact stored under the id, with its count as an integer and its
     * time in the package's form, whatever the engine returns.
     *
     * @param  string  $id
     * @return array<string, int|string>
     */
    private function storedArtifact(string $id): array
    {
        $row = $this->storageConnection()->table(EntrySettings::artifactsTable())->where('id', $id)->first();

        self::assertNotNull($row, "No artifact is stored under {$id}.");

        $row = (array) $row;

        return [
            'id'           => (string) $row['id'],
            'entry_id'     => (string) $row['entry_id'],
            'kind'         => (string) $row['kind'],
            'member_count' => (int) $row['member_count'],
            'digest'       => (string) $row['digest'],
            'members'      => (string) $row['members'],
            'created_at'   => StoredTime::fromStorage((string) $row['created_at']),
        ];
    }

    /**
     * The number of rows in the artifacts table.
     *
     * @return int
     */
    private function artifactCount(): int
    {
        return $this->storageConnection()->table(EntrySettings::artifactsTable())->count();
    }

    /**
     * A bulk record of three members, finalised on the frozen clock.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function bundle(): FinalisedRecord
    {
        return $this->finaliser()->finalise(RecordFactory::bundled());
    }

    /**
     * The artifact the bundle is stored with, as `storedArtifact()` reads it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $bundle
     * @return array<string, int|string>
     */
    private static function expectedArtifact(FinalisedRecord $bundle): array
    {
        return [...(new RowCodec)->encodeAttachment($bundle), 'created_at' => $bundle->recordedAt];
    }

    /**
     * The id of the bundle's attachment.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $bundle
     * @return string
     */
    private static function attachmentId(FinalisedRecord $bundle): string
    {
        $attachment = $bundle->record->attachment;

        self::assertNotNull($attachment);

        return $attachment->id;
    }

    /**
     * The table an insert writes to, its quoting dropped.
     *
     * @param  string  $query
     * @return string
     */
    private static function tableOf(string $query): string
    {
        return preg_match('/\Ainsert into [`"]?([a-z0-9_]+)/', $query, $matches) === 1 ? $matches[1] : '';
    }

    /**
     * The table a read is from, its quoting dropped.
     *
     * @param  string  $query
     * @return string
     */
    private static function fromTableOf(string $query): string
    {
        return preg_match('/ from [`"]?([a-z0-9_]+)/', $query, $matches) === 1 ? $matches[1] : '';
    }
}
