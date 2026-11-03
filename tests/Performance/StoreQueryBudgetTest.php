<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RecordConflictException;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Statement-budget contract for the database store: one plain insert per
 * record, and inside a transaction only Laravel's savepoint beside it; a
 * duplicate adds one read, and inside a transaction the savepoint's rollback. A
 * bundle is two plain inserts, its artifact's first, in one transaction of its
 * own or one savepoint inside a host's; its duplicate is the one insert that
 * fails and two reads, and the rollback of that transaction or savepoint.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAuditStore::class)]
final class StoreQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithAuditStore;

    /** @var string The id records are pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /**
     * Roll back any transaction a failed test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        while (DB::connection()->transactionLevel() > 0) {
            DB::connection()->rollBack();
        }

        parent::tearDown();
    }

    /**
     * Outside a transaction a record costs one insert, no read, and no
     * savepoint or rollback.
     *
     * @return void
     */
    public function testStoringARecordIsOneInsert(): void
    {
        $finalised = $this->finalised();

        $this->assertStatementBudget(0, 1, 0, 0, fn () => $this->store()->store($finalised));

        self::assertSame(1, $this->entryCount());
    }

    /**
     * Inside a transaction a record costs the same insert and one savepoint,
     * and the savepoint's success issues nothing.
     *
     * @return void
     */
    public function testStoringInsideATransactionAddsOnlyASavepoint(): void
    {
        $finalised = $this->finalised();

        DB::beginTransaction();

        $this->assertStatementBudget(0, 1, 1, 0, fn () => $this->store()->store($finalised));

        DB::commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * Outside a transaction a duplicate costs its insert and one read.
     *
     * @return void
     */
    public function testADuplicateIsOneInsertAndOneRead(): void
    {
        $finalised = $this->finalised();

        $this->store()->store($finalised);

        $this->assertStatementBudget(1, 1, 0, 0, fn () => $this->store()->store($finalised));

        self::assertSame(1, $this->entryCount());
    }

    /**
     * Inside a transaction a duplicate costs its insert, one read, the
     * savepoint and the savepoint's rollback.
     *
     * @return void
     */
    public function testADuplicateInsideATransactionAlsoRollsBackItsSavepoint(): void
    {
        $finalised = $this->finalised();

        $this->store()->store($finalised);

        DB::beginTransaction();

        $this->assertStatementBudget(1, 1, 1, 1, fn () => $this->store()->store($finalised));

        DB::commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * The insert is a plain insert: it ignores no error and resolves no
     * conflict itself.
     *
     * @return void
     */
    public function testTheInsertIsAPlainInsert(): void
    {
        $finalised = $this->finalised();

        $this->capture(fn () => $this->store()->store($finalised));

        $writes = $this->capturedWrites();

        self::assertCount(1, $writes);
        self::assertStringStartsWith('insert into ', $writes[0]);
        self::assertDoesNotMatchRegularExpression('/\b(ignore|on conflict|on duplicate key|replace)\b/i', $writes[0]);
    }

    /**
     * A hundred distinct records cost a hundred inserts, and nothing else, and
     * store a hundred rows.
     *
     * @return void
     */
    public function testEachDistinctRecordCostsOneInsert(): void
    {
        $records = array_map(fn (): FinalisedRecord => $this->finaliser()->finalise(RecordFactory::captured()), range(1, 100));

        $this->assertStatementBudget(0, 100, 0, 0, function () use ($records): void {
            foreach ($records as $record) {
                $this->store()->store($record);
            }
        });

        self::assertSame(100, $this->entryCount());
    }

    /**
     * Inside one host transaction every record costs a savepoint of its own,
     * none of which is released or rolled back before the host commits: on
     * PostgreSQL each is a subtransaction held until then, which is why the
     * store's documentation keeps the records of one transaction well under 64,
     * the most PostgreSQL's snapshots hold before they overflow.
     *
     * @return void
     */
    public function testEachRecordInsideOneTransactionHoldsASavepointUntilTheHostCommits(): void
    {
        $records = array_map(fn (): FinalisedRecord => $this->finaliser()->finalise(RecordFactory::captured()), range(1, 10));

        DB::beginTransaction();

        $this->assertStatementBudget(0, 10, 10, 0, function () use ($records): void {
            foreach ($records as $record) {
                $this->store()->store($record);
            }
        });

        self::assertSame(1, DB::connection()->transactionLevel());

        DB::commit();

        self::assertSame(10, $this->entryCount());
    }

    /**
     * Outside a transaction a bundle costs two plain inserts, its artifact's
     * then its entry's, no read, and one transaction of its own, committed
     * once.
     *
     * @return void
     */
    public function testStoringABundleIsTwoInsertsInOneTransaction(): void
    {
        $bundle = $this->bundle();

        $this->assertTransactionBudget(1, 1, fn () => $this->assertStatementBudget(0, 2, 0, 0, fn () => $this->store()->store($bundle)));

        $writes = $this->capturedWrites();

        self::assertStringContainsString(EntrySettings::artifactsTable(), $writes[0]);
        self::assertStringContainsString(EntrySettings::table(), $writes[1]);

        foreach ($writes as $write) {
            self::assertStringStartsWith('insert into ', $write);
            self::assertDoesNotMatchRegularExpression('/\b(ignore|on conflict|on duplicate key|replace)\b/i', $write);
        }

        self::assertSame(1, $this->entryCount());
    }

    /**
     * Inside a transaction a bundle costs the same two inserts and one
     * savepoint, and begins and commits no transaction of its own.
     *
     * @return void
     */
    public function testStoringABundleInsideATransactionIsTwoInsertsInOneSavepoint(): void
    {
        $bundle = $this->bundle();

        DB::beginTransaction();

        $this->assertTransactionBudget(0, 0, fn () => $this->assertStatementBudget(0, 2, 1, 0, fn () => $this->store()->store($bundle)));

        self::assertSame(1, DB::connection()->transactionLevel());

        DB::commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * Outside a transaction a bundle's duplicate costs the artifact's insert,
     * which fails, so the entry's never runs; the rollback of its transaction;
     * and two reads, of the entry and of the artifact. Nothing is committed.
     *
     * @return void
     */
    public function testABundleDuplicateIsOneInsertAndTwoReads(): void
    {
        $bundle = $this->bundle();

        $this->store()->store($bundle);

        $this->assertTransactionBudget(1, 0, fn () => $this->assertStatementBudget(2, 1, 0, 1, fn () => $this->store()->store($bundle)));

        self::assertSame(1, $this->entryCount());
    }

    /**
     * Inside a transaction a bundle's duplicate costs its one insert, the two
     * reads, the savepoint and the savepoint's rollback.
     *
     * @return void
     */
    public function testABundleDuplicateInsideATransactionAlsoRollsBackItsSavepoint(): void
    {
        $bundle = $this->bundle();

        $this->store()->store($bundle);

        DB::beginTransaction();

        $this->assertStatementBudget(2, 1, 1, 1, fn () => $this->store()->store($bundle));

        DB::commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A bundle whose entry is stored without its artifact costs both inserts,
     * the entry's failing, the rollback that takes the artifact back, and the
     * two reads that find the conflict.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABundleWhoseEntryIsStoredAloneIsTwoInsertsAndTwoReads(): void
    {
        $bundle = $this->bundle();

        DB::table(EntrySettings::table())->insert((new RowCodec)->encode($bundle));

        $this->assertStatementBudget(2, 2, 0, 1, function () use ($bundle): void {
            try {
                $this->store()->store($bundle);

                self::fail('Expected the bundle to conflict.');
            } catch (RecordConflictException) {
                // The conflict is the outcome whose cost is measured
            }
        });

        self::assertSame(0, DB::table(EntrySettings::artifactsTable())->count());
    }

    /**
     * A hundred distinct bundles cost two hundred inserts and nothing else, in
     * a hundred transactions, and store a hundred entries and a hundred
     * artifacts.
     *
     * @return void
     */
    public function testEachDistinctBundleCostsTwoInserts(): void
    {
        $bundles = array_map(fn (): FinalisedRecord => $this->bundle(), range(1, 100));

        $this->assertTransactionBudget(100, 100, fn () => $this->assertStatementBudget(0, 200, 0, 0, function () use ($bundles): void {
            foreach ($bundles as $bundle) {
                $this->store()->store($bundle);
            }
        }));

        self::assertSame(100, $this->entryCount());
        self::assertSame(100, DB::table(EntrySettings::artifactsTable())->count());
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
     * A bulk record of three members, finalised on the frozen clock.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function bundle(): FinalisedRecord
    {
        return $this->finaliser()->finalise(RecordFactory::bundled());
    }
}
