<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Statement-budget contract for the database store: one plain insert per
 * record, and inside a transaction only Laravel's savepoint beside it; a
 * duplicate adds one read, and inside a transaction the savepoint's rollback.
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
     * The captured record of an approved invoice under the pinned id, finalised
     * on the frozen clock.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function finalised(): FinalisedRecord
    {
        return $this->finaliser()->finalise(RecordFactory::captured(id: self::ID));
    }
}
