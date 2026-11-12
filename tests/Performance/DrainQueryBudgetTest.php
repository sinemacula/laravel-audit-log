<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Log\LogManager;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Delivery\DeliveryCoordinator;
use SineMacula\Laravel\AuditLog\Delivery\DrainResult;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\Receipts;
use SineMacula\Laravel\AuditLog\Export\NdjsonFormatter;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\LogAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\PrunesByHand;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\CallbackStore;

/**
 * Statement budget for the outbox drain, per row and per destination; no run
 * reads a payload before its claim.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OutboxDrainer::class)]
#[CoversClass(DeliveryCoordinator::class)]
#[CoversClass(Outbox::class)]
#[CoversClass(Receipts::class)]
#[CoversClass(PruneTombstones::class)]
final class DrainQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, PrunesByHand, SealsEntries, SeedsTheOutbox;

    /**
     * Move the clock on a millisecond before every statement: on MySQL a
     * renewal at the lease's own instant changes no row and adds a read.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        DB::connection()->beforeExecuting(static function (): void {
            CarbonImmutable::setTestNow(CarbonImmutable::now()->addMillisecond());
        });
    }

    /**
     * A drain that finds nothing makes the one read of its candidates.
     *
     * @return void
     */
    public function testAnEmptyDrainIsOneRead(): void
    {
        $result = $this->assertStatementBudget(1, 0, 0, 0, fn (): DrainResult => $this->drain());

        self::assertSame(0, $result->delivered());
    }

    /**
     * One row to the database has a fixed budget, with a savepoint around its
     * insert.
     *
     * @return void
     */
    public function testOneRowToTheDatabaseIsPinned(): void
    {
        $this->enqueue($this->finalisedRecord());

        $result = $this->assertStatementBudget(4, 7, 1, 0, fn (): DrainResult => $this->drain());

        self::assertSame(1, $result->delivered());
        self::assertSame(1, $this->entryCount());
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A row to the database shares one top-level transaction between its entry
     * and its receipt.
     *
     * @return void
     */
    public function testARowToTheDatabaseIsOneTopLevelTransaction(): void
    {
        $this->enqueue($this->finalisedRecord());
        $this->enqueue($this->finalisedRecord());

        $result = $this->assertTransactionBudget(2, 2, fn (): DrainResult => $this->drain());

        self::assertSame(2, $result->delivered());
    }

    /**
     * A destination that joins no transaction is delivered with none.
     *
     * @return void
     */
    public function testARowToALogIsNoTransaction(): void
    {
        app()->instance(AuditStore::class, new LogAuditStore(app(LogManager::class), new NdjsonFormatter));

        $this->enqueue($this->finalisedRecord());

        $this->assertTransactionBudget(0, 0, fn (): DrainResult => $this->drain());
    }

    /**
     * Ten rows cost ten times one row, sharing one read of their candidates.
     *
     * @return void
     */
    public function testTenRowsCostTenTimesOneRow(): void
    {
        foreach (range(1, 10) as $ignored) {
            $this->enqueue($this->finalisedRecord());
        }

        $result = $this->assertStatementBudget(31, 70, 10, 0, fn (): DrainResult => $this->drain());

        self::assertSame(10, $result->delivered());
        self::assertSame(10, $this->entryCount());
    }

    /**
     * A bundle costs one row and its artifact's insert, ahead of the entry's in
     * the same savepoint.
     *
     * @return void
     */
    public function testDrainingABundleIsTwoInsertsInOneTransaction(): void
    {
        $id = $this->enqueue($this->finalisedRecord(RecordFactory::bundled()));

        $result = $this->assertTransactionBudget(1, 1, fn (): DrainResult => $this->assertStatementBudget(4, 8, 1, 0, fn (): DrainResult => $this->drain()));

        $deliveries = DeliveryTables::deliveriesTable();
        $isRowWrite = static fn (string $write): bool => str_starts_with($write, 'insert into ') && !str_contains($write, $deliveries);
        $inserts    = array_values(array_filter($this->capturedWrites(), $isRowWrite));

        self::assertSame(1, $result->delivered());
        self::assertCount(2, $inserts);
        self::assertStringContainsString(EntrySettings::artifactsTable(), $inserts[0]);
        self::assertStringContainsString(EntrySettings::table(), $inserts[1]);
        self::assertSame(1, $this->entryCount());
        self::assertSame(0, $this->outboxCount());
        self::assertSame(1, DB::connection()->table(EntrySettings::artifactsTable())->where('entry_id', $id)->count());
    }

    /**
     * A bundle refused by a store that keeps no attachments costs what a
     * failure costs, and inserts nothing.
     *
     * @return void
     */
    public function testARefusedBundleCostsWhatAFailureCosts(): void
    {
        app()->instance(AuditStore::class, CallbackStore::saying(true));

        $this->enqueue($this->finalisedRecord(RecordFactory::bundled()));

        $result = $this->assertStatementBudget(4, 6, 0, 0, fn (): DrainResult => $this->drain());

        self::assertSame(1, $result->retried());
        self::assertSame(0, $this->entryCount());
        self::assertSame(1, $this->outboxCount());
    }

    /**
     * A duplicate adds one read and the rollback of its savepoint.
     *
     * @return void
     */
    public function testADuplicateAddsOneReadAndARollback(): void
    {
        $record = $this->finalisedRecord();

        $this->store()->store($record);
        $this->enqueue($record);

        $result = $this->assertStatementBudget(5, 7, 1, 1, fn (): DrainResult => $this->drain());

        self::assertSame(1, $result->delivered());
        self::assertSame(1, $this->entryCount());
    }

    /**
     * A log destination after the database adds its renewals, attempt and
     * receipt, and no read.
     *
     * @return void
     */
    public function testASecondLogDestinationAddsItsReceipts(): void
    {
        app()->instance(AuditStore::class, new StackAuditStore([
            'database' => app(DatabaseAuditStore::class),
            'log'      => new LogAuditStore(app(LogManager::class), new NdjsonFormatter, 'null'),
        ]));

        $this->enqueue($this->finalisedRecord());

        $result = $this->assertStatementBudget(4, 11, 1, 0, fn (): DrainResult => $this->drain());

        self::assertSame(1, $result->delivered());
        self::assertSame(2, $this->receiptCount());
    }

    /**
     * A failed delivery to a destination that joins no transaction has a fixed
     * budget.
     *
     * @return void
     */
    public function testAFailureIsPinned(): void
    {
        app()->instance(AuditStore::class, CallbackStore::failingWith(new \DomainException('Down.')));

        $this->enqueue($this->finalisedRecord());

        $result = $this->assertStatementBudget(4, 6, 0, 0, fn (): DrainResult => $this->drain());

        self::assertSame(1, $result->retried());
        self::assertSame(1, $this->outboxCount());
    }

    /**
     * A claim lost before the first renewal adds one read, then the drain
     * stops.
     *
     * @return void
     */
    public function testAStaleRenewalAddsOneSelectAndStops(): void
    {
        $store = CallbackStore::saying(true);

        app()->instance(AuditStore::class, $store);

        $this->enqueue($this->finalisedRecord());
        $this->takeTheClaimWhenTheReceiptsAreRead();

        $result = $this->assertStatementBudget(5, 2, 0, 0, fn (): DrainResult => $this->drain());

        self::assertSame(1, $result->stale());
        self::assertSame(0, $this->receiptCount());
    }

    /**
     * The candidates read names only the id, so only a row's owner reads its
     * payload.
     *
     * @return void
     */
    public function testCandidatesReadNoPayload(): void
    {
        $this->enqueue($this->finalisedRecord());

        $this->capture(fn (): DrainResult => $this->drain());

        $table = preg_quote(DeliveryTables::outboxTable(), '/');

        self::assertMatchesRegularExpression('/^select \W?id\W? from \W?' . $table . '\W? where /', $this->capturedStatements()[0]);
    }

    /**
     * A row its destination already holds costs only its claim and its delete.
     *
     * @return void
     */
    public function testARecoveredRowCostsOnlyItsClaimAndItsDelete(): void
    {
        $id = $this->enqueue($this->finalisedRecord());

        $receipts = app(Receipts::class);

        $receipts->attempting($id, DeliveryCoordinator::STORE_DESTINATION, null);
        $receipts->delivered($id, DeliveryCoordinator::STORE_DESTINATION);

        $result = $this->assertStatementBudget(4, 2, 0, 0, fn (): DrainResult => $this->drain());

        self::assertSame(1, $result->delivered());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A row past its attempts costs its claim, its payload read and its
     * failure, and no delivery.
     *
     * @return void
     */
    public function testAnAbandonedRowCostsOnlyItsClaimAndItsFailure(): void
    {
        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $this->enqueue($this->finalisedRecord(), ['attempts' => 10]);

        $result = $this->assertStatementBudget(2, 2, 0, 0, fn (): DrainResult => $this->drain());

        self::assertSame(1, $result->failed());
        self::assertSame(0, $this->receiptCount());
    }

    /**
     * Each row whose record is read costs exactly one tombstone read, and no
     * other statement names the members table.
     *
     * @return void
     */
    public function testEachRowCostsOneTombstoneCheck(): void
    {
        foreach (range(1, 3) as $ignored) {
            $this->enqueue($this->finalisedRecord());
        }

        $this->capture(fn (): DrainResult => $this->drain());

        $three = count($this->tombstoneChecks());

        foreach (range(1, 4) as $ignored) {
            $this->enqueue($this->finalisedRecord());
        }

        $this->capture(fn (): DrainResult => $this->drain());

        self::assertSame([3, 4], [$three, count($this->tombstoneChecks())]);
    }

    /**
     * A pruned row costs its claim, payload read, tombstone check, seal reads
     * and delete, and nothing of a delivery.
     *
     * @return void
     */
    public function testAPrunedRowCostsItsClaimItsCheckAndItsDelete(): void
    {
        $record = $this->finalisedRecord();

        $this->store()->store($record);
        $this->sealAll();
        $this->pruneByHand($record->record->id);
        $this->enqueue($record);

        $result = $this->assertStatementBudget(5, 2, 0, 0, fn (): DrainResult => $this->drain());

        self::assertSame(1, $result->pruned());
        self::assertSame(0, $this->outboxCount());
        self::assertSame(0, $this->receiptCount());
    }

    /**
     * The captured statements that read the tombstones.
     *
     * @return list<string>
     */
    private function tombstoneChecks(): array
    {
        $members = IntegrityTables::membersTable();

        return array_values(array_filter($this->capturedStatements(), static fn (string $statement): bool => str_contains($statement, $members)));
    }

    /**
     * Drain the outbox with the drainer the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\DrainResult
     *
     * @throws \LogicException
     */
    private function drain(): DrainResult
    {
        return app(OutboxDrainer::class)->drain(100, false);
    }

    /**
     * When a drain reads the receipts, reassign every outbox row over the raw
     * connection, uncounted, so the next renewal finds its claim gone.
     *
     * @return void
     */
    private function takeTheClaimWhenTheReceiptsAreRead(): void
    {
        $deliveries = DeliveryTables::deliveriesTable();
        $outbox     = DeliveryTables::outboxTable();

        DB::connection()->beforeExecuting(static function (string $query, array $bindings, Connection $connection) use ($deliveries, $outbox): void {
            if (!str_starts_with($query, 'select') || !str_contains($query, $deliveries)) {
                return;
            }

            $connection->getPdo()->exec("update {$outbox} set claimed_by = 'another-owner'");
        });
    }
}
