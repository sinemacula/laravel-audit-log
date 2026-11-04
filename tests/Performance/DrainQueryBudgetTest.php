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
 * Statement-budget contract for the drain: an empty run is one read of ids; a
 * row delivered to the database costs its claim, its payload, its tombstone
 * check, its receipts, a renewal before and after the store, its attempt, its
 * insert in a savepoint of the transaction it shares with its receipt, and its
 * delete; each further row costs the same again, one tombstone check each; a
 * pruned row costs its claim, its payload, its check and its delete; a duplicate adds one read and the savepoint's rollback;
 * a further destination adds its renewals and its receipt; a bundle adds its
 * artifact's insert to the same savepoint, and one refused costs a failure; a
 * failure and a lost claim are pinned as well, and no run reads a payload
 * before its claim.
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
     * Move the frozen clock on by a millisecond before every statement, because
     * a renewal at the instant the lease was written changes no row on MySQL,
     * which would add its follow-up read to that engine's budget alone.
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
     * One row to the database reads its candidates, its payload, its tombstones
     * and its receipts, and writes its claim, a renewal, its attempt, its
     * insert, a renewal, its receipt and its delete, with a savepoint around
     * the insert.
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
     * A row delivered to the database shares one top-level transaction between
     * its entry and its receipt, and no other: a second per row, or none, shows
     * here though no statement budget would see it.
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
     * Ten rows cost ten times what one costs, apart from the one read of their
     * candidates they share.
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
     * A bundle to the database costs what one row costs and one more insert,
     * its artifact's, which precedes its entry's inside the same savepoint of
     * the one top-level transaction it shares with its receipt.
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
     * A bundle refused by a store that keeps no attachments costs what any
     * failure costs, and no insert of the entry or the artifact.
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
     * A record the database already holds adds the read that resolves the
     * duplicate and the rollback of the savepoint its insert failed in, and
     * nothing else.
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
     * A log destination after the database adds its renewal, its attempt, a
     * renewal and its receipt, and no read: the receipts are read once, and the
     * log shares no transaction.
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
     * A destination that joins no transaction and fails reads the candidates,
     * the payload, the tombstones and the receipts, and writes the claim, a
     * renewal, the attempt, a renewal, the failed receipt and the retry.
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
     * A claim lost before the first renewal adds the read that tells a lost
     * claim from a renewal that changed nothing, and then the drain stops: no
     * attempt, no store and no receipt.
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
     * The read of the candidates names only the id, so a payload is read only
     * by the worker that owns its row.
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
     * A row whose destination already has the record costs its claim and its
     * delete and none of a delivery's writes, however it came to be left: the
     * statements of a recovery are not repeated.
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
     * A row past its attempts costs its claim, the read of its payload and the
     * write that fails it, and no delivery is begun: its record is never read,
     * so its tombstones are not either.
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
     * Each row whose record is read costs exactly one read of the tombstones,
     * whatever happens to it next, and no other statement names the members
     * table.
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
     * A pruned row costs its claim, the read of its payload, its tombstone
     * check, the reads of its seal and the seal's members that tell its prune a
     * valid record covers, and its delete, and nothing of a delivery.
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
     * As soon as a drain reads the receipts, hand every outbox row to another
     * owner over the raw connection, so the statement is not counted and the
     * next renewal finds its claim gone.
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
