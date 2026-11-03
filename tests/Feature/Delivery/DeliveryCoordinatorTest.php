<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Log\LogManager;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Delivery\DeliveryCoordinator;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryOutcome;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxClaim;
use SineMacula\Laravel\AuditLog\Delivery\StaleClaimException;
use SineMacula\Laravel\AuditLog\Export\NdjsonFormatter;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\LogAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SearchesForSecrets;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\Fixtures\Stores\PlainStore;
use Tests\TestCase;

/**
 * Feature tests for the coordinator that delivers a claimed outbox row's record
 * to each destination of the store: the receipt it keeps for each, counted
 * before the call; a stack's destinations each tried, and a retry reaching only
 * those still without the record; the transaction a database destination shares
 * with its receipt; destinations that come and go; the claim renewed before
 * each call and each receipt, and nothing further written once it is lost; and
 * the write guard around each call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliveryCoordinator::class)]
#[CoversClass(StaleClaimException::class)]
final class DeliveryCoordinatorTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore, InteractsWithOutbox, SearchesForSecrets, SeedsTheOutbox;

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var string Past the default lease of a claim taken at the start. */
    private const string PAST_THE_LEASE = '2026-11-01T12:05:01.000000Z';

    /** @var list<string> What happened during a delivery, in order: each write of the outbox or the deliveries table, and each destination's call. */
    private array $steps = [];

    /**
     * Stop the clock at the start of the day's tests.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClockTo(self::NOW);
    }

    /**
     * Roll back any transaction a test left open, put the clock and the outbox
     * back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(self::CONNECTION);

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        $this->removeMovedOutbox();

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A destination's attempt is counted on its receipt before it is called:
     * the destination itself reads a receipt of one attempt, not yet delivered.
     *
     * @return void
     */
    public function testAttemptsAreRecordedBeforeInvocation(): void
    {
        $seen = null;

        $this->bindStore(new CallbackStore(function (FinalisedRecord $record) use (&$seen): void {
            $seen = $this->receipt($record->record->id, DeliveryCoordinator::STORE_DESTINATION);
        }, participatesOn: []));

        [$record, $claim] = $this->claimedRecord();

        $this->coordinator()->deliver($record, $claim);

        self::assertIsArray($seen);
        self::assertSame(1, $seen['attempts']);
        self::assertNull($seen['delivered_at']);
    }

    /**
     * A destination that has the record has its receipt marked delivered, at
     * the clock's instant and with no error, and the delivery is complete.
     *
     * @return void
     */
    public function testASuccessMarksTheReceiptDelivered(): void
    {
        $store = $this->bindStore(new PlainStore);

        [$record, $claim] = $this->claimedRecord();

        self::assertSame(DeliveryOutcome::COMPLETE, $this->coordinator()->deliver($record, $claim)->outcome);

        $receipt = $this->receipt($record->record->id, DeliveryCoordinator::STORE_DESTINATION);

        self::assertSame(1, $store->calls());
        self::assertIsArray($receipt);
        self::assertSame(1, $receipt['attempts']);
        self::assertSame(self::NOW, $receipt['delivered_at']);
        self::assertNull($receipt['last_error_class']);
    }

    /**
     * A destination that fails keeps its failure's class on its receipt, which
     * stays undelivered, and the delivery is incomplete, naming the failure.
     *
     * @return void
     */
    public function testAFailureKeepsItsClassOnTheReceipt(): void
    {
        $this->bindStore(CallbackStore::failingWith(new \DomainException('The store is down.'), participatesOn: []));

        [$record, $claim] = $this->claimedRecord();

        $result = $this->coordinator()->deliver($record, $claim);

        self::assertSame(DeliveryOutcome::INCOMPLETE, $result->outcome);

        $receipt = $this->receipt($record->record->id, DeliveryCoordinator::STORE_DESTINATION);

        self::assertIsArray($receipt);
        self::assertSame(\DomainException::class, $receipt['last_error_class']);
        self::assertNull($receipt['delivered_at']);
        self::assertSame(\DomainException::class, $result->failure()->exceptionClass);
        self::assertSame($record->record->id, $result->failure()->recordId);
        self::assertSame($record->record->event, $result->failure()->eventCode);
        self::assertSame('drain', $result->failure()->operation->value);
        self::assertSame(CallbackStore::class, $result->failure()->store);
        self::assertNull($result->failure()->destination);
    }

    /**
     * A failure whose message, SQL and bindings hold the secret leaves none of
     * it on the receipt, in the last failure or anywhere in the deliveries
     * table: only its class and its SQLSTATE are kept.
     *
     * @return void
     */
    public function testAFailureLeavesNoMessageOnTheReceipt(): void
    {
        $failure = new QueryException('testing', 'insert into x values (?)', [self::SECRET], new \PDOException('SQLSTATE[23000]: ' . self::SECRET));

        $this->bindStore(CallbackStore::failingWith($failure, participatesOn: []));

        [$record, $claim] = $this->claimedRecord();

        $coordinator = $this->coordinator();

        $result = $coordinator->deliver($record, $claim);

        $receipts = DB::connection(self::CONNECTION)->table(DeliveryTables::deliveriesTable())->get()->all();

        self::assertCount(1, $receipts);
        self::assertSame(QueryException::class, $this->receipt($record->record->id, DeliveryCoordinator::STORE_DESTINATION)['last_error_class'] ?? null);
        self::assertHoldsNoSecret($receipts, 'the deliveries table');
        self::assertHoldsNoSecret($result->failure(), 'the last failure');
    }

    /**
     * Each destination of a stack has a receipt of its own, under its id.
     *
     * @return void
     */
    public function testAReceiptIsWrittenForEachDestination(): void
    {
        $this->bindStore(new StackAuditStore(['first' => new PlainStore, 'second' => new PlainStore]));

        [$record, $claim] = $this->claimedRecord();

        $this->coordinator()->deliver($record, $claim);

        self::assertSame(2, $this->receiptCount());
        self::assertSame(self::NOW, $this->receipt($record->record->id, 'first')['delivered_at'] ?? null);
        self::assertSame(self::NOW, $this->receipt($record->record->id, 'second')['delivered_at'] ?? null);
    }

    /**
     * Every destination of a stack is called, in order, even after one failed.
     *
     * @return void
     */
    public function testEveryDestinationIsAttempted(): void
    {
        $this->bindStore(new StackAuditStore([
            'first'  => $this->recordingStep('first', fail: true),
            'second' => $this->recordingStep('second'),
            'third'  => $this->recordingStep('third', fail: true),
        ]));

        [$record, $claim] = $this->claimedRecord();

        self::assertSame(DeliveryOutcome::INCOMPLETE, $this->coordinator()->deliver($record, $claim)->outcome);
        self::assertSame(['call first', 'call second', 'call third'], $this->steps);
    }

    /**
     * A stack whose second destination fails is incomplete, its first
     * destination delivered and its second not, and the last failure names the
     * second by its id.
     *
     * @return void
     */
    public function testAFailingSecondDestinationIsIncomplete(): void
    {
        $this->bindStore(new StackAuditStore(['first' => new PlainStore, 'second' => CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: [])]));

        [$record, $claim] = $this->claimedRecord();

        $result = $this->coordinator()->deliver($record, $claim);

        self::assertSame(DeliveryOutcome::INCOMPLETE, $result->outcome);
        self::assertSame(self::NOW, $this->receipt($record->record->id, 'first')['delivered_at'] ?? null);
        self::assertNull($this->receipt($record->record->id, 'second')['delivered_at'] ?? null);
        self::assertSame('second', $result->failure()->destination);
    }

    /**
     * Once a destination has the record, a later delivery of the row reaches
     * only the destination that failed, which then counts a second attempt.
     *
     * @return void
     */
    public function testARetryReachesOnlyTheFailedDestination(): void
    {
        $first = new PlainStore;
        $calls = 0;

        $this->bindStore(new StackAuditStore([
            'first'  => $first,
            'second' => self::failingOnce($calls),
        ]));

        [$record, $claim] = $this->claimedRecord();

        self::assertSame(DeliveryOutcome::INCOMPLETE, $this->coordinator()->deliver($record, $claim)->outcome);
        self::assertSame(DeliveryOutcome::COMPLETE, $this->coordinator()->deliver($record, $this->reclaimed($record->record->id))->outcome);
        self::assertSame(1, $first->calls());
        self::assertSame(2, $calls);
        self::assertSame(1, $this->receipt($record->record->id, 'first')['attempts'] ?? null);
        self::assertSame(2, $this->receipt($record->record->id, 'second')['attempts'] ?? null);
    }

    /**
     * A destination that fails after the database has the record does not undo
     * the entry or its receipt.
     *
     * @return void
     */
    public function testAFailingDestinationDoesNotUndoTheOthers(): void
    {
        $this->bindStore(new StackAuditStore([
            'database' => app(DatabaseAuditStore::class),
            'log'      => CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: []),
        ]));

        [$record, $claim] = $this->claimedRecord();

        self::assertSame(DeliveryOutcome::INCOMPLETE, $this->coordinator()->deliver($record, $claim)->outcome);
        self::assertSame(1, $this->entryCount());
        self::assertSame(self::NOW, $this->receipt($record->record->id, 'database')['delivered_at'] ?? null);
    }

    /**
     * A store that is not a stack is the one destination `store`, and a failure
     * of it names no destination.
     *
     * @return void
     */
    public function testASingleStoreIsOneDestination(): void
    {
        $this->bindStore(new PlainStore);

        [$record, $claim] = $this->claimedRecord();

        $this->coordinator()->deliver($record, $claim);

        self::assertSame(1, $this->receiptCount());
        self::assertNotNull($this->receipt($record->record->id, 'store'));
    }

    /**
     * Every destination receives the record the row holds, byte for byte the
     * envelope that was written.
     *
     * @return void
     */
    public function testEveryDestinationReceivesIdenticalBytes(): void
    {
        $first  = new PlainStore;
        $second = new PlainStore;

        $this->bindStore(new StackAuditStore(['first' => $first, 'second' => $second]));

        [$record, $claim] = $this->claimedRecord();

        $this->coordinator()->deliver($record, $claim);

        $codec = app(EnvelopeCodec::class);

        self::assertSame($codec->encode($record), $codec->encode($first->received()[0]));
        self::assertSame($codec->encode($record), $codec->encode($second->received()[0]));
    }

    /**
     * A database destination's insert and the receipt saying it was delivered
     * run inside one transaction on the storage connection, which commits both.
     *
     * @return void
     */
    public function testADatabaseDestinationSharesATransactionWithItsReceipt(): void
    {
        $this->bindStore(app(DatabaseAuditStore::class));

        [$record, $claim] = $this->claimedRecord();

        $levels = [];

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query, array $bindings, $connection) use (&$levels): void {
            $step = match (true) {
                str_starts_with($query, 'insert into ') && str_contains($query, 'audit_log_entries') => 'entry',
                self::marksDelivered($query)                                                         => 'delivered',
                default                                                                              => null,
            };

            if ($step === null) {
                return;
            }

            $levels[$step] = $connection->transactionLevel();
        });

        self::assertSame(DeliveryOutcome::COMPLETE, $this->coordinator()->deliver($record, $claim)->outcome);
        self::assertSame(['entry' => 2, 'delivered' => 1], $levels);
        self::assertSame(0, DB::connection(self::CONNECTION)->transactionLevel());
        self::assertSame(1, $this->entryCount());
        self::assertSame(self::NOW, $this->receipt($record->record->id, 'store')['delivered_at'] ?? null);
    }

    /**
     * A receipt that fails to say a database destination has the record rolls
     * back the record's insert with it, so the entry and the receipt never
     * disagree: the delivery is incomplete, with nothing stored.
     *
     * @return void
     */
    public function testAFailedReceiptRollsBackItsInsert(): void
    {
        $this->bindStore(app(DatabaseAuditStore::class));

        [$record, $claim] = $this->claimedRecord();

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query): void {
            if (self::marksDelivered($query)) {
                throw new \DomainException('The receipt failed.');
            }
        });

        self::assertSame(DeliveryOutcome::INCOMPLETE, $this->coordinator()->deliver($record, $claim)->outcome);
        self::assertSame(0, $this->entryCount());
        self::assertNull($this->receipt($record->record->id, 'store')['delivered_at'] ?? null);
        self::assertSame(\DomainException::class, $this->receipt($record->record->id, 'store')['last_error_class'] ?? null);
        self::assertSame(0, DB::connection(self::CONNECTION)->transactionLevel());
    }

    /**
     * A log destination writes its line with no transaction open, and its
     * receipt follows, on its own.
     *
     * @return void
     */
    public function testALogDestinationSharesNoTransaction(): void
    {
        $levels = [];

        $this->captureLogLines();
        $this->bindStore(new LogAuditStore(app(LogManager::class), new NdjsonFormatter));

        [$record, $claim] = $this->claimedRecord();

        $this->onLogLine(static function () use (&$levels): void {
            $levels[] = DB::connection(self::CONNECTION)->transactionLevel();
        });

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query, array $bindings, $connection) use (&$levels): void {
            if (!self::marksDelivered($query)) {
                return;
            }

            $levels[] = $connection->transactionLevel();
        });

        self::assertSame(DeliveryOutcome::COMPLETE, $this->coordinator()->deliver($record, $claim)->outcome);
        self::assertSame([0, 0], $levels);
    }

    /**
     * A destination whose receipt says it has the record is not called again,
     * and its receipt is left as it is.
     *
     * @return void
     */
    public function testADeliveredDestinationIsNotCalledAgain(): void
    {
        $store = $this->bindStore(new PlainStore);

        [$record, $claim] = $this->claimedRecord();

        $this->coordinator()->deliver($record, $claim);

        $this->moveClockTo(self::PAST_THE_LEASE);

        self::assertSame(DeliveryOutcome::COMPLETE, $this->coordinator()->deliver($record, $this->reclaimed($record->record->id))->outcome);
        self::assertSame(1, $store->calls());
        self::assertSame(1, $this->receipt($record->record->id, 'store')['attempts'] ?? null);
        self::assertSame(self::NOW, $this->receipt($record->record->id, 'store')['delivered_at'] ?? null);
    }

    /**
     * A destination removed from the stack after it failed no longer blocks the
     * row: the next delivery is complete without it.
     *
     * @return void
     */
    public function testADestinationThatDisappearedStopsBlocking(): void
    {
        $this->recordingHandler();

        $kept = new PlainStore;

        $this->bindStore(new StackAuditStore(['kept' => $kept, 'gone' => CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: [])]));

        [$record, $claim] = $this->claimedRecord();

        self::assertSame(DeliveryOutcome::INCOMPLETE, $this->coordinator()->deliver($record, $claim)->outcome);

        $this->bindStore(new StackAuditStore(['kept' => $kept]));

        self::assertSame(DeliveryOutcome::COMPLETE, $this->coordinator()->deliver($record, $this->reclaimed($record->record->id))->outcome);
        self::assertSame(1, $kept->calls());
    }

    /**
     * The undelivered receipt of a destination removed from the stack is
     * reported once, as the row completes, naming the record and the
     * destination; an incomplete delivery reports nothing of it.
     *
     * @return void
     */
    public function testADestinationThatDisappearedIsReportedOnce(): void
    {
        $handler = $this->recordingHandler();
        $failing = CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: []);

        $this->bindStore(new StackAuditStore(['kept' => new PlainStore, 'gone' => $failing]));

        [$record, $claim] = $this->claimedRecord();

        $this->coordinator()->deliver($record, $claim);

        $this->bindStore(new StackAuditStore(['kept' => new PlainStore, 'other' => $failing]));

        self::assertSame(DeliveryOutcome::INCOMPLETE, $this->coordinator()->deliver($record, $this->reclaimed($record->record->id))->outcome);
        $incomplete = $handler->reports();

        self::assertSame([], $incomplete);

        $this->bindStore(new StackAuditStore(['kept' => new PlainStore]));

        self::assertSame(DeliveryOutcome::COMPLETE, $this->coordinator()->deliver($record, $this->reclaimed($record->record->id))->outcome);

        $reports = array_map(static fn (\Throwable $report): string => $report::class . ': ' . $report->getMessage(), $handler->reports());

        self::assertSame([
            \LogicException::class . ': Audit record ' . $record->record->id . ' has an undelivered receipt for the destination [gone],'
                . ' which the store no longer has; the record was delivered without it.',
            \LogicException::class . ': Audit record ' . $record->record->id . ' has an undelivered receipt for the destination [other],'
                . ' which the store no longer has; the record was delivered without it.',
        ], $reports);
    }

    /**
     * A destination removed from the stack once it had the record is not
     * reported.
     *
     * @return void
     */
    public function testADeliveredDestinationThatDisappearedIsNotReported(): void
    {
        $handler = $this->recordingHandler();

        $this->bindStore(new StackAuditStore([
            'kept'    => new PlainStore,
            'gone'    => new PlainStore,
            'failing' => CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: []),
        ]));

        [$record, $claim] = $this->claimedRecord();

        $this->coordinator()->deliver($record, $claim);

        $this->bindStore(new StackAuditStore(['kept' => new PlainStore, 'failing' => new PlainStore]));

        self::assertSame(DeliveryOutcome::COMPLETE, $this->coordinator()->deliver($record, $this->reclaimed($record->record->id))->outcome);
        self::assertSame([], $handler->reports());
    }

    /**
     * A broken reporter of a removed destination is contained: the delivery is
     * still complete.
     *
     * @return void
     */
    public function testABrokenReporterOfADisappearedDestinationIsContained(): void
    {
        $handler = $this->recordingHandler(throwsOnReport: true);

        $this->bindStore(new StackAuditStore(['kept' => new PlainStore, 'gone' => CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: [])]));

        [$record, $claim] = $this->claimedRecord();

        $this->coordinator()->deliver($record, $claim);

        $this->bindStore(new StackAuditStore(['kept' => new PlainStore]));

        self::assertSame(DeliveryOutcome::COMPLETE, $this->coordinator()->deliver($record, $this->reclaimed($record->record->id))->outcome);
        self::assertCount(1, $handler->reports());
    }

    /**
     * A destination added to the stack after the row was first attempted is
     * delivered, and those that already have the record are not called again.
     *
     * @return void
     */
    public function testANewDestinationIsDelivered(): void
    {
        $kept  = new PlainStore;
        $added = new PlainStore;

        $this->bindStore(new StackAuditStore(['kept' => $kept, 'failing' => CallbackStore::failingWith(new \DomainException('Down.'), participatesOn: [])]));

        [$record, $claim] = $this->claimedRecord();

        $this->coordinator()->deliver($record, $claim);

        $this->bindStore(new StackAuditStore(['kept' => $kept, 'failing' => new PlainStore, 'added' => $added]));

        self::assertSame(DeliveryOutcome::COMPLETE, $this->coordinator()->deliver($record, $this->reclaimed($record->record->id))->outcome);
        self::assertSame(1, $kept->calls());
        self::assertSame(1, $added->calls());
        self::assertSame(self::NOW, $this->receipt($record->record->id, 'added')['delivered_at'] ?? null);
    }

    /**
     * The claim is renewed before each destination's attempt is counted and
     * before each receipt, and a failure's receipt follows a renewal too.
     *
     * @return void
     */
    public function testARenewalPrecedesEachDestination(): void
    {
        $this->bindStore(new StackAuditStore([
            'first'  => $this->recordingStep('first'),
            'second' => $this->recordingStep('second', fail: true),
        ]));

        [$record, $claim] = $this->claimedRecord();

        $this->recordWrites();

        $this->coordinator()->deliver($record, $claim);

        self::assertSame([
            'renew', 'attempt', 'call first', 'renew', 'delivered',
            'renew', 'attempt', 'call second', 'renew', 'failed',
        ], $this->steps);
    }

    /**
     * A claim lost before a destination is called stops the row there: the
     * destination is not called and no receipt is written.
     *
     * @return void
     */
    public function testALostClaimBeforeADestinationStopsTheRow(): void
    {
        $store = $this->bindStore(new PlainStore);

        [$record, $claim] = $this->claimedRecord();

        $this->moveClockTo(self::PAST_THE_LEASE);
        $this->reclaimed($record->record->id);

        self::assertSame(DeliveryOutcome::STALE, $this->coordinator()->deliver($record, $claim)->outcome);
        self::assertSame(0, $store->calls());
        self::assertSame(0, $this->receiptCount());
    }

    /**
     * A claim lost while a destination is called writes no receipt of the call,
     * even though it succeeded, and the remaining destinations are not called:
     * the new owner repeats the work.
     *
     * @return void
     */
    public function testALostClaimAfterADestinationWritesNoReceipt(): void
    {
        $second = new PlainStore;
        $owner  = null;

        $this->bindStore(new StackAuditStore([
            'first' => new CallbackStore(function (FinalisedRecord $record) use (&$owner): void {
                $this->moveClockTo(self::PAST_THE_LEASE);

                $owner = $this->reclaimed($record->record->id);
            }, participatesOn: []),
            'second' => $second,
        ]));

        [$record, $claim] = $this->claimedRecord();

        self::assertSame(DeliveryOutcome::STALE, $this->coordinator()->deliver($record, $claim)->outcome);
        self::assertSame(0, $second->calls());
        self::assertSame(1, $this->receipt($record->record->id, 'first')['attempts'] ?? null);
        self::assertNull($this->receipt($record->record->id, 'first')['delivered_at'] ?? null);
        self::assertNull($this->receipt($record->record->id, 'second'));
        self::assertInstanceOf(OutboxClaim::class, $owner);
        self::assertSame($owner->token, $this->outboxRow($record->record->id)['claimed_by'] ?? null);
    }

    /**
     * A claim lost while a destination is failing writes no receipt of the
     * failure.
     *
     * @return void
     */
    public function testALostClaimDuringAFailureWritesNoReceipt(): void
    {
        $this->bindStore(new CallbackStore(function (FinalisedRecord $record): void {
            $this->moveClockTo(self::PAST_THE_LEASE);
            $this->reclaimed($record->record->id);

            throw new \DomainException('Down.');
        }, participatesOn: []));

        [$record, $claim] = $this->claimedRecord();

        self::assertSame(DeliveryOutcome::STALE, $this->coordinator()->deliver($record, $claim)->outcome);
        self::assertNull($this->receipt($record->record->id, 'store')['last_error_class'] ?? null);
    }

    /**
     * A claim lost while a database destination is called inside its shared
     * transaction rolls that transaction back: no entry and no delivered
     * receipt, while the new owner keeps the row. The lost claim is read as
     * such, not as a failure of the destination, so the claim is not renewed
     * again to write a failed receipt.
     *
     * @return void
     */
    public function testALostClaimInASharedTransactionRollsItBack(): void
    {
        $this->moveOutboxToItsOwnConnection();

        $owner = null;

        $this->bindStore(new CallbackStore(function (FinalisedRecord $record) use (&$owner): void {
            app(DatabaseAuditStore::class)->store($record);

            $this->moveClockTo(self::PAST_THE_LEASE);

            $owner = $this->reclaimed($record->record->id);
        }, participatesOn: [self::CONNECTION]));

        [$record, $claim] = $this->claimedRecord();

        $renewals = 0;

        DB::listen(static function (QueryExecuted $query) use (&$renewals): void {
            if (preg_match('/\Aupdate .* set [`"]?claimed_until[`"]? = \? where .*claimed_by/', $query->sql) !== 1) {
                return;
            }

            $renewals++;
        });

        self::assertSame(DeliveryOutcome::STALE, $this->coordinator()->deliver($record, $claim)->outcome);
        self::assertSame(2, $renewals);
        self::assertSame(0, $this->entryCount());
        self::assertNull($this->receipt($record->record->id, 'store')['delivered_at'] ?? null);
        self::assertNull($this->receipt($record->record->id, 'store')['last_error_class'] ?? null);
        self::assertSame(0, DB::connection(self::CONNECTION)->transactionLevel());
        self::assertInstanceOf(OutboxClaim::class, $owner);
        self::assertSame($owner->token, $this->outboxRow($record->record->id)['claimed_by'] ?? null);
    }

    /**
     * The write guard is active while a destination is called, and released
     * once it returns.
     *
     * @return void
     */
    public function testTheGuardIsActiveDuringADestination(): void
    {
        $active = null;

        $this->bindStore(new CallbackStore(static function () use (&$active): void {
            $active = app(WriteGuard::class)->isActive();
        }, participatesOn: []));

        [$record, $claim] = $this->claimedRecord();

        $this->coordinator()->deliver($record, $claim);

        self::assertTrue($active);
        self::assertFalse(app(WriteGuard::class)->isActive());
    }

    /**
     * The write guard is released when a destination throws.
     *
     * @return void
     */
    public function testTheGuardIsReleasedAfterADestinationThrows(): void
    {
        $active = null;

        $this->bindStore(new CallbackStore(static function () use (&$active): void {
            $active = app(WriteGuard::class)->isActive();

            throw new \DomainException('Down.');
        }, participatesOn: []));

        [$record, $claim] = $this->claimedRecord();

        self::assertSame(DeliveryOutcome::INCOMPLETE, $this->coordinator()->deliver($record, $claim)->outcome);
        self::assertTrue($active);
        self::assertFalse(app(WriteGuard::class)->isActive());
    }

    /**
     * A failure belongs to the delivery that made it, so a coordinator holds
     * none between deliveries.
     *
     * @return void
     */
    public function testAFailureBelongsToItsOwnDelivery(): void
    {
        $calls = 0;

        $this->bindStore(self::failingOnce($calls));

        [$record, $claim] = $this->claimedRecord();

        $coordinator = $this->coordinator();

        self::assertSame(DeliveryOutcome::INCOMPLETE, $coordinator->deliver($record, $claim)->outcome);
        self::assertSame(DeliveryOutcome::COMPLETE, $coordinator->deliver($record, $this->reclaimed($record->record->id))->outcome);
    }

    /**
     * A record, finalised, put in the outbox and claimed now.
     *
     * @return array{0: \SineMacula\Laravel\AuditLog\Records\FinalisedRecord, 1: \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim}
     */
    private function claimedRecord(): array
    {
        $record = $this->finalisedRecord();

        return [$record, $this->reclaimed($this->enqueue($record))];
    }

    /**
     * A new claim on the row, which must be claimable now: unclaimed, or its
     * lease passed, or released by the claim before it.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim
     */
    private function reclaimed(string $id): OutboxClaim
    {
        $outbox = app(Outbox::class);

        $outbox->connection()->table(DeliveryTables::outboxTable())->where('id', $id)->update(['claimed_until' => null]);

        $claim = $outbox->claim($id, CarbonImmutable::now());

        self::assertNotNull($claim, "The row {$id} could not be claimed.");

        return $claim;
    }

    /**
     * The coordinator, as the container builds it.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\DeliveryCoordinator
     */
    private function coordinator(): DeliveryCoordinator
    {
        return app(DeliveryCoordinator::class);
    }

    /**
     * Bind the store and return it.
     *
     * @template TStore of \SineMacula\Laravel\AuditLog\Contracts\AuditStore
     *
     * @param  TStore  $store
     * @return TStore
     */
    private function bindStore(AuditStore $store): AuditStore
    {
        app()->instance(AuditStore::class, $store);

        return $store;
    }

    /**
     * Bind a handler that keeps what it is asked to report and return it.
     *
     * @param  bool  $throwsOnReport
     * @return \Tests\Fixtures\Privacy\RecordingExceptionHandler
     */
    private function recordingHandler(bool $throwsOnReport = false): RecordingExceptionHandler
    {
        $handler = new RecordingExceptionHandler($throwsOnReport);

        app()->instance(ExceptionHandler::class, $handler);

        return $handler;
    }

    /**
     * A destination that notes its call among the steps, then fails when told
     * to.
     *
     * @param  string  $name
     * @param  bool  $fail
     * @return \Tests\Fixtures\Stores\CallbackStore
     */
    private function recordingStep(string $name, bool $fail = false): CallbackStore
    {
        return new CallbackStore(function () use ($name, $fail): void {
            $this->steps[] = 'call ' . $name;

            if ($fail) {
                throw new \DomainException('Down.');
            }
        }, participatesOn: []);
    }

    /**
     * Note each write of the outbox or the deliveries table among the steps, by
     * what it does: a renewal, an attempt counted, a receipt delivered or
     * failed.
     *
     * @return void
     */
    private function recordWrites(): void
    {
        DB::listen(function (QueryExecuted $query): void {
            $sql = $query->sql;

            $step = match (true) {
                str_starts_with($sql, 'update ')                      && str_contains($sql, DeliveryTables::outboxTable()) && str_contains($sql, 'claimed_until') => 'renew',
                str_contains($sql, DeliveryTables::deliveriesTable()) && str_contains($sql, 'attempts') && !str_starts_with($sql, 'select ')                      => 'attempt',
                self::marksDelivered($sql)                                                                                                                        => 'delivered',
                str_starts_with($sql, 'update ') && str_contains($sql, DeliveryTables::deliveriesTable())                                                         => 'failed',
                default                                                                                                                                           => null,
            };

            if ($step === null) {
                return;
            }

            $this->steps[] = $step;
        });
    }

    /**
     * A destination that is neither durable nor joins a transaction, counting
     * its calls on the counter given, and failing on its first call alone.
     *
     * @param  int  $calls
     * @return \Tests\Fixtures\Stores\CallbackStore
     */
    private static function failingOnce(int &$calls): CallbackStore
    {
        return new CallbackStore(static function () use (&$calls): void {
            if (++$calls > 1) {
                return;
            }

            throw new \DomainException('Down.');
        }, participatesOn: []);
    }

    /**
     * Whether the statement marks a receipt delivered: an update that sets
     * `delivered_at`, as against one that only reads it in its condition.
     *
     * @param  string  $sql
     * @return bool
     */
    private static function marksDelivered(string $sql): bool
    {
        return preg_match('/\Aupdate .* set [`"]?delivered_at[`"]? = /', $sql) === 1;
    }
}
