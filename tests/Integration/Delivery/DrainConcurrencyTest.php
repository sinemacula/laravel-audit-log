<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\DeliveryCoordinator;
use SineMacula\Laravel\AuditLog\Delivery\DrainResult;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\Receipts;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Integration tests for two real processes draining one outbox, each with its
 * own clock, meeting on file gates instead of timing.
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
final class DrainConcurrencyTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, RunsKilledChildren, SeedsTheOutbox;

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var string The instant a claim taken at the start ends its lease. */
    private const string LEASE_END = '2026-11-01T12:05:00.000000Z';

    /** @var string The microsecond after that lease ends. */
    private const string JUST_PAST_THE_LEASE = '2026-11-01T12:05:00.000001Z';

    /** @var string Past the lease of a claim taken at the start. */
    private const string PAST_THE_LEASE = '2026-11-01T12:05:01.000000Z';

    /** @var string The claim: the one update of the outbox that counts an attempt. */
    private const string CLAIM = '/^update \S*audit_log_outbox\S* set \S*attempts/';

    /** @var string The file each destination call is named in. */
    private const string CALLS = 'calls';

    /** @var string The file a child leaves what it found in. */
    private const string RESULT = 'result';

    /** @var string The gate that starts a race. */
    private const string START = 'start';

    /** @var string The gate a child opens once it has reached where it is held. */
    private const string ARRIVED = 'arrived';

    /** @var string The gate that lets a held child go on. */
    private const string RELEASE = 'release';

    /**
     * Stop the clock at the start of the test.
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
     * Reset the clock, and remove the children's shared files after the
     * migrations roll back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * Two processes draining 50 rows at once deliver every record exactly once.
     *
     * @return void
     */
    public function testOneOwnerBeforeExpiry(): void
    {
        $this->bindCountingStore();

        $ids = array_map(fn (): string => $this->enqueue($this->finalisedRecord()), range(1, 50));

        $child = $this->startChild(function (): void {
            $this->awaitGate(self::START);
            $this->leaveTally($this->drain());
        });

        $this->openGate(self::START);

        $result = $this->drain();

        $this->assertKilled($this->waitForChild($child));

        $calls = $this->childFileLines(self::CALLS);

        sort($calls);
        sort($ids);

        self::assertSame($ids, $calls);
        self::assertSame(50, $result->delivered() + $this->leftTally()['delivered']);
        self::assertSame(0, $result->stale() + $this->leftTally()['stale']);
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * When the parent claims a row first, a child already holding it as a
     * candidate claims nothing.
     *
     * @return void
     */
    public function testAConditionalUpdateHasOneWinner(): void
    {
        $id  = $this->enqueue($this->finalisedRecord());
        $due = CarbonImmutable::now();

        $child = $this->startChild(function () use ($id, $due): void {
            $this->holdBeforeTheClaim();

            file_put_contents($this->childFile(self::RESULT), app(Outbox::class)->claim($id, $due) === null ? 'lost' : 'won');
        });

        $this->awaitGate(self::ARRIVED);

        $winner = app(Outbox::class)->claim($id, $due);

        $this->openGate(self::RELEASE);

        $this->assertKilled($this->waitForChild($child));

        self::assertNotNull($winner);
        self::assertSame('lost', file_get_contents($this->childFile(self::RESULT)));
        self::assertSame($winner->token, $this->outboxRow($id)['claimed_by'] ?? null);
        self::assertSame(1, $this->outboxRow($id)['attempts'] ?? null);
    }

    /**
     * A row whose worker was killed after claiming it can be reclaimed only
     * after its lease, with both attempts counted.
     *
     * @return void
     */
    public function testAnExpiredLeaseIsReclaimed(): void
    {
        $this->bindCountingStore();

        $id = $this->enqueue($this->finalisedRecord());

        $this->assertKilled($this->runChild(function (): void {
            $this->drain();
        }, killAfter: self::CLAIM));

        self::assertSame([0, 0, 0, 0, 0], self::tallyOf($this->drain()));

        $this->moveClockTo(self::LEASE_END);

        self::assertSame([0, 0, 0, 0, 0], self::tallyOf($this->drain()));
        self::assertSame(1, $this->outboxRow($id)['attempts'] ?? null);

        $this->moveClockTo(self::JUST_PAST_THE_LEASE);

        self::assertSame([1, 0, 0, 0, 0], self::tallyOf($this->drain()));
        self::assertSame([$id], $this->childFileLines(self::CALLS));
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * While a first worker is alive inside its lease, a second drain has
     * nothing to take.
     *
     * @return void
     */
    public function testAFirstWorkerAliveOnItsLeaseKeepsTheRow(): void
    {
        $this->bindHeldStore();

        $id = $this->enqueue($this->finalisedRecord());

        $child = $this->startChild(function (): void {
            $this->leaveTally($this->drain());
        });

        $this->awaitGate(self::ARRIVED);

        self::assertSame([0, 0, 0, 0, 0], self::tallyOf($this->drain()));
        self::assertSame(1, $this->outboxRow($id)['attempts'] ?? null);

        $this->openGate(self::RELEASE);

        $this->assertKilled($this->waitForChild($child));

        self::assertSame(1, $this->leftTally()['delivered']);
        self::assertSame([$id], $this->childFileLines(self::CALLS));
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * Rows of `[what the first worker's call does once it is released]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideFirstWorkerCalls(): iterable
    {
        yield from [
            'its call succeeds, so it would write a receipt and delete' => [false],
            'its call fails, so it would write a failure and retry'     => [true],
        ];
    }

    /**
     * A first worker alive past its lease is stale: its receipt, retry and
     * delete change nothing the new owner left.
     *
     * @param  bool  $fails
     * @return void
     */
    #[DataProvider('provideFirstWorkerCalls')]
    public function testAFirstWorkerAlivePastItsLeaseIsRejected(bool $fails): void
    {
        $this->bindHeldStore($fails);

        $id = $this->enqueue($this->finalisedRecord());

        $child = $this->startChild(function (): void {
            $this->leaveTally($this->drain());
        });

        $this->awaitGate(self::ARRIVED);

        $this->moveClockTo(self::PAST_THE_LEASE);

        self::assertSame([1, 0, 0, 0, 0], self::tallyOf($this->drain()));

        $receipt = $this->receipt($id, DeliveryCoordinator::STORE_DESTINATION);

        self::assertSame(self::PAST_THE_LEASE, $receipt['delivered_at'] ?? null);
        self::assertSame(2, $receipt['attempts'] ?? null);

        $this->openGate(self::RELEASE);

        $this->assertKilled($this->waitForChild($child));

        self::assertSame(1, $this->leftTally()['stale']);
        self::assertSame(0, $this->leftTally()['delivered'] + $this->leftTally()['retried']);
        self::assertSame($receipt, $this->receipt($id, DeliveryCoordinator::STORE_DESTINATION));
        self::assertNull($this->outboxRow($id));
    }

    /**
     * A stale claim cannot renew, retry, fail or delete a new owner's
     * unfinished row.
     *
     * @return void
     */
    public function testAStaleClaimChangesNothingOfANewOwnersRow(): void
    {
        $id  = $this->enqueue($this->finalisedRecord());
        $due = CarbonImmutable::now();

        $child = $this->startChild(function () use ($id, $due): void {
            $outbox = app(Outbox::class);
            $claim  = $outbox->claim($id, $due);

            assert($claim !== null);

            $this->openGate(self::ARRIVED);
            $this->awaitGate(self::RELEASE);

            file_put_contents($this->childFile(self::RESULT), json_encode([
                $outbox->renew($claim),
                $outbox->retry($claim, CarbonImmutable::now(), 'Stale'),
                $outbox->fail($claim, 'Stale'),
                $outbox->delete($claim),
            ], JSON_THROW_ON_ERROR));
        });

        $this->awaitGate(self::ARRIVED);

        $this->moveClockTo(self::PAST_THE_LEASE);

        $owner = app(Outbox::class)->claim($id, CarbonImmutable::now());

        self::assertNotNull($owner);

        $row = $this->outboxRow($id);

        $this->openGate(self::RELEASE);

        $this->assertKilled($this->waitForChild($child));

        self::assertSame('[false,false,false,false]', file_get_contents($this->childFile(self::RESULT)));
        self::assertSame($row, $this->outboxRow($id));
        self::assertSame(2, $row['attempts'] ?? null);
        self::assertSame($owner->token, $row['claimed_by'] ?? null);
        self::assertTrue(app(Outbox::class)->delete($owner));
    }

    /**
     * A stale worker and a new owner storing one record leave one entry, with
     * both attempts on its receipt.
     *
     * @return void
     */
    public function testIdempotentRecoveryAfterExpiry(): void
    {
        $parent     = posix_getpid();
        $database   = app(DatabaseAuditStore::class);
        $connection = StorageConnection::resolvedName();

        app()->instance(AuditStore::class, new CallbackStore(function (FinalisedRecord $record) use ($parent, $database): void {
            $this->appendToChildFile(self::CALLS, $record->record->id);

            if (posix_getpid() !== $parent) {
                $this->openGate(self::ARRIVED);
                $this->awaitGate(self::RELEASE);
            }

            $database->store($record);
        }, participatesOn: [$connection]));

        $id = $this->enqueue($this->finalisedRecord());

        $child = $this->startChild(function (): void {
            $this->leaveTally($this->drain());
        });

        $this->awaitGate(self::ARRIVED);

        $this->moveClockTo(self::PAST_THE_LEASE);

        self::assertSame([1, 0, 0, 0, 0], self::tallyOf($this->drain()));

        $this->openGate(self::RELEASE);

        $this->assertKilled($this->waitForChild($child));

        self::assertSame(1, $this->leftTally()['stale']);
        self::assertSame([$id, $id], $this->childFileLines(self::CALLS));
        self::assertSame(1, $this->entryCount());
        self::assertSame(2, $this->receipt($id, DeliveryCoordinator::STORE_DESTINATION)['attempts'] ?? null);
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * Two processes racing due retries through the database store store each
     * row once and clear each failure.
     *
     * @return void
     */
    public function testConcurrentRetriesStoreOnce(): void
    {
        app()->instance(AuditStore::class, CallbackStore::failingWith(new \DomainException('Down.')));

        $ids = array_map(fn (): string => $this->enqueue($this->finalisedRecord()), range(1, 20));

        self::assertSame(20, $this->drain()->retried());

        $database   = app(DatabaseAuditStore::class);
        $connection = StorageConnection::resolvedName();

        app()->instance(AuditStore::class, new CallbackStore(function (FinalisedRecord $record) use ($database): void {
            $this->appendToChildFile(self::CALLS, $record->record->id);

            $database->store($record);
        }, participatesOn: [$connection]));

        // Past the wait of a first failure
        $this->moveClockTo('2026-11-01T12:01:01.000000Z');

        $child = $this->startChild(function (): void {
            $this->awaitGate(self::START);
            $this->leaveTally($this->drain());
        });

        $this->openGate(self::START);

        $result = $this->drain();

        $this->assertKilled($this->waitForChild($child));

        $calls = $this->childFileLines(self::CALLS);

        sort($calls);
        sort($ids);

        self::assertSame($ids, $calls);
        self::assertSame(20, $result->delivered() + $this->leftTally()['delivered']);
        self::assertSame(20, $this->entryCount());
        self::assertSame(0, $this->outboxCount());

        foreach ($ids as $id) {
            $receipt = $this->receipt($id, DeliveryCoordinator::STORE_DESTINATION);

            self::assertNotNull($receipt);
            self::assertSame(2, $receipt['attempts']);
            self::assertNotNull($receipt['delivered_at']);
            self::assertNull($receipt['last_error_class']);
        }
    }

    /**
     * A destination slower than the whole lease is followed by a renewal, so a
     * second drain finds nothing to take.
     *
     * @return void
     */
    public function testADestinationSlowerThanTheLeaseIsRenewedBetweenDestinations(): void
    {
        app()->instance(AuditStore::class, new StackAuditStore([
            'slow' => new CallbackStore(function (): void {
                $this->appendToChildFile(self::CALLS, 'slow');

                // Longer than the whole lease, on this worker's own clock
                $this->moveClockTo('2026-11-01T12:05:50.000000Z');
            }),
            'next' => new CallbackStore(function (): void {
                $this->appendToChildFile(self::CALLS, 'next');
                $this->openGate(self::ARRIVED);
                $this->awaitGate(self::RELEASE);
            }),
        ]));

        $id = $this->enqueue($this->finalisedRecord());

        $child = $this->startChild(function (): void {
            $this->leaveTally($this->drain());
        });

        $this->awaitGate(self::ARRIVED);

        // Past the lease of the claim, inside the one its renewals took
        $this->moveClockTo('2026-11-01T12:06:40.000000Z');

        self::assertSame('2026-11-01T12:10:50.000000Z', $this->outboxRow($id)['claimed_until'] ?? null);
        self::assertSame([0, 0, 0, 0, 0], self::tallyOf($this->drain()));

        $this->openGate(self::RELEASE);

        $this->assertKilled($this->waitForChild($child));

        self::assertSame(1, $this->leftTally()['delivered']);
        self::assertSame(['slow', 'next'], $this->childFileLines(self::CALLS));
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * Put the database on a file SQLite can share across a fork.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->useFileDatabaseOnSqlite($app);
    }

    /**
     * Bind a store that joins no transaction and names each record it gets in a
     * file.
     *
     * @return void
     */
    private function bindCountingStore(): void
    {
        app()->instance(AuditStore::class, new CallbackStore(function (FinalisedRecord $record): void {
            $this->appendToChildFile(self::CALLS, $record->record->id);
        }));
    }

    /**
     * Bind a counting store that holds a child inside the call until released,
     * then fails the call when told to.
     *
     * @param  bool  $childFails
     * @return void
     */
    private function bindHeldStore(bool $childFails = false): void
    {
        $parent = posix_getpid();

        app()->instance(AuditStore::class, new CallbackStore(function (FinalisedRecord $record) use ($parent, $childFails): void {
            $this->appendToChildFile(self::CALLS, $record->record->id);

            if (posix_getpid() === $parent) {
                return;
            }

            $this->openGate(self::ARRIVED);
            $this->awaitGate(self::RELEASE);

            if ($childFails) {
                throw new \DomainException('Down.');
            }
        }));
    }

    /**
     * Hold this process just before its claim's update, after saying it
     * arrived, until released.
     *
     * @return void
     */
    private function holdBeforeTheClaim(): void
    {
        DB::connection()->beforeExecuting(function (string $query): void {
            if (preg_match(self::CLAIM, $query) !== 1) {
                return;
            }

            $this->openGate(self::ARRIVED);
            $this->awaitGate(self::RELEASE);
        });
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
     * The tally's counts: delivered, retried, failed, stale and missed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return list<int>
     */
    private static function tallyOf(DrainResult $result): array
    {
        return [$result->delivered(), $result->retried(), $result->failed(), $result->stale(), $result->missed()];
    }

    /**
     * Leave this process's tally for its parent to read.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return void
     */
    private function leaveTally(DrainResult $result): void
    {
        file_put_contents($this->childFile(self::RESULT), json_encode([
            'delivered' => $result->delivered(),
            'retried'   => $result->retried(),
            'failed'    => $result->failed(),
            'stale'     => $result->stale(),
            'missed'    => $result->missed(),
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * The tally the child left.
     *
     * @return array{delivered: int, retried: int, failed: int, stale: int, missed: int}
     */
    private function leftTally(): array
    {
        /** @var array{delivered: int, retried: int, failed: int, stale: int, missed: int} */
        return json_decode((string) file_get_contents($this->childFile(self::RESULT)), true, flags: JSON_THROW_ON_ERROR);
    }
}
