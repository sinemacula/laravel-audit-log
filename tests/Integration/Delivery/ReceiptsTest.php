<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\DeliveryCoordinator;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\Receipt;
use SineMacula\Laravel\AuditLog\Delivery\Receipts;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\InteractsWithReadWriteSplit;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for the delivery receipts on SQLite, MySQL and PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Receipts::class)]
#[CoversClass(Receipt::class)]
final class ReceiptsTest extends TestCase
{
    use InteractsWithOutbox, InteractsWithReadWriteSplit, MockeryPHPUnitIntegration, SeedsTheOutbox;

    /** @var string The instant the clock is stopped at. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var string The entry receipts are pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string A second entry. */
    private const string SECOND_ID = '01932b4e-8a40-7000-8000-000000000002';

    /** @var string The destination receipts are pinned to. */
    private const string DESTINATION = 'store';

    /** @var string A second destination. */
    private const string SECOND_DESTINATION = 'siem.primary';

    /** @var string A table the host transaction writes to. */
    private const string HOST_TABLE = 'audit_host_writes';

    /**
     * Stop the clock.
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
     * Roll back any open transaction, undo the test's changes and release the
     * clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(StorageConnection::name());

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        $this->removeMovedOutbox();
        $this->removeReadWriteSplit();

        Schema::dropIfExists(self::HOST_TABLE);

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A first attempt makes an undelivered receipt with one attempt and no
     * error.
     *
     * @return void
     */
    public function testAFirstAttemptMakesAReceipt(): void
    {
        $this->receipts()->attempting(self::ID, self::DESTINATION, null);

        self::assertSame(1, $this->receiptCount());
        self::assertSame([
            'entry_id'           => self::ID,
            'destination'        => self::DESTINATION,
            'attempts'           => 1,
            'first_attempted_at' => self::NOW,
            'delivered_at'       => null,
            'last_error_class'   => null,
        ], $this->receipt(self::ID, self::DESTINATION));
    }

    /**
     * Outside a transaction a first attempt opens none.
     *
     * @return void
     */
    public function testAFirstAttemptOutsideATransactionUsesNoSavepoint(): void
    {
        $began  = 0;
        $levels = [];

        Event::listen(TransactionBeginning::class, static function () use (&$began): void {
            $began++;
        });

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query, array $bindings, Connection $connection) use (&$levels): void {
            $levels[] = $connection->transactionLevel();
        });

        $this->receipts()->attempting(self::ID, self::DESTINATION, null);

        self::assertSame(0, $began);
        self::assertSame([0], $levels);
        self::assertSame(1, $this->receiptCount());
    }

    /**
     * Inside a host transaction a first attempt runs in a savepoint, and the
     * host returns to its own level.
     *
     * @return void
     */
    public function testAFirstAttemptInsideATransactionRunsInASavepoint(): void
    {
        $connection = DB::connection(StorageConnection::name());
        $inserts    = [];

        $connection->beforeExecuting(static function (string $query, array $bindings, Connection $connection) use (&$inserts): void {
            if (!str_starts_with($query, 'insert into')) {
                return;
            }

            $inserts[] = $connection->transactionLevel();
        });

        $connection->beginTransaction();

        $this->receipts()->attempting(self::ID, self::DESTINATION, null);

        self::assertSame([2], $inserts);
        self::assertSame(1, $connection->transactionLevel());

        $connection->commit();

        self::assertSame(1, $this->receiptCount());
    }

    /**
     * A later attempt counts one more and keeps when the first was made.
     *
     * @return void
     */
    public function testALaterAttemptCounts(): void
    {
        $receipts = $this->receipts();

        $receipts->attempting(self::ID, self::DESTINATION, null);

        $this->moveClockTo('2026-11-01T12:10:00.000000Z');

        $receipts->attempting(self::ID, self::DESTINATION, $receipts->forEntry(self::ID)[self::DESTINATION]);
        $receipts->attempting(self::ID, self::DESTINATION, $receipts->forEntry(self::ID)[self::DESTINATION]);

        self::assertSame(3, $this->receipt(self::ID, self::DESTINATION)['attempts'] ?? null);
        self::assertSame(self::NOW, $this->receipt(self::ID, self::DESTINATION)['first_attempted_at'] ?? null);
        self::assertSame(1, $this->receiptCount());
    }

    /**
     * A first attempt that finds a racing owner's receipt counts on it instead.
     *
     * @return void
     */
    public function testARacingFirstAttemptFallsToAnUpdate(): void
    {
        $receipts = $this->receipts();

        $receipts->attempting(self::ID, self::DESTINATION, null);
        $receipts->attempting(self::ID, self::DESTINATION, null);

        self::assertSame(1, $this->receiptCount());
        self::assertSame(2, $this->receipt(self::ID, self::DESTINATION)['attempts'] ?? null);
    }

    /**
     * A racing first attempt inside a host rolls back only its savepoint, and
     * the host commits.
     *
     * @return void
     */
    public function testARacingFirstAttemptInsideATransactionLeavesItUsable(): void
    {
        Schema::create(self::HOST_TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('name', 32);
        });

        $receipts   = $this->receipts();
        $connection = $receipts->connection();

        $receipts->attempting(self::ID, self::DESTINATION, null);

        $connection->beginTransaction();

        $receipts->attempting(self::ID, self::DESTINATION, null);

        self::assertSame(1, $connection->transactionLevel());

        $connection->table(self::HOST_TABLE)->insert(['name' => 'after']);
        $connection->commit();

        self::assertSame(['after'], $connection->table(self::HOST_TABLE)->pluck('name')->all());
        self::assertSame(2, $this->receipt(self::ID, self::DESTINATION)['attempts'] ?? null);
    }

    /**
     * A delivered receipt keeps its delivery time, attempts and cleared error
     * whatever is asked later.
     *
     * @return void
     */
    public function testADeliveredReceiptKeepsItsTime(): void
    {
        $receipts = $this->receipts();

        $receipts->attempting(self::ID, self::DESTINATION, null);

        $this->moveClockTo('2026-11-01T12:00:01.000000Z');

        $receipts->delivered(self::ID, self::DESTINATION);

        $delivered = $this->receipt(self::ID, self::DESTINATION);

        $this->moveClockTo('2026-11-01T12:30:00.000000Z');

        $receipts->delivered(self::ID, self::DESTINATION);
        $receipts->attempting(self::ID, self::DESTINATION, $receipts->forEntry(self::ID)[self::DESTINATION]);
        $receipts->attempting(self::ID, self::DESTINATION, null);

        self::assertSame('2026-11-01T12:00:01.000000Z', $delivered['delivered_at'] ?? null);
        self::assertSame($delivered, $this->receipt(self::ID, self::DESTINATION));
    }

    /**
     * A failure names the error's class on the receipt, and leaves it
     * undelivered.
     *
     * @return void
     */
    public function testAFailureNamesItsClass(): void
    {
        $receipts = $this->receipts();

        $receipts->attempting(self::ID, self::DESTINATION, null);
        $receipts->failed(self::ID, self::DESTINATION, \RuntimeException::class);

        self::assertSame(\RuntimeException::class, $this->receipt(self::ID, self::DESTINATION)['last_error_class'] ?? null);
        self::assertNull($this->receipt(self::ID, self::DESTINATION)['delivered_at'] ?? null);
        self::assertFalse($receipts->forEntry(self::ID)[self::DESTINATION]->delivered);
    }

    /**
     * An error class longer than its column is cut to the column, never
     * refused.
     *
     * @return void
     */
    public function testALongErrorClassIsCutToItsColumn(): void
    {
        $receipts = $this->receipts();
        $class    = 'App\\' . str_repeat('Nested\\', 40) . 'Failure';

        $receipts->attempting(self::ID, self::DESTINATION, null);
        $receipts->failed(self::ID, self::DESTINATION, $class);

        self::assertSame(substr($class, 0, WriteDiagnostics::CLASS_MAX_BYTES), $this->receipt(self::ID, self::DESTINATION)['last_error_class'] ?? null);
    }

    /**
     * An error class is cut on a character boundary, never mid-character.
     *
     * @return void
     */
    public function testAnErrorClassIsCutOnACharacterBoundary(): void
    {
        $receipts = $this->receipts();
        $class    = 'App\\' . str_repeat('é', 100);

        $receipts->attempting(self::ID, self::DESTINATION, null);
        $receipts->failed(self::ID, self::DESTINATION, $class);

        $stored = $this->receipt(self::ID, self::DESTINATION)['last_error_class'] ?? null;

        self::assertSame(mb_strcut($class, 0, WriteDiagnostics::CLASS_MAX_BYTES, 'UTF-8'), $stored);
        self::assertSame(WriteDiagnostics::CLASS_MAX_BYTES - 1, strlen($stored));
    }

    /**
     * A failure reported after a delivery never undoes it.
     *
     * @return void
     */
    public function testAFailureNeverOverwritesADelivery(): void
    {
        $receipts = $this->receipts();

        $receipts->attempting(self::ID, self::DESTINATION, null);
        $receipts->delivered(self::ID, self::DESTINATION);

        $delivered = $this->receipt(self::ID, self::DESTINATION);

        $receipts->failed(self::ID, self::DESTINATION, \RuntimeException::class);

        self::assertSame($delivered, $this->receipt(self::ID, self::DESTINATION));
        self::assertNull($this->receipt(self::ID, self::DESTINATION)['last_error_class'] ?? null);
    }

    /**
     * A delivery after a failed attempt clears the error the failure named.
     *
     * @return void
     */
    public function testADeliveryClearsTheLastError(): void
    {
        $receipts = $this->receipts();

        $receipts->attempting(self::ID, self::DESTINATION, null);
        $receipts->failed(self::ID, self::DESTINATION, \RuntimeException::class);
        $receipts->attempting(self::ID, self::DESTINATION, $receipts->forEntry(self::ID)[self::DESTINATION]);
        $receipts->delivered(self::ID, self::DESTINATION);

        $receipt = $this->receipt(self::ID, self::DESTINATION);

        self::assertNull($receipt['last_error_class'] ?? null);
        self::assertSame(self::NOW, $receipt['delivered_at'] ?? null);
        self::assertSame(2, $receipt['attempts'] ?? null);
    }

    /**
     * An entry's receipts are keyed by destination, excluding other entries'.
     *
     * @return void
     */
    public function testForEntryIsKeyedByDestination(): void
    {
        $receipts = $this->receipts();

        $receipts->attempting(self::ID, self::SECOND_DESTINATION, null);
        $receipts->attempting(self::ID, self::SECOND_DESTINATION, null);
        $receipts->failed(self::ID, self::SECOND_DESTINATION, \RuntimeException::class);
        $receipts->attempting(self::ID, self::DESTINATION, null);
        $receipts->delivered(self::ID, self::DESTINATION);
        $receipts->attempting(self::SECOND_ID, self::DESTINATION, null);

        $forEntry = $receipts->forEntry(self::ID);

        $fields = static fn (Receipt $receipt): array => [$receipt->destination, $receipt->attempts, $receipt->delivered, $receipt->lastErrorClass];

        self::assertSame([self::SECOND_DESTINATION, self::DESTINATION], array_keys($forEntry));
        self::assertSame([self::DESTINATION, 1, true, null], $fields($forEntry[self::DESTINATION]));
        self::assertSame([self::SECOND_DESTINATION, 2, false, \RuntimeException::class], $fields($forEntry[self::SECOND_DESTINATION]));
    }

    /**
     * An entry with no attempt has no receipt.
     *
     * @return void
     */
    public function testAnEntryWithNoAttemptHasNoReceipts(): void
    {
        self::assertSame([], $this->receipts()->forEntry(self::ID));
    }

    /**
     * Resetting keeps every delivered receipt as it is.
     *
     * @return void
     */
    public function testResettingKeepsDeliveries(): void
    {
        $receipts = $this->receipts();

        $receipts->attempting(self::ID, self::DESTINATION, null);
        $receipts->attempting(self::ID, self::DESTINATION, null);
        $receipts->delivered(self::ID, self::DESTINATION);

        $delivered = $this->receipt(self::ID, self::DESTINATION);

        self::assertSame(0, $receipts->resetFailed([self::ID]));
        self::assertSame($delivered, $this->receipt(self::ID, self::DESTINATION));
    }

    /**
     * Resetting clears attempts and errors of undelivered receipts for the
     * given entries only.
     *
     * @return void
     */
    public function testResettingClearsFailures(): void
    {
        $receipts = $this->receipts();

        foreach ([self::ID, self::SECOND_ID] as $id) {
            $receipts->attempting($id, self::DESTINATION, null);
            $receipts->attempting($id, self::DESTINATION, null);
            $receipts->failed($id, self::DESTINATION, \RuntimeException::class);
        }

        $receipts->attempting(self::ID, self::SECOND_DESTINATION, null);
        $receipts->delivered(self::ID, self::SECOND_DESTINATION);

        $untouched = $this->receipt(self::SECOND_ID, self::DESTINATION);

        self::assertSame(1, $receipts->resetFailed([self::ID]));
        self::assertSame([
            'entry_id'           => self::ID,
            'destination'        => self::DESTINATION,
            'attempts'           => 0,
            'first_attempted_at' => self::NOW,
            'delivered_at'       => null,
            'last_error_class'   => null,
        ], $this->receipt(self::ID, self::DESTINATION));
        self::assertSame($untouched, $this->receipt(self::SECOND_ID, self::DESTINATION));
        self::assertTrue($receipts->forEntry(self::ID)[self::SECOND_DESTINATION]->delivered);
    }

    /**
     * Resetting no entries runs no statement and resets nothing.
     *
     * @return void
     */
    public function testResettingNothingRunsNoStatement(): void
    {
        $queries = 0;

        DB::connection(StorageConnection::name())->beforeExecuting(static function () use (&$queries): void {
            $queries++;
        });

        self::assertSame(0, $this->receipts()->resetFailed([]));
        self::assertSame(0, $queries);
    }

    /**
     * A list of entries longer than one statement binds is reset in chunks.
     *
     * @return void
     */
    public function testResettingAListLongerThanAChunkResetsEveryReceipt(): void
    {
        $ids  = [];
        $rows = [];

        foreach (range(1, 1201) as $number) {
            $id     = sprintf('01932b4e-8a40-7000-8000-%012d', $number);
            $ids[]  = $id;
            $rows[] = [
                'entry_id'           => $id,
                'destination'        => self::DESTINATION,
                'attempts'           => 3,
                'first_attempted_at' => '2026-11-01 11:00:00.000000',
                'last_error_class'   => 'abandoned',
            ];
        }

        $table = DB::connection(StorageConnection::name())->table(DeliveryTables::deliveriesTable());

        foreach (array_chunk($rows, 100) as $chunk) {
            $table->clone()->insert($chunk);
        }

        $statements = 0;

        DB::connection(StorageConnection::name())->beforeExecuting(static function () use (&$statements): void {
            $statements++;
        });

        self::assertSame(1201, $this->receipts()->resetFailed($ids));
        self::assertSame(3, $statements);
        self::assertSame(0, $table->clone()->where('attempts', '>', 0)->count());
    }

    /**
     * With the outbox on its own connection, the receipts stay on the storage
     * connection.
     *
     * @return void
     */
    public function testTheReceiptsAreOnTheStorageConnectionWhenTheOutboxMoves(): void
    {
        $this->moveOutboxToItsOwnConnection();

        $receipts = $this->receipts();

        $receipts->attempting(self::ID, self::DESTINATION, null);

        self::assertSame(self::CONNECTION, $receipts->connection()->getName());
        self::assertSame(1, DB::connection(self::CONNECTION)->table(DeliveryTables::deliveriesTable())->count());
        self::assertFalse(Schema::connection(self::MOVED_OUTBOX_CONNECTION)->hasTable(DeliveryTables::deliveriesTable()));
        self::assertTrue(Schema::connection(self::MOVED_OUTBOX_CONNECTION)->hasTable(DeliveryTables::outboxTable()));
    }

    /**
     * On a read/write split receipts are written to and read from the primary.
     *
     * @return void
     */
    public function testTheReceiptsAreOnTheWriter(): void
    {
        $this->useReadWriteSplit();
        $this->migrateDeliveryTablesOn([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION]);

        $receipts = $this->receipts();

        $receipts->attempting(self::ID, self::DESTINATION, null);

        self::assertSame(1, DB::connection(self::PRIMARY_CONNECTION)->table(DeliveryTables::deliveriesTable())->count());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table(DeliveryTables::deliveriesTable())->count());
        self::assertSame([self::DESTINATION], array_keys($receipts->forEntry(self::ID)));
    }

    /**
     * A receipt holds the six columns of the deliveries table and nothing of
     * the record.
     *
     * @return void
     */
    public function testAReceiptHoldsNoPayload(): void
    {
        $receipts = $this->receipts();

        $receipts->attempting(self::ID, self::DESTINATION, null);
        $receipts->failed(self::ID, self::DESTINATION, \RuntimeException::class);

        $receipt = $this->receipt(self::ID, self::DESTINATION);

        self::assertNotNull($receipt);
        self::assertSame(self::RECEIPT_COLUMNS, array_keys($receipt));
        self::assertSame([self::ID, self::DESTINATION, 1, self::NOW, null, \RuntimeException::class], array_values($receipt));
    }

    /**
     * A connection that is not a database connection is refused, naming it.
     *
     * @return void
     */
    public function testAConnectionWithoutTransactionsIsRefused(): void
    {
        $resolver = \Mockery::mock(ConnectionResolverInterface::class);
        $resolver->shouldReceive('connection')->andReturn(\Mockery::mock(ConnectionInterface::class));

        $receipts = new Receipts($resolver, app(Clock::class));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The storage connection [testing] is not a database connection that supports transactions.');

        $receipts->connection();
    }

    /**
     * A drained bundle's receipt is marked delivered only after its artifact
     * and entry, in the transaction they share.
     *
     * @return void
     */
    public function testABundlesReceiptFollowsBothRows(): void
    {
        $record = app(RecordFinaliser::class)->finalise(RecordFactory::bundled());
        $id     = $this->enqueue($record);
        $steps  = [];
        $held   = null;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query, array $bindings, Connection $connection) use ($id, &$steps, &$held): void {
            $step = self::stepOf($query);

            if ($step === null) {
                return;
            }

            $steps[] = $step;

            if ($step !== 'delivered') {
                return;
            }

            $held = [
                'level'     => $connection->transactionLevel(),
                'entries'   => self::rawCount($connection, EntrySettings::table(), 'id', $id),
                'artifacts' => self::rawCount($connection, EntrySettings::artifactsTable(), 'entry_id', $id),
            ];
        });

        self::assertSame(1, app(OutboxDrainer::class)->drain(100, false)->delivered());
        self::assertSame(['artifact', 'entry', 'delivered'], $steps);
        self::assertSame(['level' => 1, 'entries' => 1, 'artifacts' => 1], $held);
        self::assertSame(self::NOW, $this->receipt($id, DeliveryCoordinator::STORE_DESTINATION)['delivered_at'] ?? null);

        $storage = DB::connection(StorageConnection::name());

        self::assertSame(1, $storage->table(EntrySettings::table())->where('id', $id)->count());
        self::assertSame(1, $storage->table(EntrySettings::artifactsTable())->where('entry_id', $id)->count());
    }

    /**
     * The receipts, as the container builds them.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\Receipts
     */
    private function receipts(): Receipts
    {
        return app(Receipts::class);
    }

    /**
     * What the statement does to a bundle's delivery, or `null`.
     *
     * @param  string  $query
     * @return ?string
     */
    private static function stepOf(string $query): ?string
    {
        return match (true) {
            str_starts_with($query, 'insert into ') && str_contains($query, EntrySettings::artifactsTable()) => 'artifact',
            str_starts_with($query, 'insert into ') && str_contains($query, EntrySettings::table())          => 'entry',
            preg_match('/\Aupdate .* set [`"]?delivered_at[`"]? = /', $query) === 1                          => 'delivered',
            default                                                                                          => null,
        };
    }
}
