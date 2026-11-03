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
 * Integration tests for the receipts on the engine the suite runs against: an
 * attempt counted before each call, a first attempt that falls to an update
 * when a racing owner made the receipt first, a delivery that is never changed
 * again, failures named by class, resets that keep deliveries, and every
 * receipt on the storage connection's writer however the outbox is placed, and
 * a bundle's receipt written only after both of its rows; on SQLite, MySQL and
 * PostgreSQL alike.
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
     * Roll back any transaction a failed test left open, then undo what the
     * test changed and release the clock.
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
     * A first attempt makes the receipt: one attempt, first made now, not
     * delivered, and no error named.
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
     * Outside a transaction a first attempt opens none: no transaction begins,
     * and the insert runs at level 0.
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
     * Inside a host transaction a first attempt is inserted one level deeper,
     * in a savepoint, and the host is back at its own level once it succeeds.
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
     * A later attempt counts one more on the receipt, and keeps when the first
     * was made.
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
     * A first attempt that finds the receipt made already, by a racing owner
     * that read none either, counts on it instead.
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
     * Inside a host transaction a racing first attempt rolls back to its own
     * savepoint, so the host stays usable and commits what it wrote.
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
     * A delivered receipt keeps the time it was first delivered, its attempts
     * and its cleared error, whatever is asked of it later.
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
     * An error class is cut on a character boundary, so a multibyte name never
     * leaves half a character in the column.
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
     * A failure reported after a delivery, by a slower owner, never undoes it
     * or names an error on it.
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
     * The receipts of an entry are keyed by destination, each as stored, and
     * another entry's are not among them.
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
     * Resetting starts an undelivered receipt's attempts again with no error
     * named, for the entries given and no other.
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
     * A list of entries longer than one statement binds is reset in chunks,
     * every failed receipt of it.
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
     * With the outbox moved to a connection of its own, the receipts stay on
     * the storage connection, beside the entries.
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
     * On a read/write split a receipt is written to the primary, the replica
     * never sees it, and the receipts are still read, because they are read
     * from the writer.
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
     * the record: the entry's id, the destination, a count, two times and an
     * error's class.
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
     * A drained bundle's receipt is marked delivered only after both of its
     * rows are written, the artifact's then the entry's, inside the transaction
     * the receipt shares with them: when the receipt is written, the
     * transaction already holds the entry and its artifact, and once it commits
     * all three are kept.
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
     * What the statement does to a bundle's delivery: inserts its artifact,
     * inserts its entry, or marks its receipt delivered; otherwise nothing.
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

    /**
     * The rows of the table whose column holds the id, counted over the
     * connection's own PDO, so the count is seen inside its open transaction
     * and is not itself a statement the connection reports.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  string  $column
     * @param  string  $id
     * @return int
     */
    private static function rawCount(Connection $connection, string $table, string $column, string $id): int
    {
        $grammar   = $connection->getQueryGrammar();
        $statement = $connection->getPdo()->prepare(sprintf('select count(*) from %s where %s = ?', $grammar->wrapTable($table), $grammar->wrap($column)));

        $statement->execute([$id]);

        return (int) $statement->fetchColumn();
    }
}
