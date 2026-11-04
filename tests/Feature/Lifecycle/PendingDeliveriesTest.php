<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction;
use SineMacula\Laravel\AuditLog\Lifecycle\PendingDeliveries;
use Tests\Concerns\InteractsWithOutbox;
use Tests\TestCase;

/**
 * Feature tests for the deliveries a prune must wait for, on whichever engine
 * the suite runs against: an outbox row, pending, claimed or failed, and a
 * receipt not yet delivered each keep their entry, a delivered receipt does
 * not; each id is named once, in the order given, at most 500 to a statement;
 * and the outbox is read inside the chunk's transaction when it lives on the
 * storage database, and through its own connection after the lock when it does
 * not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingDeliveries::class)]
final class PendingDeliveriesTest extends TestCase
{
    use InteractsWithOutbox;

    /** @var string An entry with a delivery to wait for. */
    private const string PENDING = '01932b4e-9000-7000-8000-000000000001';

    /** @var string An entry with nothing to wait for. */
    private const string DONE = '01932b4e-9000-7000-8000-000000000002';

    /** @var string When every row is written. */
    private const string NOW = '2026-11-02T09:00:00.000000Z';

    /** @var string The operation every lifecycle transaction runs as. */
    private const string OPERATION = '01932b4e-c000-7000-8000-000000000001';

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
     * Put the outbox back and the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeMovedOutbox();

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * An entry with a pending outbox row waits, one without does not.
     *
     * @return void
     */
    public function testAnOutboxRowIsPending(): void
    {
        $this->seedOutboxRow(self::PENDING, 'payload');

        self::assertSame([self::PENDING], $this->deliveries()->inOutbox($this->maintenance(), [self::DONE, self::PENDING]));
        self::assertSame([], $this->deliveries()->inOutbox($this->maintenance(), [self::DONE]));
    }

    /**
     * A failed outbox row, and a claimed one, keep their entries too: the
     * record has not reached its destinations until it is replayed.
     *
     * @return void
     */
    public function testAFailedOutboxRowIsPending(): void
    {
        $this->seedOutboxRow(self::PENDING, 'payload', ['attempts' => 5, 'failed_at' => self::NOW, 'last_error_class' => \RuntimeException::class]);
        $this->seedOutboxRow(self::DONE, 'payload', ['attempts' => 1, 'claimed_until' => '2026-11-02T09:05:00.000000Z', 'claimed_by' => 'claim-1']);

        self::assertSame([self::PENDING, self::DONE], $this->deliveries()->inOutbox($this->maintenance(), [self::PENDING, self::DONE]));
    }

    /**
     * A receipt not yet delivered keeps its entry, a failed attempt included.
     *
     * @return void
     */
    public function testAnUndeliveredReceiptIsPending(): void
    {
        $this->seedReceipt(self::PENDING, 'siem', null);
        $this->seedReceipt(self::PENDING, 'archive', '2026-11-02 09:00:00.000000');

        self::assertSame([self::PENDING], $this->deliveries()->undelivered($this->maintenance(), [self::DONE, self::PENDING]));
    }

    /**
     * An entry whose every receipt was delivered has nothing to wait for.
     *
     * @return void
     */
    public function testADeliveredReceiptIsNot(): void
    {
        $this->seedReceipt(self::DONE, 'siem', '2026-11-02 09:00:00.000000');
        $this->seedReceipt(self::DONE, 'archive', '2026-11-02 09:00:01.000000');

        self::assertSame([], $this->deliveries()->undelivered($this->maintenance(), [self::DONE]));
    }

    /**
     * Each id found is named once, in the order given, and at most 500 ids are
     * named to a statement.
     *
     * @return void
     */
    public function testEachIdIsNamedOnceAtMostFiveHundredToAStatement(): void
    {
        $ids = array_map(static fn (int $index): string => sprintf('01932b4e-9000-7000-8000-%012d', $index), range(1, 600));

        $this->seedOutboxRow($ids[599], 'payload');
        $this->seedOutboxRow($ids[3], 'payload');
        $this->seedReceipt($ids[550], 'siem', null);

        $statements = $this->countStatements();

        self::assertSame([$ids[3], $ids[599]], $this->deliveries()->inOutbox($this->maintenance(), [...$ids, $ids[3]]));
        self::assertSame([$ids[550]], $this->deliveries()->undelivered($this->maintenance(), $ids));
        self::assertCount(4, $statements);
    }

    /**
     * Nothing to ask about is asked about in no statement.
     *
     * @return void
     */
    public function testNoIdsAskNothing(): void
    {
        $statements = $this->countStatements();

        self::assertSame([], $this->deliveries()->inOutbox($this->maintenance(), []));
        self::assertSame([], $this->deliveries()->undelivered($this->maintenance(), []));
        self::assertCount(0, $statements);
    }

    /**
     * An outbox on the storage database is read through the maintenance
     * connection, inside the chunk's transaction, after its lock.
     *
     * @return void
     */
    public function testAnOutboxOnTheStorageDatabaseIsReadInTheTransaction(): void
    {
        $this->seedOutboxRow(self::PENDING, 'payload');

        $log = $this->statementLog();

        $found = app(MaintenanceTransaction::class)->run(self::OPERATION, fn (Connection $connection): array => $this->deliveries()->inOutbox($connection, [self::PENDING]));

        self::assertSame([self::PENDING], $found);

        $reads = array_values(array_filter($log->getArrayCopy(), static fn (array $entry): bool => str_contains($entry[1], DeliveryTables::outboxTable())));
        $lock  = array_search('lock', array_column($log->getArrayCopy(), 2), true);
        $read  = array_search('outbox', array_column($log->getArrayCopy(), 2), true);

        self::assertCount(1, $reads);
        self::assertSame([StorageConnection::resolvedMaintenanceName(), 1], [$reads[0][0], $reads[0][3]]);
        self::assertIsInt($lock);
        self::assertGreaterThan($lock, $read);
    }

    /**
     * An outbox on another connection is read through that connection's writer,
     * in a read of its own outside the transaction, after the chunk's lock
     * statement.
     *
     * @return void
     */
    public function testAnOutboxOnAnotherConnectionIsReadAfterTheLock(): void
    {
        $this->moveOutboxToItsOwnConnection();
        $this->seedOutboxRow(self::PENDING, 'payload');

        $log = $this->statementLog();

        $ids   = [self::PENDING, self::DONE];
        $found = app(MaintenanceTransaction::class)->run(self::OPERATION, fn (Connection $connection): array => $this->deliveries()->inOutbox($connection, $ids));

        self::assertSame([self::PENDING], $found);

        $entries = $log->getArrayCopy();
        $lock    = array_search('lock', array_column($entries, 2), true);
        $read    = array_search('outbox', array_column($entries, 2), true);

        self::assertIsInt($lock);
        self::assertIsInt($read);
        self::assertGreaterThan($lock, $read);
        self::assertSame([self::MOVED_OUTBOX_CONNECTION, 0], [$entries[$read][0], $entries[$read][3]]);
    }

    /**
     * Seed a receipt of the entry for the destination, delivered at the time
     * given, as the engine stores it, or not yet.
     *
     * @param  string  $entryId
     * @param  string  $destination
     * @param  ?string  $deliveredAt
     * @return void
     */
    private function seedReceipt(string $entryId, string $destination, ?string $deliveredAt): void
    {
        $this->maintenance()->table(DeliveryTables::deliveriesTable())->insert([
            'entry_id'           => $entryId,
            'destination'        => $destination,
            'attempts'           => 1,
            'first_attempted_at' => '2026-11-02 08:59:00.000000',
            'delivered_at'       => $deliveredAt,
            'last_error_class'   => $deliveredAt === null ? \RuntimeException::class : null,
        ]);
    }

    /**
     * Count the statements every connection runs from now.
     *
     * @return \ArrayObject<int, string>
     */
    private function countStatements(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append($query->sql);
        });

        return $statements;
    }

    /**
     * Log every statement from now: its connection, its SQL, whether it is the
     * lock, an outbox read or anything else, and the transaction level of its
     * connection.
     *
     * @return \ArrayObject<int, array{0: string, 1: string, 2: string, 3: int}>
     */
    private function statementLog(): \ArrayObject
    {
        /** @var \ArrayObject<int, array{0: string, 1: string, 2: string, 3: int}> $log */
        $log = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($log): void {
            $kind = match (true) {
                str_starts_with($query->sql, 'update') && str_contains($query->sql, 'audit_log_lifecycle_lock') => 'lock',
                str_contains($query->sql, DeliveryTables::outboxTable())                                        => 'outbox',
                default                                                                                         => 'other',
            };

            $log->append([$query->connectionName, $query->sql, $kind, $query->connection->transactionLevel()]);
        });

        return $log;
    }

    /**
     * The pending deliveries, as the container builds them.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\PendingDeliveries
     */
    private function deliveries(): PendingDeliveries
    {
        return app(PendingDeliveries::class);
    }

    /**
     * The maintenance connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function maintenance(): Connection
    {
        return DB::connection(StorageConnection::forMaintenance());
    }
}
