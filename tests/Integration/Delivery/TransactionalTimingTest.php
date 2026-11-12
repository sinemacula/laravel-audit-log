<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\TestCase;

/**
 * Integration tests for `transactional()` through the public API, on the engine
 * the suite runs against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordDelivery::class)]
#[CoversClass(Recorder::class)]
final class TransactionalTimingTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string A second connection a host transacts on. */
    private const string OTHER = 'audit_other';

    /** @var string A storage connection of the application's own. */
    private const string STORAGE = 'audit_store';

    /** @var string The table holding the host's business data. */
    private const string INVOICES = 'timing_invoices';

    /** @var string The refusal when the storage connection has no transaction open. */
    private const string NO_TRANSACTION = 'A transactional record needs a transaction open on the storage connection [%s].';

    /** @var string The refusal when a record names a connection other than the storage connection. */
    private const string ANOTHER_CONNECTION = 'A transactional record is written on the storage connection [%s], not [%s]; another connection needs the outbox.';

    /**
     * Create the table holding the host's business data.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::connection(self::CONNECTION)->create(self::INVOICES, static function (Blueprint $table): void {
            $table->string('number', 16);
        });
    }

    /**
     * Roll back any transaction a test left open, then drop the tables it
     * created.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (DB::getConnections() as $connection) {
            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }

        $this->removeProbeTable();

        Schema::connection(self::CONNECTION)->dropIfExists(self::INVOICES);

        parent::tearDown();
    }

    /**
     * The record is written inside the host's transaction and commits with the
     * business change.
     *
     * @return void
     */
    public function testAtomicWithTheHostOnCommit(): void
    {
        $this->host()->beginTransaction();

        $this->insertInvoice();

        $record = AuditLog::event(self::CODE)->transactional()->record();

        self::assertSame(1, $this->entryCount());

        $this->host()->commit();

        self::assertSame(1, $this->invoiceCount());
        self::assertSame(1, $this->entryCount());
        self::assertSame($record->id, $this->storedRow($record->id)['id']);
    }

    /**
     * The record goes with the business change when the host rolls back.
     *
     * @return void
     */
    public function testRolledBackWithTheHost(): void
    {
        $this->host()->beginTransaction();

        $this->insertInvoice();

        AuditLog::event(self::CODE)->transactional()->record();

        $this->host()->rollBack();

        self::assertSame(0, $this->invoiceCount());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * An inner rollback takes the record, and the outer business change commits
     * without it.
     *
     * @return void
     */
    public function testRolledBackWithAnInnerTransaction(): void
    {
        $this->host()->beginTransaction();

        $this->insertInvoice();

        $this->host()->beginTransaction();

        AuditLog::event(self::CODE)->transactional()->record();

        $this->host()->rollBack();
        $this->host()->commit();

        self::assertSame(1, $this->invoiceCount());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A transactional record with no transaction open is refused and writes
     * nothing.
     *
     * @return void
     */
    public function testRefusedWithNoOpenTransaction(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf(self::NO_TRANSACTION, self::CONNECTION));

        try {
            AuditLog::event(self::CODE)->transactional()->record();
        } finally {
            self::assertSame(0, $this->entryCount());
        }
    }

    /**
     * A transaction on another connection cannot make the record atomic, so it
     * is refused.
     *
     * @return void
     */
    public function testRefusedWhenTheTransactionIsOnAnotherConnection(): void
    {
        $this->other()->beginTransaction();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf(self::NO_TRANSACTION, self::CONNECTION));

        AuditLog::event(self::CODE)->transactional()->record();
    }

    /**
     * A record naming another connection is refused, even with a transaction
     * open on both.
     *
     * @return void
     */
    public function testRefusedNamingAnotherConnection(): void
    {
        $this->host()->beginTransaction();
        $this->other()->beginTransaction();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf(self::ANOTHER_CONNECTION, self::CONNECTION, self::OTHER));

        AuditLog::event(self::CODE)->transactional(self::OTHER)->record();
    }

    /**
     * A record naming the storage connection is accepted and atomic with it.
     *
     * @return void
     */
    public function testAcceptedNamingTheStorageConnection(): void
    {
        $this->host()->beginTransaction();

        AuditLog::event(self::CODE)->transactional(self::CONNECTION)->record();

        self::assertSame(1, $this->entryCount());

        $this->host()->rollBack();

        self::assertSame(0, $this->entryCount());
    }

    /**
     * A refusal consumes nothing, so the builder records once a transaction is
     * open.
     *
     * @return void
     */
    public function testARefusalLeavesTheBuilderUsable(): void
    {
        $pending = AuditLog::event(self::CODE)->transactional();

        try {
            $pending->record();

            self::fail('Expected the record to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame(sprintf(self::NO_TRANSACTION, self::CONNECTION), $exception->getMessage());
        }

        $this->host()->beginTransaction();

        $record = $pending->record();

        $this->host()->commit();

        self::assertSame($record->id, $this->storedRow($record->id)['id']);
    }

    /**
     * A failed write propagates, and its savepoint leaves the host usable on
     * every engine.
     *
     * @return void
     */
    public function testAFailedWritePropagatesAndTheHostStaysUsable(): void
    {
        $this->pointAtProbeTable();

        $this->host()->beginTransaction();

        $this->insertInvoice('INV-1');

        try {
            AuditLog::event(self::CODE)->transactional()->record();

            self::fail('Expected the audit insert to fail.');
        } catch (AuditWriteFailedException $exception) {
            self::assertSame(QueryException::class, $exception->exceptionClass);
            self::assertNotNull($exception->sqlState);
        }

        self::assertSame(1, $this->host()->transactionLevel());

        $this->insertInvoice('INV-2');

        $this->host()->commit();

        self::assertSame(2, $this->invoiceCount());
        self::assertSame(0, $this->probeCount());
    }

    /**
     * An uncaught failed write rolls the host's business change back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedWriteLeftUncaughtRollsBackTheBusinessChange(): void
    {
        $this->pointAtProbeTable();

        try {
            $this->host()->transaction(function (): void {
                $this->insertInvoice();

                AuditLog::event(self::CODE)->transactional()->record();
            });

            self::fail('Expected the audit insert to fail.');
        } catch (AuditWriteFailedException $exception) {
            self::assertSame(QueryException::class, $exception->exceptionClass);
            self::assertNotNull($exception->sqlState);
        }

        self::assertSame(0, $this->host()->transactionLevel());
        self::assertSame(0, $this->invoiceCount());
        self::assertSame(0, $this->probeCount());
    }

    /**
     * `failClosed()` leaves a transactional record transactional, whichever is
     * called first.
     *
     * @return void
     */
    public function testFailClosedTransactionalStaysTransactional(): void
    {
        $builders = [
            'fail closed first'   => AuditLog::event(self::CODE)->failClosed()->transactional(),
            'transactional first' => AuditLog::event(self::CODE)->transactional()->failClosed(),
        ];

        foreach ($builders as $order => $pending) {
            try {
                $pending->record();

                self::fail("Expected the record to be refused, {$order}.");
            } catch (\LogicException $exception) {
                self::assertSame(sprintf(self::NO_TRANSACTION, self::CONNECTION), $exception->getMessage(), $order);
            }

            $this->host()->beginTransaction();

            $pending->record();

            self::assertSame(1, $this->entryCount(), $order);

            $this->host()->rollBack();

            self::assertSame(0, $this->entryCount(), $order);
        }
    }

    /**
     * With dedicated storage, only the host's transaction open, the record is
     * refused naming the storage connection.
     *
     * @return void
     */
    #[DefineEnvironment('useDedicatedStorage')]
    public function testRefusedOnADedicatedConnectionWithOnlyTheHostsTransactionOpen(): void
    {
        $this->host()->beginTransaction();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf(self::NO_TRANSACTION, self::STORAGE));

        AuditLog::event(self::CODE)->transactional()->record();
    }

    /**
     * With dedicated storage, naming the host's connection is naming another
     * connection.
     *
     * @return void
     */
    #[DefineEnvironment('useDedicatedStorage')]
    public function testRefusedNamingTheDefaultConnectionWhenStorageIsDedicated(): void
    {
        $this->host()->beginTransaction();
        $this->storageConnection()->beginTransaction();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf(self::ANOTHER_CONNECTION, self::STORAGE, self::CONNECTION));

        AuditLog::event(self::CODE)->transactional(self::CONNECTION)->record();
    }

    /**
     * With dedicated storage the record is atomic with that connection's
     * transaction, untouched by the host's.
     *
     * @return void
     */
    #[DefineEnvironment('useDedicatedStorage')]
    public function testAtomicWithATransactionOnADedicatedConnection(): void
    {
        $storage = $this->storageConnection();

        $this->host()->beginTransaction();
        $storage->beginTransaction();

        AuditLog::event(self::CODE)->transactional()->record();

        $this->host()->rollBack();

        self::assertSame(1, $this->entryCount());

        $storage->rollBack();

        self::assertSame(0, $this->entryCount());
    }

    /**
     * Register the second transacting connection and the dedicated storage
     * connection, each with its own table prefix.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config  = $app->make(ConfigRepository::class);
        $testing = $config->array('database.connections.' . self::CONNECTION);

        $config->set('database.connections.' . self::OTHER, [...$testing, 'prefix' => 'other_']);
        $config->set('database.connections.' . self::STORAGE, [...$testing, 'prefix' => 'store_']);
    }

    /**
     * Make the package's tables live on the dedicated storage connection.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function useDedicatedStorage(Application $app): void
    {
        $app->make(ConfigRepository::class)->set('audit-log.storage.connection', self::STORAGE);
    }

    /**
     * The connection the host's transactions and business data are on.
     *
     * @return \Illuminate\Database\Connection
     */
    private function host(): Connection
    {
        return DB::connection(self::CONNECTION);
    }

    /**
     * The second connection a host transacts on.
     *
     * @return \Illuminate\Database\Connection
     */
    private function other(): Connection
    {
        return DB::connection(self::OTHER);
    }

    /**
     * Insert a row of the host's business data.
     *
     * @param  string  $number
     * @return void
     */
    private function insertInvoice(string $number = 'INV-1'): void
    {
        $this->host()->table(self::INVOICES)->insert(['number' => $number]);
    }

    /**
     * The number of rows of the host's business data.
     *
     * @return int
     */
    private function invoiceCount(): int
    {
        return $this->host()->table(self::INVOICES)->count();
    }
}
