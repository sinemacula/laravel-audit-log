<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\TestCase;

/**
 * Integration tests for `immediately()` and `failClosed()` through the public
 * API, on the engine the suite runs against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordDelivery::class)]
#[CoversClass(Recorder::class)]
final class ImmediateTimingTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string A storage connection of the application's own. */
    private const string STORAGE = 'audit_store';

    /** @var string The table holding the host's business data. */
    private const string INVOICES = 'timing_invoices';

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
     * Inside a transaction the record is written before `record()` returns and
     * outlasts the commit.
     *
     * @return void
     */
    public function testWrittenNowInsideATransaction(): void
    {
        $this->host()->beginTransaction();

        $record = AuditLog::event(self::CODE)->immediately()->record();

        self::assertSame($record->id, $this->storedRow($record->id)['id']);

        $this->host()->commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * With no transaction open the record is written and durable at once.
     *
     * @return void
     */
    public function testWrittenNowWithNoTransaction(): void
    {
        $record = AuditLog::event(self::CODE)->immediately()->record();

        self::assertSame(0, $this->host()->transactionLevel());
        self::assertSame($record->id, $this->storedRow($record->id)['id']);
    }

    /**
     * On a shared connection the host's rollback takes the record.
     *
     * @return void
     */
    public function testRolledBackWithTheHostOnASharedConnection(): void
    {
        $this->host()->beginTransaction();

        AuditLog::event(self::CODE)->immediately()->record();

        self::assertSame(1, $this->entryCount());

        $this->host()->rollBack();

        self::assertSame(0, $this->entryCount());
    }

    /**
     * On a shared connection an inner rollback takes the record, with the outer
     * transaction still open.
     *
     * @return void
     */
    public function testRolledBackWithAnInnerTransactionOnASharedConnection(): void
    {
        $this->host()->beginTransaction();
        $this->host()->beginTransaction();

        AuditLog::event(self::CODE)->immediately()->record();

        $this->host()->rollBack();

        self::assertSame(1, $this->host()->transactionLevel());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * On a dedicated connection the record survives the host's rollback, and
     * the business change does not.
     *
     * @return void
     */
    #[DefineEnvironment('useDedicatedStorage')]
    public function testSurvivesAHostRollbackOnADedicatedConnection(): void
    {
        $this->host()->beginTransaction();

        $this->insertInvoice();

        $record = AuditLog::event(self::CODE)->immediately()->record();

        self::assertSame(0, $this->storageConnection()->transactionLevel());

        $this->host()->rollBack();

        self::assertSame(0, $this->invoiceCount());
        self::assertSame(1, $this->entryCount());
        self::assertSame($record->id, $this->storedRow($record->id)['id']);
    }

    /**
     * Under the `throw` mode a failed write propagates, and its savepoint
     * leaves the host usable on every engine.
     *
     * @return void
     */
    public function testAFailedWritePropagatesAndTheHostStaysUsable(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        $this->pointAtProbeTable();

        $this->host()->beginTransaction();

        $this->insertInvoice('INV-1');

        $this->assertTheRecordFails(static fn () => AuditLog::event(self::CODE)->immediately()->record());

        self::assertSame(1, $this->host()->transactionLevel());

        $this->insertInvoice('INV-2');

        $this->host()->commit();

        self::assertSame(2, $this->invoiceCount());
        self::assertSame(0, $this->probeCount());
    }

    /**
     * On a dedicated connection a failed write propagates under the `throw`
     * mode and the host's transaction carries on.
     *
     * @return void
     */
    #[DefineEnvironment('useDedicatedStorage')]
    public function testAFailedWriteOnADedicatedConnectionLeavesTheHostUntouched(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        $this->pointAtProbeTable();

        $this->host()->beginTransaction();

        $this->insertInvoice();

        $this->assertTheRecordFails(static fn () => AuditLog::event(self::CODE)->immediately()->record());

        $this->host()->commit();

        self::assertSame(1, $this->invoiceCount());
        self::assertSame(0, $this->probeCount());
    }

    /**
     * A fail-closed record with no timing of its own is written inside the open
     * transaction.
     *
     * @return void
     */
    public function testFailClosedIsWrittenNow(): void
    {
        $this->host()->beginTransaction();

        $record = AuditLog::event(self::CODE)->failClosed()->record();

        self::assertSame($record->id, $this->storedRow($record->id)['id']);

        $this->host()->commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A fail-closed record's failed write reaches the caller at the call, not
     * at the commit.
     *
     * @return void
     */
    public function testAFailClosedRecordsFailedWriteReachesTheCallerAtTheCall(): void
    {
        $this->pointAtProbeTable();

        $this->host()->beginTransaction();

        $this->assertTheRecordFails(static fn () => AuditLog::event(self::CODE)->failClosed()->record());

        $this->host()->commit();

        self::assertSame(0, $this->host()->transactionLevel());
        self::assertSame(0, $this->probeCount());
    }

    /**
     * On a dedicated connection a fail-closed record survives the host's
     * rollback.
     *
     * @return void
     */
    #[DefineEnvironment('useDedicatedStorage')]
    public function testFailClosedSurvivesOnADedicatedConnection(): void
    {
        $this->host()->beginTransaction();

        $record = AuditLog::event(self::CODE)->failClosed()->record();

        $this->host()->rollBack();

        self::assertSame(1, $this->entryCount());
        self::assertSame($record->id, $this->storedRow($record->id)['id']);
    }

    /**
     * `AuditRecorded` is dispatched before the host commits, so the record can
     * still go with a rollback.
     *
     * @return void
     */
    public function testAuditRecordedIsDispatchedBeforeTheHostCommits(): void
    {
        $heard = [];

        Event::listen(AuditRecorded::class, function (AuditRecorded $event) use (&$heard): void {
            $heard[] = [$event->id, $this->host()->transactionLevel()];
        });

        $this->host()->beginTransaction();

        $record = AuditLog::event(self::CODE)->immediately()->record();

        self::assertSame([[$record->id, 1]], $heard);

        $this->host()->rollBack();

        self::assertSame(0, $this->entryCount());
        self::assertCount(1, $heard);
    }

    /**
     * An immediate record is dispatched once, and not again when the host
     * commits.
     *
     * @return void
     */
    public function testAuditRecordedIsDispatchedOnceThroughTheCommit(): void
    {
        $heard = [];

        Event::listen(AuditRecorded::class, static function (AuditRecorded $event) use (&$heard): void {
            $heard[] = $event->id;
        });

        $this->host()->beginTransaction();

        $record = AuditLog::event(self::CODE)->immediately()->record();

        $this->host()->commit();

        self::assertSame([$record->id], $heard);
    }

    /**
     * Register the dedicated storage connection with its own table prefix.
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

        $config = $app->make(ConfigRepository::class);

        $config->set('database.connections.' . self::STORAGE, [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'store_']);
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

    /**
     * Run a capture into the probe table, which fails on its `NOT NULL` column
     * with the engine's `QueryException`, sanitised.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Records\AuditRecord  $capture
     * @return void
     *
     * @throws \Throwable
     */
    private function assertTheRecordFails(\Closure $capture): void
    {
        try {
            $capture();

            self::fail('Expected the audit insert to fail.');
        } catch (AuditWriteFailedException $exception) {
            self::assertSame(QueryException::class, $exception->exceptionClass);
            self::assertNotNull($exception->sqlState);
        }
    }
}
