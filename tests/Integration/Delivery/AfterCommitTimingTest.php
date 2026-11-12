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
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\AfterCommit;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Integration tests for the default after-commit timing through the public API,
 * on the engine the suite runs against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AfterCommit::class)]
#[CoversClass(RecordDelivery::class)]
#[CoversClass(Recorder::class)]
final class AfterCommitTimingTest extends TestCase
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

    /** @var list<string> The host's callbacks that have run, in order. */
    private array $callbacks = [];

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
     * The record is written when the host commits, and not before.
     *
     * @return void
     */
    public function testWrittenOnCommit(): void
    {
        $this->host()->beginTransaction();

        $record = AuditLog::record(self::CODE);

        self::assertSame(0, $this->entryCount());

        $this->host()->commit();

        self::assertSame(1, $this->entryCount());
        self::assertSame(self::CODE, $this->storedRow($record->id)['event']);
    }

    /**
     * A read or write selector names the same connection, so the record waits
     * for that connection's commit.
     *
     * @return void
     */
    public function testPinningAReadOrWriteSelectorStillDefers(): void
    {
        $this->host()->beginTransaction();

        foreach (['::write', '::read'] as $selector) {
            AuditLog::event(self::CODE)->afterCommit(self::CONNECTION . $selector)->record();

            self::assertSame(0, $this->entryCount(), $selector);
        }

        $this->host()->commit();

        self::assertSame(2, $this->entryCount());
    }

    /**
     * A record pinned with a selector is dropped on rollback.
     *
     * @return void
     */
    public function testARecordPinnedWithASelectorIsDroppedOnRollback(): void
    {
        $this->host()->beginTransaction();

        AuditLog::event(self::CODE)->afterCommit(self::CONNECTION . '::write')->record();

        $this->host()->rollBack();

        self::assertSame(0, $this->entryCount());
    }

    /**
     * A selector pins its own connection and no other.
     *
     * @return void
     */
    public function testASelectorPinsItsOwnConnectionOnly(): void
    {
        $this->other()->beginTransaction();

        AuditLog::event(self::CODE)->afterCommit(self::CONNECTION . '::write')->record();

        self::assertSame(1, $this->entryCount());

        $this->other()->rollBack();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * The record is never written when the host rolls back.
     *
     * @return void
     */
    public function testDroppedOnRollback(): void
    {
        $this->host()->beginTransaction();

        AuditLog::record(self::CODE);

        $this->host()->rollBack();

        self::assertSame(0, $this->entryCount());
    }

    /**
     * Rolling back the inner transaction the record selected drops it, though
     * the outer one commits.
     *
     * @return void
     */
    public function testDroppedOnAnInnerRollbackOfTheSelectedTransaction(): void
    {
        $this->host()->beginTransaction();
        $this->host()->beginTransaction();

        AuditLog::record(self::CODE);

        $this->host()->rollBack();
        $this->host()->commit();

        self::assertSame(0, $this->host()->transactionLevel());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * An inner rollback keeps a record the outer transaction selected before
     * the inner one began.
     *
     * @return void
     */
    public function testAnInnerRollbackKeepsARecordOfTheOuterTransaction(): void
    {
        $this->host()->beginTransaction();

        $kept = AuditLog::record(self::CODE);

        $this->host()->beginTransaction();

        AuditLog::record(self::CODE);

        $this->host()->rollBack();
        $this->host()->commit();

        self::assertSame(1, $this->entryCount());
        self::assertSame($kept->id, $this->storedRow($kept->id)['id']);
    }

    /**
     * An inner commit does not write the record; the outer commit does.
     *
     * @return void
     */
    public function testAnInnerCommitWaitsForTheOuterCommit(): void
    {
        $this->host()->beginTransaction();
        $this->host()->beginTransaction();

        AuditLog::record(self::CODE);

        $this->host()->commit();

        self::assertSame(0, $this->entryCount());

        $this->host()->commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * An outer rollback drops a record whose inner transaction has committed.
     *
     * @return void
     */
    public function testDroppedOnAnOuterRollbackAfterAnInnerCommit(): void
    {
        $this->host()->beginTransaction();
        $this->host()->beginTransaction();

        AuditLog::record(self::CODE);

        $this->host()->commit();
        $this->host()->rollBack();

        self::assertSame(0, $this->entryCount());
    }

    /**
     * With no transaction open the record is written before `record()` returns.
     *
     * @return void
     */
    public function testWrittenNowWithNoTransaction(): void
    {
        $record = AuditLog::record(self::CODE);

        self::assertSame(1, $this->entryCount());
        self::assertSame($record->id, $this->storedRow($record->id)['id']);
    }

    /**
     * `record()` returns the captured record before it is written.
     *
     * @return void
     */
    public function testTheCapturedRecordIsReturnedBeforeItIsWritten(): void
    {
        $this->host()->beginTransaction();

        $record = AuditLog::record(self::CODE);

        self::assertSame(self::CODE, $record->event);
        self::assertSame(0, $this->entryCount());

        $this->host()->commit();

        self::assertSame($record->occurredAt, $this->storedRow($record->id)['occurred_at']);
    }

    /**
     * The occurrence time is the capture time and the recording time is the
     * write time.
     *
     * @return void
     */
    public function testOccurredAtIsCaptureTimeAndRecordedAtIsWriteTime(): void
    {
        $this->app?->instance(Clock::class, FrozenClock::at('2026-11-01 12:00:00.100000'));

        $this->host()->beginTransaction();

        $record = AuditLog::record(self::CODE);

        $this->app?->instance(Clock::class, FrozenClock::at('2026-11-01 12:00:05.200000'));

        $this->host()->commit();

        $stored = $this->storedRow($record->id);

        self::assertSame('2026-11-01T12:00:00.100000Z', $record->occurredAt);
        self::assertSame('2026-11-01T12:00:00.100000Z', $stored['occurred_at']);
        self::assertSame('2026-11-01T12:00:05.200000Z', $stored['recorded_at']);
    }

    /**
     * A rolled-back transaction's record does not carry over to the next
     * transaction.
     *
     * @return void
     */
    public function testRecordsOfSuccessiveTransactionsAreKeptApart(): void
    {
        $this->host()->beginTransaction();

        AuditLog::record(self::CODE);

        $this->host()->rollBack();
        $this->host()->beginTransaction();

        $first  = AuditLog::record(self::CODE);
        $second = AuditLog::record(self::CODE);

        $this->host()->commit();

        self::assertSame(2, $this->entryCount());
        self::assertSame($first->id, $this->storedRow($first->id)['id']);
        self::assertSame($second->id, $this->storedRow($second->id)['id']);
    }

    /**
     * Laravel's own `transaction()` helper writes the record when its closure
     * returns.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWrittenWhenAClosureTransactionReturns(): void
    {
        $this->host()->transaction(function (): void {
            AuditLog::record(self::CODE);

            self::assertSame(0, $this->entryCount());
        });

        self::assertSame(1, $this->entryCount());
    }

    /**
     * Laravel's own `transaction()` helper drops the record when its closure
     * throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDroppedWhenAClosureTransactionThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('The host failed.');

        try {
            $this->host()->transaction(static function (): void {
                AuditLog::record(self::CODE);

                throw new \RuntimeException('The host failed.');
            });
        } finally {
            self::assertSame(0, $this->entryCount());
        }
    }

    /**
     * With no name the record selects whichever transaction began last, on any
     * connection.
     *
     * @return void
     */
    public function testTheDefaultSelectsTheInnermostOnAnyConnection(): void
    {
        $this->other()->beginTransaction();
        $this->host()->beginTransaction();

        AuditLog::record(self::CODE);

        $this->host()->commit();

        self::assertSame(1, $this->entryCount());

        $this->other()->rollBack();

        self::assertSame(1, $this->entryCount());

        $this->host()->beginTransaction();
        $this->other()->beginTransaction();

        AuditLog::record(self::CODE);

        $this->other()->rollBack();
        $this->host()->commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * Nested on two connections, the innermost's commit writes the record while
     * the outer stays open.
     *
     * @return void
     */
    public function testNestedTransactionsOnTwoConnectionsWriteOnTheInnermostsCommit(): void
    {
        $this->host()->beginTransaction();
        $this->other()->beginTransaction();

        AuditLog::record(self::CODE);

        self::assertSame(0, $this->entryCount());

        $this->other()->commit();

        self::assertSame(1, $this->host()->transactionLevel());
        self::assertSame(1, $this->entryCount());

        $this->host()->commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A write made on the innermost's commit rolls back with a transaction
     * still open on the storage connection.
     *
     * @return void
     */
    public function testAWriteInsideAnOpenStorageTransactionRollsBackWithIt(): void
    {
        $this->host()->beginTransaction();
        $this->other()->beginTransaction();

        AuditLog::record(self::CODE);

        $this->other()->commit();
        $this->host()->rollBack();

        self::assertSame(0, $this->entryCount());
    }

    /**
     * A record pinned to a connection waits for that connection's commit while
     * another is innermost.
     *
     * @return void
     */
    public function testPinningWaitsForThatConnectionWhileAnotherIsInnermost(): void
    {
        $this->other()->beginTransaction();
        $this->host()->beginTransaction();

        AuditLog::event(self::CODE)->afterCommit(self::OTHER)->record();

        $this->host()->commit();

        self::assertSame(0, $this->entryCount());

        $this->other()->commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A record pinned to a connection with no transaction is written now and
     * survives another connection's rollback.
     *
     * @return void
     */
    public function testPinningWritesNowWhenOnlyAnotherConnectionIsOpen(): void
    {
        $this->other()->beginTransaction();

        AuditLog::event(self::CODE)->afterCommit(self::CONNECTION)->record();

        self::assertSame(1, $this->entryCount());

        $this->other()->rollBack();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A pinned record is dropped by the rollback of the connection it names.
     *
     * @return void
     */
    public function testAPinnedRecordIsDroppedByItsOwnConnectionsRollback(): void
    {
        $this->other()->beginTransaction();
        $this->host()->beginTransaction();

        AuditLog::event(self::CODE)->afterCommit(self::OTHER)->record();

        $this->host()->commit();
        $this->other()->rollBack();

        self::assertSame(0, $this->entryCount());
    }

    /**
     * A pinned record survives the rollback of a connection it does not name.
     *
     * @return void
     */
    public function testAPinnedRecordIgnoresTheOtherConnectionsRollback(): void
    {
        $this->other()->beginTransaction();
        $this->host()->beginTransaction();

        AuditLog::event(self::CODE)->afterCommit(self::OTHER)->record();

        $this->host()->rollBack();
        $this->other()->commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A pinned record is dropped by an inner rollback on its connection.
     *
     * @return void
     */
    public function testAPinnedRecordIsDroppedByAnInnerRollbackOnItsConnection(): void
    {
        $this->host()->beginTransaction();
        $this->host()->beginTransaction();
        $this->other()->beginTransaction();

        AuditLog::event(self::CODE)->afterCommit(self::CONNECTION)->record();

        $this->other()->commit();
        $this->host()->rollBack();
        $this->host()->commit();

        self::assertSame(0, $this->entryCount());
    }

    /**
     * A name no connection answers to is refused, and nothing is written.
     *
     * @return void
     */
    public function testPinningAnUnknownConnectionIsRefusedAndWritesNothing(): void
    {
        $this->host()->beginTransaction();

        try {
            AuditLog::event(self::CODE)->afterCommit('audit_unknown')->record();

            self::fail('Expected the unknown connection to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Database connection [audit_unknown] not configured.', $exception->getMessage());
        }

        $this->host()->commit();

        self::assertSame(0, $this->entryCount());
    }

    /**
     * Under the `throw` mode a failed write surfaces from the commit, after the
     * business data has committed.
     *
     * @return void
     */
    public function testAFailedWriteSurfacesAfterTheBusinessDataHasCommitted(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        $this->createInvoices();
        $this->pointAtProbeTable();

        $this->host()->beginTransaction();

        $this->host()->table(self::INVOICES)->insert(['number' => 'INV-1']);

        $record = AuditLog::record(self::CODE);

        self::assertSame(self::CODE, $record->event);

        $this->assertTheCommitFails();

        self::assertSame(0, $this->host()->transactionLevel());
        self::assertSame(1, $this->host()->table(self::INVOICES)->count());
        self::assertSame(0, $this->probeCount());
    }

    /**
     * Under the `throw` mode a failed write stops the after-commit callbacks
     * registered behind it.
     *
     * @return void
     */
    public function testAFailedWriteStopsLaterAfterCommitCallbacks(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        $this->pointAtProbeTable();

        $this->host()->beginTransaction();

        $this->registerCallback('earlier');

        AuditLog::record(self::CODE);

        $this->registerCallback('later');

        $this->assertTheCommitFails();

        self::assertSame(['earlier'], $this->callbacks);
    }

    /**
     * With no failure every callback runs, the record among them in its place.
     *
     * @return void
     */
    public function testACallbackBehindAWrittenRecordRunsAfterTheWrite(): void
    {
        $this->host()->beginTransaction();

        AuditLog::record(self::CODE);

        $this->host()->afterCommit(function (): void {
            $this->callbacks[] = 'entries: ' . $this->entryCount();
        });

        $this->host()->commit();

        self::assertSame(['entries: 1'], $this->callbacks);
    }

    /**
     * On a dedicated storage connection a default record is dropped by the
     * host's rollback.
     *
     * @return void
     */
    #[DefineEnvironment('useDedicatedStorage')]
    public function testTheDedicatedDefaultIsDroppedByAHostRollback(): void
    {
        $this->host()->beginTransaction();

        AuditLog::record(self::CODE);

        self::assertSame(0, $this->storageConnection()->transactionLevel());

        $this->host()->rollBack();

        self::assertSame(self::STORAGE, $this->storageConnection()->getName());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * On a dedicated storage connection a default record is written on the
     * host's commit.
     *
     * @return void
     */
    #[DefineEnvironment('useDedicatedStorage')]
    public function testTheDedicatedDefaultIsWrittenOnAHostCommit(): void
    {
        $this->host()->beginTransaction();

        $record = AuditLog::record(self::CODE);

        self::assertSame(0, $this->entryCount());

        $this->host()->commit();

        self::assertSame(1, $this->entryCount());
        self::assertSame($record->id, $this->storedRow($record->id)['id']);
    }

    /**
     * A record pinned to an idle dedicated storage connection is written now
     * and survives the host's rollback.
     *
     * @return void
     */
    #[DefineEnvironment('useDedicatedStorage')]
    public function testPinningTheDedicatedConnectionIgnoresTheHostsRollback(): void
    {
        $this->host()->beginTransaction();

        AuditLog::event(self::CODE)->afterCommit(self::STORAGE)->record();

        self::assertSame(1, $this->entryCount());

        $this->host()->rollBack();

        self::assertSame(1, $this->entryCount());
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
     * Create the table holding the host's business data.
     *
     * @return void
     */
    private function createInvoices(): void
    {
        Schema::connection(self::CONNECTION)->create(self::INVOICES, static function (Blueprint $table): void {
            $table->string('number', 16);
        });
    }

    /**
     * Register a host after-commit callback that notes its name when it runs.
     *
     * @param  string  $name
     * @return void
     */
    private function registerCallback(string $name): void
    {
        $this->host()->afterCommit(function () use ($name): void {
            $this->callbacks[] = $name;
        });
    }

    /**
     * Commit the host's transaction, whose deferred insert fails on a `NOT
     * NULL` column with the engine's `QueryException`, sanitised.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function assertTheCommitFails(): void
    {
        try {
            $this->host()->commit();

            self::fail('Expected the deferred audit insert to fail.');
        } catch (AuditWriteFailedException $exception) {
            self::assertSame(QueryException::class, $exception->exceptionClass);
            self::assertNotNull($exception->sqlState);
        }
    }
}
