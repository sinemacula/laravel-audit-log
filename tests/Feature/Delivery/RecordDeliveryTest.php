<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Log\LogManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Delivery\CaptureSignal;
use SineMacula\Laravel\AuditLog\Delivery\FailedWrite;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\PackageWrite;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Export\NdjsonFormatter;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use SineMacula\Laravel\AuditLog\Stores\LogAuditStore;
use SineMacula\Laravel\AuditLog\Stores\NullAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SearchesForSecrets;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\Fixtures\Stores\PlainStore;
use Tests\TestCase;

/**
 * Feature tests for how one captured record is delivered, by timing, delivery
 * mode and failure rule.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordDelivery::class)]
final class RecordDeliveryTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore, InteractsWithOutbox, SearchesForSecrets, SeedsTheOutbox;

    /** @var string A second connection, on an in-memory SQLite database whatever the engine under test. */
    private const string OTHER = 'other';

    /** @var string A connection of the audit log's own, on which no host transaction is open. */
    private const string DEDICATED = 'audit_dedicated';

    /** @var string The code a test records. */
    private const string CODE = 'invoice.approved';

    /** @var string The code recorded from inside a write. */
    private const string INNER_CODE = 'invoice.inner';

    /** @var string A value of the record made inside a write. */
    private const string INNER_VALUE = 'kept-out-of-every-frame';

    /** @var string What a fail-closed or a transactional capture is refused with. */
    private const string STRICT_CAPTURE = 'A captured record is written immediately or after commit, never fail-closed or transactional.';

    /** @var string A failure Laravel reads as a concurrency error. */
    private const string DEADLOCK = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock';

    /** @var string What a fail-closed or a transactional record made inside the guard is refused with. */
    private const string STRICT_REFUSAL = 'A fail-closed or transactional record was made while an audit record was being written or its failure handled,'
        . ' so its guarantee cannot be met.';

    /** @var string Why a package write is refused any other timing. */
    private const string LOOSE_PACKAGE_WRITE = 'A package write is delivered immediately and fail-closed.';

    /** @var list<string> The class each capture's signal passed on, in order. */
    private array $signalled = [];

    /** @var list<string> What a package write and a listener saw, in order. */
    private array $seen = [];

    /** @var list<\SineMacula\Laravel\AuditLog\Records\FinalisedRecord> The finalised records a package write was handed, in order. */
    private array $acknowledged = [];

    /**
     * Capture every line logged.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->captureLogLines();
    }

    /**
     * Roll back any transaction a test left open.
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

        parent::tearDown();
    }

    /**
     * An immediate record is in the entries table when `deliver()` returns.
     *
     * @return void
     */
    public function testImmediateWritesNow(): void
    {
        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertSame(1, $this->entryCount());
    }

    /**
     * An immediate record does not wait for an open transaction.
     *
     * @return void
     */
    public function testImmediateDoesNotWaitForATransaction(): void
    {
        $fake = FakeAuditStore::fake();

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertSame(1, $fake->count());
    }

    /**
     * A transactional record is written inside the open transaction, and goes
     * with it when it is rolled back.
     *
     * @return void
     */
    public function testTransactionalWritesNow(): void
    {
        $connection = DB::connection(self::CONNECTION);

        $connection->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::TRANSACTIONAL, null);

        self::assertSame(1, $this->entryCount());

        $connection->rollBack();

        self::assertSame(0, $this->entryCount());
    }

    /**
     * With no transaction open, an after-commit record is written at once.
     *
     * @return void
     */
    public function testAfterCommitWritesNowWithNoTransaction(): void
    {
        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);

        self::assertSame(1, $this->entryCount());
    }

    /**
     * An after-commit record waits for the commit, and is committed when the
     * transaction's work is.
     *
     * @return void
     */
    public function testAfterCommitDefersToTheCommit(): void
    {
        $connection = DB::connection(self::CONNECTION);

        $connection->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);

        self::assertSame(0, $this->entryCount());

        $connection->commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A rollback drops an after-commit record and writes nothing.
     *
     * @return void
     */
    public function testAfterCommitDropsOnRollback(): void
    {
        $fake       = FakeAuditStore::fake();
        $connection = DB::connection(self::CONNECTION);

        $connection->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);

        $connection->rollBack();

        self::assertSame(0, $fake->count());
    }

    /**
     * An after-commit record pinned to a connection is not held back by a
     * transaction on another one.
     *
     * @return void
     */
    public function testAfterCommitPinnedToAConnectionIgnoresAnother(): void
    {
        $fake = FakeAuditStore::fake();

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, self::OTHER);

        self::assertSame(1, $fake->count());
    }

    /**
     * An after-commit record pinned to a connection waits for that connection's
     * commit, and for no other.
     *
     * @return void
     */
    public function testAfterCommitPinnedToAConnectionWaitsForIt(): void
    {
        $fake = FakeAuditStore::fake();

        DB::connection(self::OTHER)->beginTransaction();
        DB::connection(self::CONNECTION)->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, self::OTHER);

        DB::connection(self::CONNECTION)->commit();

        self::assertSame(0, $fake->count());

        DB::connection(self::OTHER)->commit();

        self::assertSame(1, $fake->count());
    }

    /**
     * With no transactions manager an after-commit record is written at once,
     * from the delivery's own container.
     *
     * @return void
     */
    public function testAContainerWithoutATransactionsManagerWritesNow(): void
    {
        DB::connection(self::CONNECTION)->beginTransaction();

        $container = new Container;

        $container->instance(RecordFinaliser::class, app(RecordFinaliser::class));
        $container->instance(Dispatcher::class, app(Dispatcher::class));
        $container->instance(Repository::class, app(Repository::class));

        $own     = FakeAuditStore::fake($container);
        $another = FakeAuditStore::fake();

        (new RecordDelivery($container, app(ConnectionResolverInterface::class)))->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);

        self::assertSame(1, $own->count());
        self::assertSame(0, $another->count());
    }

    /**
     * A store bound after the record was captured, while the transaction is
     * open, is the one that receives it.
     *
     * @return void
     */
    public function testAStoreBoundLaterIsTheOneUsed(): void
    {
        $connection = DB::connection(self::CONNECTION);
        $earlier    = FakeAuditStore::fake();

        $connection->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);

        $later = FakeAuditStore::fake();

        $connection->commit();

        self::assertSame(0, $earlier->count());
        self::assertSame(1, $later->count());
    }

    /**
     * The record is finalised once, by the clock bound when it is written, and
     * so stamped with the time of the write rather than the capture.
     *
     * @return void
     */
    public function testFinalisesOnceAndStampsTheWriteTime(): void
    {
        $fake       = FakeAuditStore::fake();
        $connection = DB::connection(self::CONNECTION);
        $record     = RecordFactory::captured();

        $connection->beginTransaction();

        $this->delivery()->deliver($record, Timing::AFTER_COMMIT, null);

        $clock = \Mockery::mock(Clock::class);

        $clock->shouldReceive('now')->once()->andReturn(CarbonImmutable::parse('2026-11-01 12:00:09.5', 'UTC'));

        app()->instance(Clock::class, $clock);

        $connection->commit();

        self::assertCount(1, $fake->finalised());
        self::assertSame($record, $fake->finalised()[0]->record);
        self::assertSame('2026-11-01T12:00:09.500000Z', $fake->finalised()[0]->recordedAt);
    }

    /**
     * Under the `throw` mode a failed write reaches the caller, sanitised, and
     * no event says the store accepted the record.
     *
     * @return void
     */
    public function testAFailedWritePropagatesAndNotifiesNothing(): void
    {
        $this->failureMode('throw');

        Event::fake([AuditRecorded::class]);
        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        try {
            $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

            self::fail('Expected the write to fail.');
        } catch (AuditWriteFailedException $caught) {
            self::assertSame(\RuntimeException::class, $caught->exceptionClass);
            self::assertNull($caught->getPrevious());
        }

        Event::assertNotDispatched(AuditRecorded::class);
    }

    /**
     * Under the `throw` mode a deferred write's failure reaches the code that
     * commits, sanitised.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeferredWritesFailureReachesTheCommit(): void
    {
        $connection = DB::connection(self::CONNECTION);

        $this->failureMode('throw');

        Event::fake([AuditRecorded::class]);
        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $connection->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);

        try {
            $connection->commit();

            self::fail('Expected the write to fail.');
        } catch (AuditWriteFailedException $caught) {
            self::assertSame(\RuntimeException::class, $caught->exceptionClass);
            self::assertNull($caught->getPrevious());
        }

        Event::assertNotDispatched(AuditRecorded::class);
    }

    /**
     * The event names the record's id, code and category.
     *
     * @return void
     */
    public function testTheEventCarriesTheIdCodeAndCategory(): void
    {
        Event::fake([AuditRecorded::class]);
        FakeAuditStore::fake();

        $record = RecordFactory::captured();

        $this->delivery()->deliver($record, Timing::IMMEDIATE, null);

        Event::assertDispatchedTimes(AuditRecorded::class, 1);
        Event::assertDispatched(
            AuditRecorded::class,
            static fn (AuditRecorded $event): bool => $event->id === $record->id && $event->code === 'invoice.approved' && $event->category === 'finance',
        );
    }

    /**
     * The store holds the record by the time a listener hears of it.
     *
     * @return void
     */
    public function testTheEventFollowsTheWrite(): void
    {
        $fake  = FakeAuditStore::fake();
        $heard = [];

        Event::listen(AuditRecorded::class, static function () use ($fake, &$heard): void {
            $heard[] = $fake->count();
        });

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertSame([1], $heard);
    }

    /**
     * A listener's exception is reported, the very exception, and goes no
     * further.
     *
     * @return void
     */
    public function testAThrowingListenerIsReportedAndContained(): void
    {
        $exception = new \RuntimeException('The listener failed.');
        $handler   = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report')->once()->with($exception);

        app()->instance(ExceptionHandler::class, $handler);

        $fake = FakeAuditStore::fake();

        $this->listenerThrows($exception);

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertSame(1, $fake->count());
    }

    /**
     * A reporter that throws as well goes no further either.
     *
     * @return void
     */
    public function testAThrowingReporterIsContained(): void
    {
        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report')->once()->andThrow(new \RuntimeException('The reporter failed.'));

        app()->instance(ExceptionHandler::class, $handler);

        $fake = FakeAuditStore::fake();

        $this->listenerThrows(new \RuntimeException('The listener failed.'));

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertSame(1, $fake->count());
    }

    /**
     * A dispatcher that cannot even be resolved is contained like a listener
     * that throws, because the record is already stored by then.
     *
     * @return void
     */
    public function testADispatcherThatCannotBeResolvedIsContained(): void
    {
        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report')->once();

        $container = new Container;

        $container->instance(RecordFinaliser::class, app(RecordFinaliser::class));
        $container->instance(ExceptionHandler::class, $handler);
        $container->instance(Repository::class, app(Repository::class));

        $fake = FakeAuditStore::fake($container);

        (new RecordDelivery($container, app(ConnectionResolverInterface::class)))->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertSame(1, $fake->count());
    }

    /**
     * A listener's failure never leads to a second write.
     *
     * @return void
     */
    public function testANotificationFailureNeverCausesAnotherWrite(): void
    {
        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report');

        app()->instance(ExceptionHandler::class, $handler);

        $fake = FakeAuditStore::fake();

        $this->listenerThrows(new \RuntimeException('The listener failed.'));

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertCount(1, $fake->finalised());
    }

    /**
     * A listener's failure during a commit stops neither the commit nor the
     * next after-commit callback.
     *
     * @return void
     */
    public function testAThrowingListenerDoesNotStopALaterAfterCommitCallback(): void
    {
        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report')->twice();

        app()->instance(ExceptionHandler::class, $handler);

        $fake       = FakeAuditStore::fake();
        $connection = DB::connection(self::CONNECTION);

        $this->listenerThrows(new \RuntimeException('The listener failed.'));

        $connection->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);
        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);

        $connection->commit();

        self::assertSame(2, $fake->count());
    }

    /**
     * A transactional record with no transaction open is refused, naming the
     * storage connection.
     *
     * @return void
     */
    public function testTransactionalWithoutAnOpenTransactionIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A transactional record needs a transaction open on the storage connection [testing].');

        $this->delivery()->check(Timing::TRANSACTIONAL, null);
    }

    /**
     * A transaction open only on another connection does not help a
     * transactional record.
     *
     * @return void
     */
    public function testTransactionalOpenOnlyOnAnotherConnectionIsRefused(): void
    {
        DB::connection(self::OTHER)->beginTransaction();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A transactional record needs a transaction open on the storage connection [testing].');

        $this->delivery()->check(Timing::TRANSACTIONAL, null);
    }

    /**
     * Naming a connection other than the storage connection is refused, even
     * with a transaction open on both, naming each.
     *
     * @return void
     */
    public function testTransactionalOnAnotherConnectionIsRefused(): void
    {
        DB::connection(self::CONNECTION)->beginTransaction();
        DB::connection(self::OTHER)->beginTransaction();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A transactional record is written on the storage connection [testing], not [other]; another connection needs the outbox.');

        $this->delivery()->check(Timing::TRANSACTIONAL, self::OTHER);
    }

    /**
     * Naming the storage connection, with a transaction open on it, is the same
     * as naming none.
     *
     * @return void
     */
    public function testTransactionalNamingTheStorageConnectionIsAccepted(): void
    {
        DB::connection(self::CONNECTION)->beginTransaction();

        $this->delivery()->check(Timing::TRANSACTIONAL, self::CONNECTION);
        $this->delivery()->check(Timing::TRANSACTIONAL, null);

        $this->addToAssertionCount(1);
    }

    /**
     * The storage connection is the configured one, and its own transaction is
     * the one that counts.
     *
     * @return void
     */
    public function testTransactionalFollowsAConfiguredStorageConnection(): void
    {
        app(ConfigRepository::class)->set('audit-log.storage.connection', self::OTHER);

        DB::connection(self::OTHER)->beginTransaction();

        $this->delivery()->check(Timing::TRANSACTIONAL, self::OTHER);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A transactional record is written on the storage connection [other], not [testing]; another connection needs the outbox.');

        $this->delivery()->check(Timing::TRANSACTIONAL, self::CONNECTION);
    }

    /**
     * A storage connection that is not a database connection has no trusted
     * transaction levels, so a transactional record is refused.
     *
     * @return void
     */
    public function testTransactionalOnAForeignConnectionIsRefused(): void
    {
        $connection = \Mockery::mock(ConnectionInterface::class);

        $connection->shouldReceive('transactionLevel')->andReturn(1);

        $resolver = \Mockery::mock(ConnectionResolverInterface::class);

        $resolver->shouldReceive('connection')->with(self::CONNECTION)->andReturn($connection);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A transactional record needs a transaction open on the storage connection [testing].');

        (new RecordDelivery(Container::getInstance(), $resolver))->check(Timing::TRANSACTIONAL, null);
    }

    /**
     * A name no connection answers to is refused rather than silently writing
     * at once.
     *
     * @return void
     */
    public function testAfterCommitOnAnUnknownConnectionIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('[unknown]');

        $this->delivery()->check(Timing::AFTER_COMMIT, 'unknown');
    }

    /**
     * Checking a known connection opens nothing, so a record pinned to a
     * connection that is down costs nothing until it is written.
     *
     * @return void
     */
    public function testAfterCommitOnAKnownConnectionOpensNoPdo(): void
    {
        $this->delivery()->check(Timing::AFTER_COMMIT, self::OTHER);

        $connection = DB::connection(self::OTHER);

        self::assertInstanceOf(Connection::class, $connection);
        self::assertInstanceOf(\Closure::class, $connection->getRawPdo());
    }

    /**
     * A record naming a connection with a read or write selector waits for the
     * transaction on that connection, whose record holds the plain name.
     *
     * @return void
     */
    public function testAfterCommitWithASelectorDefersToTheConnectionsTransaction(): void
    {
        $fake = FakeAuditStore::fake();

        DB::connection(self::OTHER)->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, self::OTHER . '::write');

        self::assertSame(0, $fake->count());

        DB::connection(self::OTHER)->commit();

        self::assertSame(1, $fake->count());
    }

    /**
     * A record naming a connection with a selector is dropped with that
     * connection's transaction.
     *
     * @return void
     */
    public function testAfterCommitWithASelectorDropsOnRollback(): void
    {
        $fake = FakeAuditStore::fake();

        DB::connection(self::OTHER)->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, self::OTHER . '::write');

        DB::connection(self::OTHER)->rollBack();

        self::assertSame(0, $fake->count());
    }

    /**
     * A resolver giving something that is no `Connection`, or a connection with
     * no name of its own, leaves the name as it was given.
     *
     * @return void
     */
    public function testAConnectionThatGivesNoNameLeavesTheOneGiven(): void
    {
        $unnamed = \Mockery::mock(Connection::class);

        $unnamed->shouldReceive('getName')->andReturn(null);

        foreach ([\Mockery::mock(ConnectionInterface::class), $unnamed] as $resolved) {

            $fake     = FakeAuditStore::fake();
            $resolver = \Mockery::mock(ConnectionResolverInterface::class);

            $resolver->shouldReceive('connection')->with(self::OTHER)->andReturn($resolved);

            DB::connection(self::OTHER)->beginTransaction();

            (new RecordDelivery(Container::getInstance(), $resolver))->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, self::OTHER);

            self::assertSame(0, $fake->count());

            DB::connection(self::OTHER)->commit();

            self::assertSame(1, $fake->count());
        }
    }

    /**
     * A transactional record naming the storage connection with a selector is
     * refused, as any other name is.
     *
     * @return void
     */
    public function testTransactionalWithASelectorIsRefused(): void
    {
        DB::connection(self::CONNECTION)->beginTransaction();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A transactional record is written on the storage connection [testing], not [testing::write]; another connection needs the outbox.');

        $this->delivery()->check(Timing::TRANSACTIONAL, self::CONNECTION . '::write');
    }

    /**
     * An after-commit record naming no connection resolves nothing.
     *
     * @return void
     */
    public function testAfterCommitWithNoNameChecksNothing(): void
    {
        $resolver = \Mockery::mock(ConnectionResolverInterface::class);

        $resolver->shouldNotReceive('connection');

        (new RecordDelivery(Container::getInstance(), $resolver))->check(Timing::AFTER_COMMIT, null);

        $this->addToAssertionCount(1);
    }

    /**
     * An immediate record asks nothing, even of a name that does not exist.
     *
     * @return void
     */
    public function testImmediateChecksNothing(): void
    {
        $resolver = \Mockery::mock(ConnectionResolverInterface::class);

        $resolver->shouldNotReceive('connection');

        (new RecordDelivery(Container::getInstance(), $resolver))->check(Timing::IMMEDIATE, 'unknown');
        (new RecordDelivery(Container::getInstance(), $resolver))->check(Timing::IMMEDIATE, null);

        $this->addToAssertionCount(1);
    }

    /**
     * In the default mode a failed write returns to the caller, reports the
     * failure sanitised, spills the record and says nothing of a written one.
     *
     * @return void
     */
    public function testAReportModeFailureReturnsAndNotifiesNothing(): void
    {
        $reporter = $this->reporter();
        $failures = [];

        Event::listen(AuditWriteFailed::class, static function (AuditWriteFailed $event) use (&$failures): void {
            $failures[] = $event;
        });

        $recorded = 0;

        Event::listen(AuditRecorded::class, static function () use (&$recorded): void {
            $recorded++;
        });

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $record = RecordFactory::captured();

        $this->delivery()->deliver($record, Timing::IMMEDIATE, null);

        $report = self::reportOf($reporter);

        self::assertSame(0, $recorded);
        self::assertCount(1, $failures);
        self::assertSame($record->id, $failures[0]->id);
        self::assertSame($record->id, $report->recordId);
        self::assertSame(FailedOperation::STORE->value, $report->operation);
        self::assertSame(\RuntimeException::class, $report->exceptionClass);
        self::assertSame(self::CONNECTION, $report->connection);
        self::assertNull($report->getPrevious());
        $this->assertSpilled(1);
    }

    /**
     * In the default mode a deferred write's failure stays out of the commit,
     * whose own work has already committed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeferredReportModeFailureLeavesTheCommitAlone(): void
    {
        $reporter   = $this->reporter();
        $connection = DB::connection(self::CONNECTION);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $connection->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);

        $this->assertSpilled(0);

        $connection->commit();

        self::assertSame(0, $connection->transactionLevel());
        self::assertCount(1, $reporter->reports());
        $this->assertSpilled(1);
    }

    /**
     * In the default mode a deferred write's failure stops no callback behind
     * it, a later record's among them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeferredReportModeFailureLeavesLaterCallbacksRunning(): void
    {
        $this->reporter();

        $connection = DB::connection(self::CONNECTION);
        $ran        = [];

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $connection->beginTransaction();

        $connection->afterCommit(static function () use (&$ran): void {
            $ran[] = 'earlier';
        });

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);
        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);

        $connection->afterCommit(static function () use (&$ran): void {
            $ran[] = 'later';
        });

        $connection->commit();

        self::assertSame(['earlier', 'later'], $ran);
        $this->assertSpilled(2);
    }

    /**
     * Rows of `[failure mode]`: both of them.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideFailureModes(): iterable
    {
        yield from [
            'report' => [FailureMode::REPORT->value],
            'throw'  => [FailureMode::THROW->value],
        ];
    }

    /**
     * A fail-closed record throws, spilled, under either failure mode.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideFailureModes')]
    public function testAFailClosedRecordThrowsWhateverTheMode(string $mode): void
    {
        $reporter = $this->reporter();

        $this->failureMode($mode);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        try {
            $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null, true);

            self::fail('Expected the write to fail.');
        } catch (AuditWriteFailedException $caught) {
            self::assertSame(\RuntimeException::class, $caught->exceptionClass);
        }

        self::assertSame([], $reporter->reports());
        $this->assertSpilled(1);
    }

    /**
     * A transactional record throws, never spilled, under either failure mode.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideFailureModes')]
    public function testATransactionalRecordThrowsWhateverTheMode(string $mode): void
    {
        $reporter   = $this->reporter();
        $connection = DB::connection(self::CONNECTION);

        $this->failureMode($mode);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $connection->beginTransaction();

        try {
            $this->delivery()->deliver(RecordFactory::captured(), Timing::TRANSACTIONAL, null);

            self::fail('Expected the write to fail.');
        } catch (AuditWriteFailedException $caught) {
            self::assertSame(\RuntimeException::class, $caught->exceptionClass);
        }

        $connection->commit();

        self::assertSame([], $reporter->reports());
        $this->assertSpilled(0);
    }

    /**
     * An unresolvable store is a failed write named by its contract: reported
     * by default and thrown under `throw`.
     *
     * @return void
     */
    public function testAnUnresolvableStoreFollowsThePolicy(): void
    {
        $reporter = $this->reporter();

        app()->bind(AuditStore::class, static function (): never {
            throw new \RuntimeException('The store cannot be built.');
        });

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertSame(AuditStore::class, self::reportOf($reporter)->store);
        self::assertSame(\RuntimeException::class, self::reportOf($reporter)->exceptionClass);

        $this->failureMode('throw');

        try {
            $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

            self::fail('Expected the write to fail.');
        } catch (AuditWriteFailedException $caught) {
            self::assertSame(AuditStore::class, $caught->store);
        }
    }

    /**
     * An anonymous store is named by what it implements, with no file path and
     * no NUL byte.
     *
     * @return void
     */
    public function testAnAnonymousStoreIsNamedWithoutItsPath(): void
    {
        $reporter = $this->reporter();

        app()->instance(AuditStore::class, new class implements AuditStore {
            /**
             * Fail.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function store(#[\SensitiveParameter] FinalisedRecord $record): void
            {
                throw new \RuntimeException('The store is down.');
            }
        });

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertSame(AuditStore::class . '@anonymous', self::reportOf($reporter)->store);
    }

    /**
     * A record that cannot be finalised is a failed write of that step, with no
     * store resolved and a spill marked unsigned.
     *
     * @return void
     */
    public function testAFailedFinaliseFollowsThePolicy(): void
    {
        $reporter = $this->reporter();
        $clock    = \Mockery::mock(Clock::class);

        $clock->shouldReceive('now')->once()->andThrow(new \RuntimeException('The clock stopped.'));

        app()->instance(Clock::class, $clock);

        $fake = FakeAuditStore::fake();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertSame(0, $fake->count());
        self::assertSame(FailedOperation::FINALISE->value, self::reportOf($reporter)->operation);
        self::assertSame(AuditStore::class, self::reportOf($reporter)->store);
        $this->assertSpilled(1);
        self::assertStringContainsString('"unsigned":true', $this->spillLines()[0]);
    }

    /**
     * A transaction open on the storage connection at another connection's
     * commit holds the row, so its spill waits for that commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAfterCommitFailureInsideAnOpenStorageTransactionBindsItsSpill(): void
    {
        $reporter = $this->reporter();
        $storage  = DB::connection(self::CONNECTION);
        $other    = DB::connection(self::OTHER);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $other->beginTransaction();
        $storage->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, self::OTHER);

        $other->commit();

        self::assertCount(1, $reporter->reports());
        $this->assertSpilled(0);

        $storage->commit();

        $this->assertSpilled(1);
    }

    /**
     * That bound spill goes with the storage transaction's rollback, so a
     * replay never brings the record back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThatBoundSpillIsDiscardedWhenTheStorageTransactionRollsBack(): void
    {
        $reporter = $this->reporter();
        $storage  = DB::connection(self::CONNECTION);
        $other    = DB::connection(self::OTHER);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $other->beginTransaction();
        $storage->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, self::OTHER);

        $other->commit();
        $storage->rollBack();

        self::assertCount(1, $reporter->reports());
        $this->assertSpilled(0);
    }

    /**
     * An after-commit record pinned to another connection, written now while
     * the storage connection is transacting, binds its spill too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPinnedRecordWrittenNowBindsItsSpillToTheStorageTransaction(): void
    {
        $this->reporter();

        $storage = DB::connection(self::CONNECTION);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $storage->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, self::OTHER);

        $this->assertSpilled(0);

        $storage->commit();

        $this->assertSpilled(1);
    }

    /**
     * A write deferred to the storage connection's own commit has no
     * transaction left to wait for, so its spill goes at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeferredFailureOnTheStorageConnectionSpillsAtItsCommit(): void
    {
        $this->reporter();

        $storage = DB::connection(self::CONNECTION);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $storage->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);

        $this->assertSpilled(0);

        $storage->commit();

        $this->assertSpilled(1);
    }

    /**
     * With nothing open an after-commit record is written now, and its spill
     * goes at once.
     *
     * @return void
     */
    public function testAnAfterCommitFailureWithNothingOpenSpillsAtOnce(): void
    {
        $this->reporter();

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);

        $this->assertSpilled(1);
    }

    /**
     * An immediate record's spill goes at once, inside a host transaction too,
     * because that transaction may already have failed.
     *
     * @return void
     */
    public function testAnImmediateFailureInsideAHostSpillsAtOnce(): void
    {
        $this->reporter();

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        $this->assertSpilled(1);
    }

    /**
     * A transaction on another instance of the storage connection, as a
     * selector gives, cannot hold the row or its spill.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionOnAnotherInstanceOfTheStorageConnectionBindsNoSpill(): void
    {
        $this->reporter();

        $other = DB::connection(self::OTHER);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        DB::connection(self::CONNECTION . '::write')->beginTransaction();

        $other->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, self::OTHER);

        $other->commit();

        $this->assertSpilled(1);
    }

    /**
     * A failure raised by a listener that ended the transaction open on the
     * storage connection is thrown, sanitised, though the record was stored.
     *
     * @return void
     */
    public function testAHostFatalListenerFailureInsideAStorageTransactionPropagates(): void
    {
        FakeAuditStore::fake();

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->listenerThrows(new \RuntimeException('SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock'));

        $this->expectException(DeadlockException::class);

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);
    }

    /**
     * A deadlock of the write itself, with the storage connection transacting,
     * is thrown whatever the rule, because it has ended that transaction.
     *
     * @return void
     */
    public function testAHostFatalWriteFailurePropagatesInReportMode(): void
    {
        $reporter = $this->reporter();

        FakeAuditStore::failing(new \RuntimeException('SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock'));

        DB::connection(self::CONNECTION)->beginTransaction();

        try {
            $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

            self::fail('Expected the deadlock to propagate.');
        } catch (DeadlockException $caught) {
            self::assertNull($caught->getPrevious());
        }

        self::assertSame([], $reporter->reports());
        $this->assertSpilled(0);
    }

    /**
     * The same failure with no transaction open follows the rule, since no
     * transaction was ended.
     *
     * @return void
     */
    public function testADeadlockWithNothingOpenFollowsTheRule(): void
    {
        $reporter = $this->reporter();

        FakeAuditStore::failing(new \RuntimeException('SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock'));

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertCount(1, $reporter->reports());
        $this->assertSpilled(1);
    }

    /**
     * A storage connection that cannot be resolved has no transaction, and the
     * write's failure follows the rule rather than escaping.
     *
     * @return void
     */
    public function testAStorageConnectionThatCannotBeResolvedFollowsTheRule(): void
    {
        $reporter = $this->reporter();

        app(ConfigRepository::class)->set('audit-log.storage.connection', 'unknown');

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertNull(self::reportOf($reporter)->connection);
        $this->assertSpilled(1);
    }

    /**
     * A storage connection named with a read or write selector is known by the
     * connection's own name, as its transactions are, never the selector.
     *
     * @return void
     */
    public function testAStorageConnectionNamedWithASelectorIsKnownByItsOwnName(): void
    {
        $reporter = $this->reporter();

        app(ConfigRepository::class)->set('audit-log.storage.connection', self::OTHER . '::write');

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertSame(self::OTHER, self::reportOf($reporter)->connection);
    }

    /**
     * A deferred write holds the record sealed, so a failure's trace cannot
     * reach it through the transaction a commit's frames hold.
     *
     * @return void
     */
    public function testADeferredWriteHoldsTheRecordSealed(): void
    {
        FakeAuditStore::fake();

        $connection = DB::connection(self::CONNECTION);
        $record     = RecordFactory::captured();
        $manager    = app('db.transactions');

        $connection->beginTransaction();

        $this->delivery()->deliver($record, Timing::AFTER_COMMIT, null);

        self::assertInstanceOf(DatabaseTransactionsManager::class, $manager);

        $callbacks = $manager->callbackApplicableTransactions()->last()?->getCallbacks();

        self::assertCount(1, $callbacks ?? []);
        self::assertFalse(self::holdsText($callbacks, $record->id));
    }

    /**
     * Every parameter of the delivery that holds the record is marked
     * sensitive, so no frame of the delivery shows it.
     *
     * @return void
     */
    public function testEveryPayloadParameterIsMarkedSensitive(): void
    {
        $checked = [];

        foreach ((new \ReflectionClass(RecordDelivery::class))->getMethods() as $method) {
            foreach ($method->getParameters() as $parameter) {
                $type = $parameter->getType();
                $name = $type instanceof \ReflectionNamedType ? $type->getName() : '';

                if (!in_array($name, [AuditRecord::class, FinalisedRecord::class, FailedWrite::class, \Throwable::class, \Closure::class], true)) {
                    continue;
                }

                $checked[] = $method->getName();

                self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class), "{$method->getName()}() does not mark \${$parameter->getName()} sensitive.");
            }
        }

        self::assertSame(['deliver', 'writeAfterCommit', 'writeAfterTransaction', 'refuse', 'abandonSealed', 'write'], $checked);
    }

    /**
     * A listener's deadlock on the host's connection reaches the caller, though
     * the store's own dedicated connection had nothing open.
     *
     * @return void
     */
    public function testAListenersDeadlockOnTheHostsConnectionPropagatesFromADedicatedStore(): void
    {
        FakeAuditStore::fake();

        $this->storeOnADedicatedConnection();

        Event::listen(AuditRecorded::class, static function (): never {
            throw new QueryException(self::CONNECTION, 'update hosts set x = 1', [], new \PDOException('SQLSTATE[40001]: Deadlock found when trying to get lock'));
        });

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->expectException(DeadlockException::class);

        AuditLog::event(self::CODE)->immediately()->record();
    }

    /**
     * The same listener with nothing open on the host's connection ended
     * nothing, so the record stands and the failure is contained.
     *
     * @return void
     */
    public function testAListenersDeadlockWithNothingOpenIsContained(): void
    {
        FakeAuditStore::fake();

        $reporter = $this->reporter();

        Event::listen(AuditRecorded::class, static function (): never {
            throw new QueryException(self::CONNECTION, 'update hosts set x = 1', [], new \PDOException('SQLSTATE[40001]: Deadlock found when trying to get lock'));
        });

        AuditLog::event(self::CODE)->immediately()->record();

        self::assertCount(1, $reporter->reports());
    }

    /**
     * An `AuditWriteFailed` listener's deadlock on the host's connection
     * reaches the host the same way.
     *
     * @return void
     */
    public function testAFailureStepOnTheHostsConnectionPropagatesFromADedicatedStore(): void
    {
        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $this->storeOnADedicatedConnection();

        Event::listen(AuditWriteFailed::class, static function (): never {
            throw new QueryException(self::CONNECTION, 'update hosts set x = 1', [], new \PDOException('SQLSTATE[40001]: Deadlock found when trying to get lock'));
        });

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->expectException(DeadlockException::class);

        AuditLog::event(self::CODE)->immediately()->record();
    }

    /**
     * A malformed failure mode is refused by a check, naming the key.
     *
     * @return void
     */
    public function testACheckRefusesAMalformedFailureMode(): void
    {
        $this->failureMode('nonsense');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.failure.mode`');

        $this->delivery()->check(Timing::IMMEDIATE, null);
    }

    /**
     * A malformed delivery mode is refused by a check, naming the key.
     *
     * @return void
     */
    public function testACheckRefusesAMalformedDeliveryMode(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', 'nonsense');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.delivery.mode`');

        $this->delivery()->check(Timing::IMMEDIATE, null);
    }

    /**
     * Rows of `[key]`: each mode's setting.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideModeKeys(): iterable
    {
        yield from [
            'the failure mode'  => ['audit-log.failure.mode'],
            'the delivery mode' => ['audit-log.delivery.mode'],
        ];
    }

    /**
     * A malformed mode refuses the record and leaves its builder usable, and it
     * is never an exception out of a commit, since nothing was deferred.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideModeKeys')]
    public function testARefusedModeLeavesTheBuilderUsable(string $key): void
    {
        $fake    = FakeAuditStore::fake();
        $config  = app(ConfigRepository::class);
        $before  = $config->get($key);
        $pending = AuditLog::event(self::CODE);

        $config->set($key, 'nonsense');

        try {
            $pending->record();

            self::fail('Expected the record to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString($key, $exception->getMessage());
        }

        self::assertSame(0, $fake->count());

        $config->set($key, $before);

        $pending->record();

        self::assertSame(1, $fake->count());
    }

    /**
     * A mode read at `deliver()` without a check is refused there too, before
     * anything is deferred.
     *
     * @return void
     */
    public function testADeliveryReadsTheModesBeforeDeferring(): void
    {
        $connection = DB::connection(self::CONNECTION);
        $fake       = FakeAuditStore::fake();

        $connection->beginTransaction();

        $this->failureMode('nonsense');

        try {
            $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);

            self::fail('Expected the delivery to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('audit-log.failure.mode', $exception->getMessage());
        }

        $this->failureMode('report');

        $connection->commit();

        self::assertSame(0, $fake->count());
    }

    /**
     * Rows of `[what makes the store, its class]`: the stores that do not say a
     * return is durable.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\AuditLog\Contracts\AuditStore, 1: class-string}>
     */
    public static function provideStoresThatAreNotDurable(): iterable
    {
        yield from [
            'null'  => [static fn (): AuditStore => new NullAuditStore, NullAuditStore::class],
            'log'   => [static fn (): AuditStore => new LogAuditStore(app(LogManager::class), new NdjsonFormatter), LogAuditStore::class],
            'plain' => [static fn (): AuditStore => new PlainStore, PlainStore::class],
        ];
    }

    /**
     * A fail-closed record needs a store that says a return is durable, and the
     * refusal names the store it has.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Contracts\AuditStore  $store
     * @param  class-string  $class
     * @return void
     */
    #[DataProvider('provideStoresThatAreNotDurable')]
    public function testAFailClosedRecordNeedsADurableStore(\Closure $store, string $class): void
    {
        app()->instance(AuditStore::class, $store());

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf('A fail-closed record needs a durable store, and %s does not say it is. Bind one, or use the outbox.', $class));

        $this->delivery()->check(Timing::IMMEDIATE, null, true);
    }

    /**
     * An ordinary record asks nothing of the store.
     *
     * @return void
     */
    public function testAnOrdinaryRecordAsksNothingOfTheStore(): void
    {
        app()->bind(AuditStore::class, static function (): never {
            throw new \RuntimeException('The store must not be resolved by a check.');
        });

        $this->delivery()->check(Timing::IMMEDIATE, null);
        $this->delivery()->check(Timing::AFTER_COMMIT, null);

        $this->addToAssertionCount(1);
    }

    /**
     * A transactional record needs a store that joins the transaction, and a
     * store that says nothing of itself does not.
     *
     * @return void
     */
    public function testATransactionalRecordNeedsAParticipatingStore(): void
    {
        app()->instance(AuditStore::class, new PlainStore);

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf('A transactional record needs a store that joins the transaction on [testing], and %s does not.', PlainStore::class));

        $this->delivery()->check(Timing::TRANSACTIONAL, null);
    }

    /**
     * A stack holding a destination that cannot join the transaction is refused
     * for a transactional record, whose log line would outlive its rollback.
     *
     * @return void
     */
    public function testAStackWithANonParticipatingDestinationIsRefusedForTransactional(): void
    {
        app()->instance(AuditStore::class, new StackAuditStore([
            'database' => app(DatabaseAuditStore::class),
            'log'      => new LogAuditStore(app(LogManager::class), new NdjsonFormatter),
        ]));

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf('A transactional record needs a store that joins the transaction on [testing], and %s does not.', StackAuditStore::class));

        $this->delivery()->check(Timing::TRANSACTIONAL, null);
    }

    /**
     * Durability is not participation: a durable store that joins nothing is
     * refused for a transactional record and accepted for a fail-closed one.
     *
     * @return void
     */
    public function testADurableStoreThatDoesNotParticipateIsRefusedForTransactional(): void
    {
        app()->instance(AuditStore::class, CallbackStore::saying(true));

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->delivery()->check(Timing::IMMEDIATE, null, true);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A transactional record needs a store that joins the transaction on [testing]');

        $this->delivery()->check(Timing::TRANSACTIONAL, null);
    }

    /**
     * Participation is not durability: a joining store that is not durable is
     * refused for fail-closed and accepted for transactional.
     *
     * @return void
     */
    public function testAParticipatingStoreThatIsNotDurableIsRefusedForFailClosed(): void
    {
        app()->instance(AuditStore::class, CallbackStore::saying(false, [self::CONNECTION]));

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->delivery()->check(Timing::TRANSACTIONAL, null);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A fail-closed record needs a durable store');

        $this->delivery()->check(Timing::TRANSACTIONAL, null, true);
    }

    /**
     * The store joins the configured storage connection, not the default one.
     *
     * @return void
     */
    public function testParticipationIsAskedOfTheStorageConnection(): void
    {
        app(ConfigRepository::class)->set('audit-log.storage.connection', self::OTHER);
        app()->instance(AuditStore::class, CallbackStore::saying(true, [self::CONNECTION]));

        DB::connection(self::OTHER)->beginTransaction();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A transactional record needs a store that joins the transaction on [other]');

        $this->delivery()->check(Timing::TRANSACTIONAL, null);
    }

    /**
     * The outbox acknowledges for a strict record, whatever the store says of
     * itself or fails to.
     *
     * @return void
     */
    public function testOutboxModeAcknowledgesForAStoreWithNeither(): void
    {
        $this->outboxModeOn();

        app()->instance(AuditStore::class, new PlainStore);

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->delivery()->check(Timing::IMMEDIATE, null, true);
        $this->delivery()->check(Timing::TRANSACTIONAL, null);
        $this->delivery()->check(Timing::TRANSACTIONAL, null, true);

        $this->addToAssertionCount(1);
    }

    /**
     * A transactional record in outbox mode needs no name, is written on the
     * outbox connection inside its transaction, and goes with the rollback.
     *
     * @return void
     */
    public function testTransactionalInOutboxModeDefaultsToTheOutboxConnection(): void
    {
        $this->outboxModeOn();

        $connection = $this->outboxConnection();

        $connection->beginTransaction();

        $this->delivery()->check(Timing::TRANSACTIONAL, null);
        $this->delivery()->check(Timing::TRANSACTIONAL, self::CONNECTION);
        $this->delivery()->deliver(RecordFactory::captured(), Timing::TRANSACTIONAL, null);

        self::assertSame(1, $this->outboxCount());

        $connection->rollBack();

        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A transactional record in outbox mode naming another connection is
     * refused, naming each.
     *
     * @return void
     */
    public function testTransactionalInOutboxModeRefusesAnotherConnection(): void
    {
        $this->outboxModeOn();

        $this->outboxConnection()->beginTransaction();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A transactional record is written on the outbox connection [testing], not [other].');

        $this->delivery()->check(Timing::TRANSACTIONAL, self::OTHER);
    }

    /**
     * A transactional outbox record needs a transaction on the outbox
     * connection, not the storage one, when the outbox has its own.
     *
     * @return void
     */
    public function testTransactionalInOutboxModeNeedsAnOpenTransaction(): void
    {
        $this->outboxModeOn();

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.connection', self::OTHER);

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A transactional record needs a transaction open on the outbox connection [other].');

        $this->delivery()->check(Timing::TRANSACTIONAL, null);
    }

    /**
     * In outbox mode the record goes to the outbox and no further: no entry, no
     * store call and no `AuditRecorded`, which the drain says.
     *
     * @return void
     */
    public function testOutboxModeWritesNoEntryAndDispatchesNothing(): void
    {
        $this->outboxModeOn();

        $record = RecordFactory::captured();
        $store  = new PlainStore;

        app()->instance(AuditStore::class, $store);

        Event::fake([AuditRecorded::class]);

        $this->delivery()->deliver($record, Timing::IMMEDIATE, null);

        self::assertSame(1, $this->outboxCount());
        self::assertNotNull($this->outboxRow($record->id));
        self::assertSame(0, $this->entryCount());
        self::assertSame(0, $store->calls());

        Event::assertNotDispatched(AuditRecorded::class);
    }

    /**
     * An after-commit record in outbox mode, pinned with a selector, waits for
     * the commit of the connection it selects.
     *
     * @return void
     */
    public function testOutboxModeNormalisesASelector(): void
    {
        $this->outboxModeOn();

        DB::connection(self::OTHER)->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, self::OTHER . '::write');

        self::assertSame(0, $this->outboxCount());

        DB::connection(self::OTHER)->commit();

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * A failed outbox insert follows the same rule: a fail-closed record
     * throws, naming the outbox as the step that failed.
     *
     * @return void
     */
    public function testAFailedOutboxInsertOfAFailClosedRecordThrows(): void
    {
        $this->outboxModeOn();
        $this->pointOutboxAtProbeTable();

        $this->beforeApplicationDestroyed(fn () => $this->removeOutboxProbeTable());

        try {
            $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null, true);

            self::fail('Expected the insert to fail.');
        } catch (AuditWriteFailedException $caught) {
            self::assertSame(FailedOperation::OUTBOX->value, $caught->operation);
        }

        $this->assertSpilled(1);
    }

    /**
     * A record made inside a store is refused: nothing further is stored, the
     * refusal is reported naming its code, and the captured record comes back.
     *
     * @return void
     */
    public function testARecordInsideAStoreIsRefusedReportedAndReturned(): void
    {
        $reporter = $this->reporter();
        $inner    = null;
        $calls    = 0;

        app()->instance(AuditStore::class, new CallbackStore(static function () use (&$inner, &$calls): void {
            $calls++;
            $inner = AuditLog::record(self::INNER_CODE);
        }));

        AuditLog::record(self::CODE);

        self::assertSame(1, $calls);
        self::assertInstanceOf(AuditRecord::class, $inner);
        self::assertSame(self::INNER_CODE, $inner->event);
        self::assertCount(1, $reporter->reports());
        self::assertInstanceOf(\LogicException::class, $reporter->reports()[0]);
        self::assertStringContainsString(self::INNER_CODE, $reporter->reports()[0]->getMessage());
        $this->assertSpilled(0);
    }

    /**
     * A record made by a listener of a failed write is refused and reported,
     * alongside the failure it heard of.
     *
     * @return void
     */
    public function testARecordInsideAnAuditWriteFailedListenerIsRefusedAndReported(): void
    {
        $reporter = $this->reporter();
        $fake     = FakeAuditStore::failing(new \RuntimeException('The store is down.'));
        $inner    = null;

        Event::listen(AuditWriteFailed::class, static function () use (&$inner): void {
            $inner = AuditLog::record(self::INNER_CODE);
        });

        AuditLog::record(self::CODE);

        self::assertSame(self::INNER_CODE, $inner?->event);
        self::assertSame(0, $fake->count());
        self::assertCount(2, $reporter->reports());
        self::assertInstanceOf(AuditWriteFailedException::class, $reporter->reports()[0]);
        self::assertSame(\LogicException::class, $reporter->reports()[1]::class);
    }

    /**
     * A reporter that records is refused, and its refusal is reported once, so
     * a reporter recording every report does not recurse.
     *
     * @return void
     */
    public function testAReporterRecordingIsRefusedWithoutRecursing(): void
    {
        $reports = 0;
        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report')->andReturnUsing(static function () use (&$reports): void {
            $reports++;

            AuditLog::record(self::INNER_CODE);
        });

        app()->instance(ExceptionHandler::class, $handler);

        $fake = FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        AuditLog::record(self::CODE);

        self::assertSame(2, $reports);
        self::assertSame(0, $fake->count());
    }

    /**
     * A record made while the spill line is written is refused.
     *
     * @return void
     */
    public function testASpillChannelRecordingIsRefused(): void
    {
        $reporter = $this->reporter();
        $inner    = null;

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $this->onLogLine(static function (MessageLogged $logged) use (&$inner): void {
            if (!str_starts_with($logged->message, FailureSpill::MARKER)) {
                return;
            }

            $inner = AuditLog::record(self::INNER_CODE);
        });

        AuditLog::record(self::CODE);

        self::assertSame(self::INNER_CODE, $inner?->event);
        $this->assertSpilled(1);
        self::assertSame(\LogicException::class, $reporter->reports()[0]::class);
    }

    /**
     * A record made while the outbox row is inserted is refused, and only the
     * outer record gets a row.
     *
     * @return void
     */
    public function testARecordInsideAnOutboxInsertIsRefused(): void
    {
        $this->outboxModeOn();

        $reporter = $this->reporter();
        $inner    = null;

        $this->outboxConnection()->beforeExecuting(static function (string $query) use (&$inner): void {
            if (!str_starts_with($query, 'insert') || !str_contains($query, DeliveryTables::outboxTable())) {
                return;
            }

            $inner = AuditLog::record(self::INNER_CODE);
        });

        AuditLog::record(self::CODE);

        self::assertSame(self::INNER_CODE, $inner?->event);
        self::assertSame(1, $this->outboxCount());
        self::assertCount(1, $reporter->reports());
        self::assertSame(\LogicException::class, $reporter->reports()[0]::class);
    }

    /**
     * A record made by the store a drain delivers to is refused, in outbox mode
     * as in sync mode, and the row is still delivered.
     *
     * @return void
     */
    public function testARecordInsideADrainDestinationIsRefused(): void
    {
        $reporter = $this->reporter();
        $inner    = null;

        app()->instance(AuditStore::class, new CallbackStore(static function () use (&$inner): void {
            $inner = AuditLog::record(self::INNER_CODE);
        }));

        $this->enqueue($this->finalisedRecord());

        $this->outboxModeOn();

        app(OutboxDrainer::class)->drain(10, false);

        self::assertSame(self::INNER_CODE, $inner?->event);
        self::assertSame(0, $this->outboxCount());
        self::assertCount(1, $reporter->reports());
        self::assertSame(\LogicException::class, $reporter->reports()[0]::class);
    }

    /**
     * A record made by a listener of a drain's final failure is refused, and no
     * further row is added.
     *
     * @return void
     */
    public function testARecordInsideTheDrainsAuditWriteFailedListenerIsRefused(): void
    {
        $reporter = $this->reporter();
        $inner    = null;

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 1);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        Event::listen(AuditWriteFailed::class, static function () use (&$inner): void {
            $inner = AuditLog::record(self::INNER_CODE);
        });

        $this->enqueue($this->finalisedRecord());

        $this->outboxModeOn();

        app(OutboxDrainer::class)->drain(10, false);

        self::assertSame(self::INNER_CODE, $inner?->event);
        self::assertSame(1, $this->outboxCount());
        self::assertContains(\LogicException::class, array_map(get_debug_type(...), $reporter->reports()));
    }

    /**
     * A fail-closed record made inside a store is refused with an exception:
     * returning unwritten would break its guarantee.
     *
     * @return void
     */
    public function testAFailClosedRecordInsideAStoreThrows(): void
    {
        $thrown = $this->thrownInsideAStore(static function (): void {
            AuditLog::event(self::INNER_CODE)->failClosed()->record();
        });

        self::assertSame(self::STRICT_REFUSAL, $thrown?->getMessage());
    }

    /**
     * A transactional record made inside a store is refused with an exception.
     *
     * @return void
     */
    public function testATransactionalRecordInsideAStoreThrows(): void
    {
        DB::connection(self::CONNECTION)->beginTransaction();

        $thrown = $this->thrownInsideAStore(static function (): void {
            AuditLog::event(self::INNER_CODE)->transactional()->record();
        });

        self::assertSame(self::STRICT_REFUSAL, $thrown?->getMessage());
    }

    /**
     * Rows of `[timing, fail closed]`: the strict records.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Records\Enums\Timing, 1: bool}>
     */
    public static function provideStrictRecords(): iterable
    {
        yield from [
            'fail closed'   => [Timing::IMMEDIATE, true],
            'transactional' => [Timing::TRANSACTIONAL, false],
        ];
    }

    /**
     * A strict record reaching `deliver()` inside the guard with no check first
     * still never returns unwritten.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  bool  $failClosed
     * @return void
     */
    #[DataProvider('provideStrictRecords')]
    public function testAStrictDeliveryInsideTheGuardThrowsWithoutACheck(Timing $timing, bool $failClosed): void
    {
        $fake = FakeAuditStore::fake();

        try {
            app(WriteGuard::class)->during(function () use ($timing, $failClosed): void {
                $this->delivery()->deliver(RecordFactory::captured(), $timing, null, $failClosed);
            });

            self::fail('Expected the strict delivery to be refused.');
        } catch (\LogicException $caught) {
            self::assertSame(self::STRICT_REFUSAL, $caught->getMessage());
        }

        self::assertSame(0, $fake->count());
    }

    /**
     * A strict record checked inside the guard is refused before anything is
     * consumed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  bool  $failClosed
     * @return void
     */
    #[DataProvider('provideStrictRecords')]
    public function testAStrictCheckInsideTheGuardIsRefused(Timing $timing, bool $failClosed): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::STRICT_REFUSAL);

        app(WriteGuard::class)->during(function () use ($timing, $failClosed): void {
            $this->delivery()->check($timing, null, $failClosed);
        });
    }

    /**
     * Many refusals in one window are reported once.
     *
     * @return void
     */
    public function testRepeatedRefusalsReportOnce(): void
    {
        $reporter = $this->reporter();

        app()->instance(AuditStore::class, new CallbackStore(static function (): void {
            AuditLog::record(self::INNER_CODE);
            AuditLog::record(self::INNER_CODE);
            AuditLog::record(self::INNER_CODE);
        }));

        AuditLog::record(self::CODE);

        self::assertCount(1, $reporter->reports());
    }

    /**
     * What a refusal reports names the code and holds no value of the record,
     * in any frame.
     *
     * @return void
     */
    public function testARefusalHoldsNoValueOfTheRecord(): void
    {
        $ignoreArgs = (string) ini_get('zend.exception_ignore_args');

        ini_set('zend.exception_ignore_args', '0');

        try {
            $reporter = $this->reporter();

            app()->instance(AuditStore::class, new CallbackStore(static function (): void {
                AuditLog::event(self::INNER_CODE)->withProperties(['note' => self::INNER_VALUE])->record();
            }));

            AuditLog::record(self::CODE);

            self::assertCount(1, $reporter->reports());
            self::assertFalse(self::holdsText($reporter->reports(), self::INNER_VALUE));
        } finally {
            ini_set('zend.exception_ignore_args', $ignoreArgs);
        }
    }

    /**
     * A reporter that throws while a refusal is reported is contained, and the
     * refused record still comes back.
     *
     * @return void
     */
    public function testABrokenReporterOfARefusalIsContained(): void
    {
        $inner = null;

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler(true));
        app()->instance(AuditStore::class, new CallbackStore(static function () use (&$inner): void {
            $inner = AuditLog::record(self::INNER_CODE);
        }));

        AuditLog::record(self::CODE);

        self::assertSame(self::INNER_CODE, $inner?->event);
        $this->assertSpilled(0);
    }

    /**
     * However the store ends, the guard is released.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideFailureModes')]
    public function testTheGuardIsReleasedAfterTheStoreThrows(string $mode): void
    {
        $this->reporter();
        $this->failureMode($mode);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        try {
            $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);
        } catch (AuditWriteFailedException) {
            // Whether it is thrown is the mode's; the guard is released either
            // way
        }

        self::assertFalse(app(WriteGuard::class)->isActive());
    }

    /**
     * The guard is active while the store runs, and not while the record is
     * finalised, the event is dispatched or a later record is written.
     *
     * @return void
     */
    public function testTheGuardCoversOnlyTheStore(): void
    {
        $guard = app(WriteGuard::class);
        $seen  = [];
        $clock = \Mockery::mock(Clock::class);

        $clock->shouldReceive('now')->once()->andReturnUsing(static function () use ($guard, &$seen): CarbonImmutable {
            $seen['finalise'] = $guard->isActive();

            return CarbonImmutable::parse('2026-11-01 12:00:09.5', 'UTC');
        });

        app()->instance(Clock::class, $clock);
        app()->instance(AuditStore::class, new CallbackStore(static function () use ($guard, &$seen): void {
            $seen['store'] = $guard->isActive();
        }));

        Event::listen(AuditRecorded::class, static function () use ($guard, &$seen): void {
            $seen['notify'] = $guard->isActive();
        });

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertSame(['finalise' => false, 'store' => true, 'notify' => false], $seen);
    }

    /**
     * Once the window has closed a record is written as usual, the refusal
     * forgotten.
     *
     * @return void
     */
    public function testARecordAfterTheWindowIsWritten(): void
    {
        $reporter = $this->reporter();
        $inner    = true;
        $calls    = 0;

        app()->instance(AuditStore::class, new CallbackStore(static function () use (&$inner, &$calls): void {
            $calls++;

            if (!$inner) {
                return;
            }

            $inner = false;

            AuditLog::record(self::INNER_CODE);
        }));

        AuditLog::record(self::CODE);
        AuditLog::record(self::CODE);

        self::assertSame(2, $calls);
        self::assertCount(1, $reporter->reports());
    }

    /**
     * A listener of a written record may record another code, since the store
     * has finished by then.
     *
     * @return void
     */
    public function testAnAuditRecordedListenerMayRecordAnotherCode(): void
    {
        $fake = FakeAuditStore::fake();

        Event::listen(AuditRecorded::class, static function (AuditRecorded $event): void {
            if ($event->code !== self::CODE) {
                return;
            }

            AuditLog::record(self::INNER_CODE);
        });

        AuditLog::record(self::CODE);

        self::assertSame(2, $fake->count());
    }

    /**
     * A capture asked to be fail-closed is refused by the check, before
     * anything is read, and by a delivery made without a check.
     *
     * @return void
     */
    public function testACaptureIsRefusedFailClosed(): void
    {
        $fake = FakeAuditStore::fake();

        $record = RecordFactory::captured();

        $this->assertThrows(fn () => $this->delivery()->check(Timing::IMMEDIATE, null, true, $this->signal()), \LogicException::class, self::STRICT_CAPTURE);
        $this->assertThrows(fn () => $this->delivery()->deliver($record, Timing::IMMEDIATE, null, true, $this->signal()), \LogicException::class, self::STRICT_CAPTURE);

        self::assertSame(0, $fake->count());
        self::assertSame([], $this->signalled);
    }

    /**
     * A transactional capture is refused before the existing checks, naming the
     * capture, even by a delivery made without a check.
     *
     * @return void
     */
    public function testACaptureIsRefusedTransactional(): void
    {
        $fake = FakeAuditStore::fake();

        $this->assertThrows(fn () => $this->delivery()->check(Timing::TRANSACTIONAL, null, false, $this->signal()), \LogicException::class, self::STRICT_CAPTURE);

        DB::connection(self::CONNECTION)->beginTransaction();

        $record = RecordFactory::captured();

        $this->assertThrows(fn () => $this->delivery()->deliver($record, Timing::TRANSACTIONAL, null, false, $this->signal()), \LogicException::class, self::STRICT_CAPTURE);

        self::assertSame(0, $fake->count());
    }

    /**
     * A capture inside the write guard asked to be strict is refused as a
     * capture first, whatever the guard would say.
     *
     * @return void
     */
    public function testAStrictCaptureInsideTheGuardIsRefusedAsACapture(): void
    {
        $thrown = null;

        app(WriteGuard::class)->during(function () use (&$thrown): void {
            try {
                $this->delivery()->check(Timing::IMMEDIATE, null, true, $this->signal());
            } catch (\LogicException $exception) {
                $thrown = $exception;
            }
        });

        self::assertInstanceOf(\LogicException::class, $thrown);
        self::assertSame(self::STRICT_CAPTURE, $thrown->getMessage());
    }

    /**
     * Under the `throw` mode a capture still follows the `REPORT` rule: its
     * failed write returns, spilled once and reported once.
     *
     * @return void
     */
    public function testACaptureFollowsTheReportRuleUnderTheThrowMode(): void
    {
        $reporter = $this->reporter();

        $this->failureMode('throw');

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $signal = $this->signal();

        $this->delivery()->check(Timing::IMMEDIATE, null, false, $signal);
        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null, false, $signal);

        self::assertSame(\RuntimeException::class, self::reportOf($reporter)->exceptionClass);
        self::assertCount(1, $reporter->reports());
        $this->assertSpilled(1);
        self::assertTrue($signal->hasFailed());
    }

    /**
     * A capture's failed write is signalled once, with the failure's class,
     * after it is said once.
     *
     * @return void
     */
    public function testACapturesWriteFailureIsSignalledOnce(): void
    {
        $this->reporter();

        $failures = [];

        Event::listen(AuditWriteFailed::class, static function (AuditWriteFailed $event) use (&$failures): void {
            $failures[] = $event;
        });

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $signal = $this->signal();
        $record = RecordFactory::captured();

        $this->delivery()->deliver($record, Timing::IMMEDIATE, null, false, $signal);

        self::assertCount(1, $failures);
        self::assertSame($record->id, $failures[0]->id);
        self::assertSame([\RuntimeException::class], $this->signalled);
        self::assertFalse($signal->isFatal());
        self::assertFalse($signal->isDeferred());
    }

    /**
     * A capture that is written signals nothing, and is said as any record is.
     *
     * @return void
     */
    public function testACapturesWriteSuccessSignalsNothing(): void
    {
        $fake   = FakeAuditStore::fake();
        $heard  = 0;
        $signal = $this->signal();

        Event::listen(AuditRecorded::class, static function () use (&$heard): void {
            $heard++;
        });

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null, false, $signal);

        self::assertSame(1, $fake->count());
        self::assertSame(1, $heard);
        self::assertFalse($signal->hasFailed());
        self::assertSame([], $this->signalled);
    }

    /**
     * A deferred capture's signal is marked deferred when its write is queued
     * for the commit, before the write runs.
     *
     * @return void
     */
    public function testADeferredCaptureIsMarkedBeforeItIsQueued(): void
    {
        $fake       = FakeAuditStore::fake();
        $connection = DB::connection(self::CONNECTION);
        $signal     = $this->signal();
        $seen       = null;

        $connection->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null, false, $signal);

        self::assertTrue($signal->isDeferred());
        self::assertSame(0, $fake->count());

        Event::listen(AuditRecorded::class, static function () use ($signal, &$seen): void {
            $seen = $signal->isDeferred();
        });

        $connection->commit();

        self::assertSame(1, $fake->count());
        self::assertTrue($seen);
        self::assertFalse($signal->hasFailed());
    }

    /**
     * An after-commit capture with no transaction open is written now, so its
     * signal is never marked deferred.
     *
     * @return void
     */
    public function testAnAfterCommitCaptureWithNothingOpenIsNotDeferred(): void
    {
        $fake   = FakeAuditStore::fake();
        $signal = $this->signal();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null, false, $signal);

        self::assertSame(1, $fake->count());
        self::assertFalse($signal->isDeferred());
    }

    /**
     * A deferred capture's failure reaches its signal when the commit runs the
     * write, not before, and the commit stands.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeferredCapturesFailureIsSignalledAtCommit(): void
    {
        $reporter   = $this->reporter();
        $connection = DB::connection(self::CONNECTION);
        $signal     = $this->signal();

        $this->failureMode('throw');

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $connection->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null, false, $signal);

        self::assertFalse($signal->hasFailed());

        $connection->commit();

        self::assertSame(0, $connection->transactionLevel());
        self::assertSame([\RuntimeException::class], $this->signalled);
        self::assertFalse($signal->isFatal());
        self::assertCount(1, $reporter->reports());
        $this->assertSpilled(1);
    }

    /**
     * A deferred capture whose transaction rolls back is never written, and
     * signals and reports nothing.
     *
     * @return void
     */
    public function testARolledBackCaptureSignalsNothing(): void
    {
        $reporter   = $this->reporter();
        $connection = DB::connection(self::CONNECTION);
        $signal     = $this->signal();

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $connection->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null, false, $signal);

        $connection->rollBack();

        self::assertFalse($signal->hasFailed());
        self::assertSame([], $reporter->reports());
        $this->assertSpilled(0);
    }

    /**
     * A bundle to a store keeping no attachments is refused inside the attempt,
     * so it follows the rule and the store is handed nothing.
     *
     * @return void
     */
    public function testADeliveredBundleToAStoreKeepingNoAttachmentsFollowsTheRule(): void
    {
        $reporter = $this->reporter();
        $store    = new PlainStore;
        $failures = 0;

        app()->instance(AuditStore::class, $store);

        Event::listen(AuditWriteFailed::class, static function () use (&$failures): void {
            $failures++;
        });

        $this->delivery()->deliver(RecordFactory::bundled(), Timing::IMMEDIATE, null);

        $report = self::reportOf($reporter);

        self::assertSame(0, $store->calls());
        self::assertCount(1, $reporter->reports());
        self::assertSame(\LogicException::class, $report->exceptionClass);
        self::assertSame(FailedOperation::STORE->value, $report->operation);
        self::assertSame(PlainStore::class, $report->store);
        self::assertSame(1, $failures);
        $this->assertSpilled(1);
    }

    /**
     * Under the `throw` mode the refused bundle is thrown, sanitised, as any
     * failed write is.
     *
     * @return void
     */
    public function testARefusedBundleIsThrownUnderTheThrowMode(): void
    {
        $this->failureMode('throw');

        app()->instance(AuditStore::class, new PlainStore);

        try {
            $this->delivery()->deliver(RecordFactory::bundled(), Timing::IMMEDIATE, null);

            self::fail('Expected the bundle to be refused.');
        } catch (AuditWriteFailedException $caught) {
            self::assertSame(\LogicException::class, $caught->exceptionClass);
            self::assertNull($caught->getPrevious());
        }
    }

    /**
     * A bundle reaches a store that keeps attachments, with its attachment, and
     * a record without one reaches a store that keeps none.
     *
     * @return void
     */
    public function testABundleReachesAStoreThatKeepsAttachments(): void
    {
        $store  = $this->storeKeepingAttachments();
        $plain  = new PlainStore;
        $record = RecordFactory::bundled();

        app()->instance(AuditStore::class, $store);

        $this->delivery()->deliver($record, Timing::IMMEDIATE, null);

        app()->instance(AuditStore::class, $plain);

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

        self::assertCount(1, $store->received);
        self::assertSame($record->attachment, $store->received[0]->record->attachment);
        self::assertSame(1, $plain->calls());
    }

    /**
     * A capture never reads the failure mode, so a malformed one stops nothing
     * and its failure follows `REPORT`; without a signal it is refused.
     *
     * @return void
     */
    public function testACaptureIgnoresAMalformedFailureMode(): void
    {
        $reporter = $this->reporter();
        $fake     = FakeAuditStore::fake();

        $this->failureMode('nonsense');

        $this->delivery()->check(Timing::IMMEDIATE, null, false, $this->signal());
        $this->delivery()->check(Timing::AFTER_COMMIT, null, false, $this->signal());
        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null, false, $this->signal());

        self::assertSame(1, $fake->count());

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null, false, $this->signal());

        self::assertCount(1, $reporter->reports());
        self::assertSame([\RuntimeException::class], $this->signalled);

        $this->assertThrows(fn () => $this->delivery()->check(Timing::IMMEDIATE, null), \InvalidArgumentException::class, '`audit-log.failure.mode`');
        $this->assertThrows(fn () => $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null), \InvalidArgumentException::class, '`audit-log.failure.mode`');
    }

    /**
     * A capture's check asks nothing of the store, since a capture is never
     * strict.
     *
     * @return void
     */
    public function testACaptureAsksNothingOfTheStore(): void
    {
        app()->bind(AuditStore::class, static function (): never {
            throw new \RuntimeException('The store must not be resolved by a check.');
        });

        $this->delivery()->check(Timing::IMMEDIATE, null, false, $this->signal());
        $this->delivery()->check(Timing::AFTER_COMMIT, self::CONNECTION, false, $this->signal());

        $this->addToAssertionCount(1);
    }

    /**
     * A listener's deadlock in a deferred capture's commit callback is reported
     * once by class and signalled, and the commit succeeds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeferredCaptureNeverThrowsFromTheCommit(): void
    {
        $reporter   = $this->reporter();
        $fake       = FakeAuditStore::fake();
        $connection = DB::connection(self::CONNECTION);
        $signal     = $this->signal();

        $this->listenerThrows(new \RuntimeException(self::DEADLOCK . ': ' . self::SECRET));

        DB::connection(self::OTHER)->beginTransaction();

        $connection->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, self::CONNECTION, false, $signal);

        $connection->commit();

        $report = self::reportOf($reporter);

        self::assertSame(0, $connection->transactionLevel());
        self::assertSame(1, $fake->count());
        self::assertCount(1, $reporter->reports());
        self::assertSame(DeadlockException::class, $report->exceptionClass);
        self::assertNull($report->getPrevious());
        self::assertSame([DeadlockException::class], $this->signalled);
        self::assertFalse($signal->isFatal());
        self::assertHoldsNoSecret($report, 'the report');
    }

    /**
     * The same escape from an ordinary record's deferred write still reaches
     * the code that commits, as it always has: only a capture contains it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeferredOrdinaryRecordsEscapeStillReachesTheCommit(): void
    {
        $this->reporter();

        FakeAuditStore::fake();

        $connection = DB::connection(self::CONNECTION);

        $this->listenerThrows(new \RuntimeException(self::DEADLOCK));

        DB::connection(self::OTHER)->beginTransaction();

        $connection->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, self::CONNECTION);

        $this->expectException(DeadlockException::class);

        $connection->commit();
    }

    /**
     * A synchronous capture's listener deadlock inside a host transaction
     * propagates sanitised for the capture to judge.
     *
     * @return void
     */
    public function testASynchronousCapturesEscapeIsNotContained(): void
    {
        FakeAuditStore::fake();

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->listenerThrows(new \RuntimeException(self::DEADLOCK));

        $this->expectException(DeadlockException::class);

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null, false, $this->signal());
    }

    /**
     * A deferred capture's write failure is signalled once, by the failure
     * path, and the containment adds no second report or signal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeferredCapturesWriteFailureIsReportedOnce(): void
    {
        $reporter   = $this->reporter();
        $connection = DB::connection(self::CONNECTION);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $connection->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null, false, $this->signal());

        $connection->commit();

        self::assertCount(1, $reporter->reports());
        self::assertSame([\RuntimeException::class], $this->signalled);
    }

    /**
     * In outbox mode a capture carries its signal to the writer: a failed
     * insert under the `throw` mode returns, reported and signalled.
     *
     * @return void
     */
    public function testACaptureInOutboxModeCarriesItsSignal(): void
    {
        $reporter = $this->reporter();

        $this->failureMode('throw');
        $this->outboxModeOn();
        $this->pointOutboxAtProbeTable();

        $this->beforeApplicationDestroyed(fn () => $this->removeOutboxProbeTable());

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null, false, $this->signal());

        self::assertSame(FailedOperation::OUTBOX->value, self::reportOf($reporter)->operation);
        self::assertSame([QueryException::class], $this->signalled);
        $this->assertSpilled(1);
    }

    /**
     * A record delivered without a signal keeps every rule: `throw` throws,
     * fail-closed is accepted, transactional needs its transaction.
     *
     * @return void
     */
    public function testAnOrdinaryRecordIgnoresTheSignalPath(): void
    {
        $this->failureMode('throw');

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $this->assertThrows(fn () => $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null), AuditWriteFailedException::class);

        app()->instance(AuditStore::class, CallbackStore::saying(true, [self::CONNECTION]));

        $this->delivery()->check(Timing::IMMEDIATE, null, true);

        $this->assertThrows(
            fn () => $this->delivery()->check(Timing::TRANSACTIONAL, null),
            \LogicException::class,
            'A transactional record needs a transaction open on the storage connection',
        );
    }

    /**
     * A package write is handed the finalised record the store was given, the
     * very one, once the store has it.
     *
     * @return void
     */
    public function testAPackageWriteIsGivenItsFinalisedRecord(): void
    {
        $fake   = FakeAuditStore::fake();
        $record = RecordFactory::captured();

        $this->delivery()->deliver($record, Timing::IMMEDIATE, null, true, null, $this->packageWrite());

        self::assertCount(1, $this->acknowledged);
        self::assertSame($fake->finalised(), $this->acknowledged);
        self::assertSame($record, $this->acknowledged[0]->record);
    }

    /**
     * The acknowledgement follows the store's write, outside the write guard's
     * window, and precedes the notification.
     *
     * @return void
     */
    public function testAPackageWriteIsAcknowledgedBeforeItsNotification(): void
    {
        $fake = FakeAuditStore::fake();

        Event::listen(AuditRecorded::class, function (): void {
            $this->seen[] = 'notified';
        });

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null, true, null, $this->packageWrite(static fn (): string => sprintf(
            'acknowledged, %d stored, %s',
            $fake->count(),
            app(WriteGuard::class)->isActive() ? 'inside the write guard' : 'outside the write guard',
        )));

        self::assertSame(['acknowledged, 1 stored, outside the write guard', 'notified'], $this->seen);
    }

    /**
     * A package write whose write fails is never acknowledged, and the failure
     * is thrown whatever the failure mode.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideFailureModes')]
    public function testAFailedPackageWriteIsNeverAcknowledged(string $mode): void
    {
        $this->failureMode($mode);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $this->assertThrows(
            fn () => $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null, true, null, $this->packageWrite()),
            AuditWriteFailedException::class,
        );

        self::assertSame([], $this->acknowledged);
        $this->assertSpilled(1);
    }

    /**
     * A package write whose finalising fails is never acknowledged either.
     *
     * @return void
     */
    public function testAPackageWriteWhoseFinalisingFailsIsNeverAcknowledged(): void
    {
        $fake  = FakeAuditStore::fake();
        $clock = \Mockery::mock(Clock::class);

        $clock->shouldReceive('now')->andThrow(new \RuntimeException('The clock stopped.'));

        app()->instance(Clock::class, $clock);

        $this->assertThrows(
            fn () => $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null, true, null, $this->packageWrite()),
            AuditWriteFailedException::class,
        );

        self::assertSame(0, $fake->count());
        self::assertSame([], $this->acknowledged);
    }

    /**
     * Rows of `[timing, fail-closed, with a capture's signal]`: every package
     * write delivery other than immediate and fail-closed.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Records\Enums\Timing, 1: bool, 2: bool}>
     */
    public static function provideLooseTimings(): iterable
    {
        yield from [
            'after commit'               => [Timing::AFTER_COMMIT, false, false],
            'immediate, not fail-closed' => [Timing::IMMEDIATE, false, false],
            'transactional, fail-closed' => [Timing::TRANSACTIONAL, true, false],
            'transactional'              => [Timing::TRANSACTIONAL, false, false],
            'immediate, as a capture'    => [Timing::IMMEDIATE, false, true],
        ];
    }

    /**
     * A package write asked to be delivered any other way is refused before
     * anything is written or acknowledged.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  bool  $failClosed
     * @param  bool  $captured
     * @return void
     */
    #[DataProvider('provideLooseTimings')]
    public function testAPackageWriteIsRefusedAnyOtherTiming(Timing $timing, bool $failClosed, bool $captured): void
    {
        $fake = FakeAuditStore::fake();

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->assertThrows(
            fn () => $this->delivery()->deliver(RecordFactory::captured(), $timing, null, $failClosed, $captured ? $this->signal() : null, $this->packageWrite()),
            \LogicException::class,
            self::LOOSE_PACKAGE_WRITE,
        );

        DB::connection(self::CONNECTION)->commit();

        self::assertSame(0, $fake->count());
        self::assertSame([], $this->acknowledged);
        self::assertSame([], $this->signalled);
    }

    /**
     * In outbox mode a package write is handed the row's envelope once the
     * insert returns; no store is called and nothing is notified.
     *
     * @return void
     */
    public function testInOutboxModeAPackageWriteIsAcknowledgedByTheInsert(): void
    {
        $this->outboxModeOn();

        $store  = new PlainStore;
        $record = RecordFactory::captured();

        app()->instance(AuditStore::class, $store);

        Event::fake([AuditRecorded::class]);

        $note = fn (): string => sprintf('acknowledged, %d in the outbox', $this->outboxCount());

        $this->delivery()->deliver($record, Timing::IMMEDIATE, null, true, null, $this->packageWrite($note));

        self::assertSame(['acknowledged, 1 in the outbox'], $this->seen);
        self::assertCount(1, $this->acknowledged);
        self::assertSame($record, $this->acknowledged[0]->record);
        self::assertSame(0, $store->calls());

        Event::assertNotDispatched(AuditRecorded::class);
    }

    /**
     * A record delivered without a package write is never acknowledged, so the
     * acknowledgement belongs only to the write that asked for it.
     *
     * @return void
     */
    public function testARecordWithoutAPackageWriteIsNotAcknowledged(): void
    {
        FakeAuditStore::fake();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null, true);

        self::assertSame([], $this->acknowledged);
    }

    /**
     * Add the second connection, on its own in-memory SQLite database.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        app(ConfigRepository::class)->set('database.connections.' . self::OTHER, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        app(ConfigRepository::class)->set('logging.default', 'null');
    }

    /**
     * A delivery as the recorder makes one, from the current container.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\RecordDelivery
     */
    private function delivery(): RecordDelivery
    {
        return app(RecordDelivery::class);
    }

    /**
     * A package write that accepts every record, and keeps each finalised
     * record it is handed, saying what the note gives when one is given.
     *
     * @param  ?\Closure(): string  $note
     * @return \SineMacula\Laravel\AuditLog\Delivery\PackageWrite
     */
    private function packageWrite(?\Closure $note = null): PackageWrite
    {
        return new PackageWrite(
            static function (): void {},
            function (FinalisedRecord $finalised) use ($note): void {
                $this->acknowledged[] = $finalised;

                if ($note === null) {
                    return;
                }

                $this->seen[] = $note();
            },
        );
    }

    /**
     * A capture's signal that keeps the class it passes on.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\CaptureSignal
     */
    private function signal(): CaptureSignal
    {
        return new CaptureSignal(function (string $exceptionClass): void {
            $this->signalled[] = $exceptionClass;
        });
    }

    /**
     * A store that says it keeps attachments, and keeps every record it is
     * handed.
     *
     * @return object{received: list<\SineMacula\Laravel\AuditLog\Records\FinalisedRecord>}&\SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments
     */
    private function storeKeepingAttachments(): AcceptsAttachments
    {
        return new class implements AcceptsAttachments {
            /** @var list<\SineMacula\Laravel\AuditLog\Records\FinalisedRecord> The records received, oldest first. */
            public array $received = [];

            /**
             * Keep the record.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
             * @return void
             */
            #[\Override]
            public function store(#[\SensitiveParameter] FinalisedRecord $record): void
            {
                $this->received[] = $record;
            }

            /**
             * Keep every attachment.
             *
             * @return bool
             */
            #[\Override]
            public function acceptsAttachments(): bool
            {
                return true;
            }
        };
    }

    /**
     * Assert how many spill lines were logged.
     *
     * @param  int  $count
     * @return void
     */
    private function assertSpilled(int $count): void
    {
        self::assertCount($count, $this->spillLines());
    }

    /**
     * Set what a failed write does.
     *
     * @param  string  $mode
     * @return void
     */
    private function failureMode(string $mode): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', $mode);
    }

    /**
     * Point the storage connection at one of its own, on an in-memory SQLite
     * database whatever the engine under test.
     *
     * @return void
     */
    private function storeOnADedicatedConnection(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::DEDICATED, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('audit-log.storage.connection', self::DEDICATED);
    }

    /**
     * Bind a reporter that keeps what it is asked to report, and return it.
     *
     * @return \Tests\Fixtures\Privacy\RecordingExceptionHandler
     */
    private function reporter(): RecordingExceptionHandler
    {
        $reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $reporter);

        return $reporter;
    }

    /**
     * The last sanitised failure the reporter was given.
     *
     * @param  \Tests\Fixtures\Privacy\RecordingExceptionHandler  $reporter
     * @return \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private static function reportOf(RecordingExceptionHandler $reporter): AuditWriteFailedException
    {
        $reports = $reporter->reports();
        $report  = $reports[array_key_last($reports)] ?? null;

        self::assertInstanceOf(AuditWriteFailedException::class, $report);

        return $report;
    }

    /**
     * Record the code through a store that runs the work inside its write, and
     * return what the work threw there.
     *
     * @param  \Closure(): void  $work
     * @return ?\LogicException
     */
    private function thrownInsideAStore(\Closure $work): ?\LogicException
    {
        $thrown = null;

        app()->instance(AuditStore::class, new CallbackStore(static function () use ($work, &$thrown): void {
            try {
                $work();
            } catch (\LogicException $exception) {
                $thrown = $exception;
            }
        }, true, [self::CONNECTION]));

        AuditLog::event(self::CODE)->immediately()->record();

        return $thrown;
    }

    /**
     * Make every `AuditRecorded` listener throw the exception.
     *
     * @param  \Throwable  $exception
     * @return void
     */
    private function listenerThrows(\Throwable $exception): void
    {
        Event::listen(AuditRecorded::class, static function () use ($exception): void {
            throw $exception;
        });
    }
}
