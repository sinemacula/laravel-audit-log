<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Feature tests for how one captured record is delivered: when each timing
 * writes it, what each refuses before anything is consumed, that the finaliser
 * and the store are resolved when the write happens, and that the notification
 * sits outside the write.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordDelivery::class)]
final class RecordDeliveryTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string A second connection, on an in-memory SQLite database whatever the engine under test. */
    private const string OTHER = 'other';

    /**
     * Roll back any transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ([self::CONNECTION, self::OTHER] as $name) {

            $connection = DB::connection($name);

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
     * A container with no transactions manager has nothing to wait for, so an
     * after-commit record is written at once; and everything the write needs
     * comes from the delivery's own container, never another.
     *
     * @return void
     */
    public function testAContainerWithoutATransactionsManagerWritesNow(): void
    {
        DB::connection(self::CONNECTION)->beginTransaction();

        $container = new Container;

        $container->instance(RecordFinaliser::class, app(RecordFinaliser::class));
        $container->instance(Dispatcher::class, app(Dispatcher::class));

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
     * A failed write reaches the caller, as the exception it was, and no event
     * says the store accepted the record.
     *
     * @return void
     */
    public function testAFailedWritePropagatesAndNotifiesNothing(): void
    {
        $exception = new \RuntimeException('The store is down.');

        Event::fake([AuditRecorded::class]);
        FakeAuditStore::failing($exception);

        try {
            $this->delivery()->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null);

            self::fail('Expected the write to fail.');
        } catch (\RuntimeException $caught) {
            self::assertSame($exception, $caught);
        }

        Event::assertNotDispatched(AuditRecorded::class);
    }

    /**
     * A deferred write's failure reaches the code that commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeferredWritesFailureReachesTheCommit(): void
    {
        $exception  = new \RuntimeException('The store is down.');
        $connection = DB::connection(self::CONNECTION);

        Event::fake([AuditRecorded::class]);
        FakeAuditStore::failing($exception);

        $connection->beginTransaction();

        $this->delivery()->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null);

        try {
            $connection->commit();

            self::fail('Expected the write to fail.');
        } catch (\RuntimeException $caught) {
            self::assertSame($exception, $caught);
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
     * A storage connection that is not a database connection has no transaction
     * levels the package trusts, so a transactional record is refused even if
     * it reports one.
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
