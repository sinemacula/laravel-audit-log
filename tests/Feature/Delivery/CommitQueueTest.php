<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Illuminate\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager as TestingManager;
use Illuminate\Support\Facades\DB;
use Monolog\Handler\NullHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Delivery\CommitFlush;
use SineMacula\Laravel\AuditLog\Delivery\CommitQueue;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Feature tests for what waits on a transaction's commit: one flush per
 * outermost transaction, nested work joining it only when its own transaction
 * commits, one record's failure costing no other, and an application callback
 * registered after the first audit use unable to stop any of it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CommitQueue::class)]
#[CoversClass(CommitFlush::class)]
final class CommitQueueTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore, InteractsWithOutbox, SeedsTheOutbox;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string The spill channel, which writes nowhere; the lines are captured as they are logged. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var list<string> What ran, in order. */
    private array $ran = [];

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /**
     * Bind a reporter that keeps what it is given, spill to a channel that
     * writes nowhere and capture its lines.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $this->reporter);
        config()->set('logging.channels.' . self::SPILL_CHANNEL, ['driver' => 'monolog', 'handler' => NullHandler::class]);
        config()->set('audit-log.failure.log_channel', self::SPILL_CHANNEL);

        $this->captureLogLines();
    }

    /**
     * Roll back any transaction a failed test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        while (DB::transactionLevel() > 0) {
            DB::rollBack();
        }

        parent::tearDown();
    }

    /**
     * The queue is scoped, so it holds nothing from one request or job to the
     * next, and is listened to for each outermost commit.
     *
     * @return void
     */
    public function testTheProviderScopesItAndListensForACommit(): void
    {
        $queue = app(CommitQueue::class);

        self::assertSame($queue, app(CommitQueue::class));

        app()->forgetScopedInstances();

        self::assertNotSame($queue, app(CommitQueue::class));
    }

    /**
     * All the work on one transaction is one commit callback, so nothing can
     * run between the pieces.
     *
     * @return void
     */
    public function testATransactionGetsOneCommitCallback(): void
    {
        $transaction = $this->begin();

        $this->queue()->defer($transaction, $this->noting('first'));
        $this->queue()->defer($transaction, $this->noting('second'));

        self::assertCount(1, $transaction->getCallbacks());

        DB::commit();

        self::assertSame(['first', 'second'], $this->ran);
    }

    /**
     * Nothing runs when the transaction rolls back.
     *
     * @return void
     */
    public function testARollbackDropsTheWork(): void
    {
        $this->queue()->defer($this->begin(), $this->noting('dropped'));

        DB::rollBack();

        self::assertSame([], $this->ran);
    }

    /**
     * A nested transaction's work waits for the outermost commit.
     *
     * @return void
     */
    public function testNestedWorkWaitsForTheOutermostCommit(): void
    {
        $this->begin();

        $this->queue()->defer($this->begin(), $this->noting('nested'));

        DB::commit();

        self::assertSame([], $this->ran);

        DB::commit();

        self::assertSame(['nested'], $this->ran);
    }

    /**
     * A nested rollback drops that transaction's work and no other, though the
     * flush that would have run it is the outermost's.
     *
     * @return void
     */
    public function testANestedRollbackDropsOnlyItsOwnWork(): void
    {
        $outer = $this->begin();

        $this->queue()->defer($outer, $this->noting('outer'));
        $this->queue()->defer($this->begin(), $this->noting('dropped'));

        DB::rollBack();

        $this->queue()->defer($this->begin(), $this->noting('kept'));

        DB::commit();
        DB::commit();

        self::assertSame(['outer', 'kept'], $this->ran);
    }

    /**
     * A failure in a nested transaction's work costs the outer's nothing,
     * though each would otherwise be a callback of its own in a plain loop.
     *
     * @return void
     */
    public function testAFailureInNestedWorkStopsNoOuterWork(): void
    {
        $outer = $this->begin();

        $this->queue()->defer($outer, $this->noting('outer'));
        $this->queue()->defer($this->begin(), static function (): never {
            throw new \RuntimeException('Nested.');
        });

        DB::commit();

        $this->assertThrows(static fn () => DB::commit(), \RuntimeException::class, 'Nested.');

        self::assertSame(['outer'], $this->ran);
    }

    /**
     * Holding the flush's place puts deferred work ahead of an application
     * callback registered after it, whatever that callback does.
     *
     * @return void
     */
    public function testAReservedPlaceRunsAheadOfALaterCallback(): void
    {
        $transaction = $this->begin();

        $this->queue()->reserve($transaction);

        DB::afterCommit(static function (): never {
            throw new \DomainException('The application failed.');
        });

        $this->queue()->defer($transaction, $this->noting('audit'));

        $this->assertThrows(static fn () => DB::commit(), \DomainException::class);

        self::assertSame(['audit'], $this->ran);
    }

    /**
     * A transaction the testing manager wraps a test in is never the outermost,
     * so a nested transaction's work runs when it would under that manager.
     *
     * @return void
     */
    public function testATestWrapperIsNotTheOutermost(): void
    {
        $connection = DB::connection(self::CONNECTION);
        $manager    = new TestingManager([self::CONNECTION]);

        app()->instance('db.transactions', $manager);
        $connection->setTransactionManager($manager);

        $connection->beginTransaction();

        $this->queue()->defer($this->begin(), $this->noting('work'));

        DB::commit();

        self::assertSame(['work'], $this->ran);

        $connection->rollBack();
    }

    /**
     * Two records under `throw` in one transaction: the first failure costs the
     * second nothing, both are spilled and attempted, and only the first leaves
     * the commit, with the second reported instead of lost.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoRecordsUnderThrowAreBothAttempted(): void
    {
        config()->set('audit-log.failure.mode', 'throw');

        $calls = 0;

        app()->instance(AuditStore::class, new CallbackStore(static function () use (&$calls): never {
            $calls++;

            throw new \DomainException('The store is down.');
        }));

        DB::beginTransaction();

        $first  = AuditLog::event(self::CODE)->record();
        $second = AuditLog::event(self::CODE)->record();

        try {
            DB::commit();

            self::fail('Expected the first failure to leave the commit.');
        } catch (AuditWriteFailedException $thrown) {
            self::assertSame($first->id, $thrown->recordId);
        }

        self::assertSame(2, $calls);
        self::assertCount(2, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
        self::assertInstanceOf(AuditWriteFailedException::class, $this->reporter->reports()[0]);
        self::assertSame($second->id, $this->reporter->reports()[0]->recordId);
    }

    /**
     * An application callback that throws between two records stops neither,
     * since both wait in the flush placed at the first.
     *
     * @return void
     */
    public function testAThrowingCallbackBetweenTwoRecordsStopsNeither(): void
    {
        $stored = [];

        app()->instance(AuditStore::class, new CallbackStore(static function () use (&$stored): void {
            $stored[] = true;
        }));

        DB::beginTransaction();

        AuditLog::event(self::CODE)->record();

        DB::afterCommit(static function (): never {
            throw new \DomainException('The application failed.');
        });

        AuditLog::event(self::CODE)->record();

        $this->assertThrows(static fn () => DB::commit(), \DomainException::class);

        self::assertCount(2, $stored);
    }

    /**
     * In outbox mode the same holds of a bound spill: a failed insert, a
     * throwing application callback, then another failed insert leaves both
     * spills, not just the first.
     *
     * @return void
     */
    public function testAThrowingCallbackStopsNoBoundSpill(): void
    {
        $this->outboxModeOn();

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query): void {
            if (str_starts_with($query, 'insert') && str_contains($query, 'outbox')) {
                throw new \DomainException('The outbox is down.');
            }
        });

        DB::beginTransaction();

        AuditLog::event(self::CODE)->record();

        DB::afterCommit(static function (): never {
            throw new \LogicException('The application failed.');
        });

        AuditLog::event(self::CODE)->record();

        self::assertSame([], $this->spillLines());

        $this->assertThrows(static fn () => DB::commit(), \LogicException::class);

        self::assertCount(2, $this->spillLines());
    }

    /**
     * Holding a place in a transaction whose insert succeeded also protects a
     * later record's failed insert from an application callback in between.
     *
     * @return void
     */
    public function testASuccessfulInsertHoldsThePlaceForALaterSpill(): void
    {
        $this->outboxModeOn();

        DB::beginTransaction();

        AuditLog::event(self::CODE)->record();

        DB::afterCommit(static function (): never {
            throw new \LogicException('The application failed.');
        });

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query): void {
            if (str_starts_with($query, 'insert') && str_contains($query, 'outbox')) {
                throw new \DomainException('The outbox is down.');
            }
        });

        AuditLog::event(self::CODE)->record();

        $this->assertThrows(static fn () => DB::commit(), \LogicException::class);

        self::assertCount(1, $this->spillLines());
    }

    /**
     * A commit with no work waiting costs no statement.
     *
     * @return void
     */
    public function testACommitWithNoWorkWaitingAsksNothing(): void
    {
        $statements = 0;

        DB::connection(self::CONNECTION)->listen(static function () use (&$statements): void {
            $statements++;
        });

        DB::beginTransaction();

        $this->queue()->reserve($this->pending());

        DB::commit();

        self::assertSame(0, $statements);
    }

    /**
     * A probe asks a PostgreSQL connection with work waiting whether its
     * transaction is alive, and an aborted one makes the commit's work abandon.
     *
     * @return void
     */
    public function testAnAbortedAnswerDoomsTheWork(): void
    {
        $abandoned   = [];
        $failure     = self::answer('25P02');
        $transaction = $this->begin();

        $this->queue()->defer($transaction, $this->noting('written'), static function (\Throwable $aborted) use (&$abandoned): void {
            $abandoned[] = $aborted;
        });

        $this->queue()->probe(new TransactionCommitting(self::postgresAnswering($failure)));

        DB::commit();

        self::assertSame([], $this->ran);
        self::assertSame([$failure], $abandoned);
    }

    /**
     * A live transaction, and a question that fails any other way, leave the
     * work to run: a failed question is the commit's to raise.
     *
     * @return void
     */
    public function testAnyOtherAnswerLeavesTheWork(): void
    {
        foreach ([null, self::answer('08006')] as $answer) {
            $this->ran = [];

            $this->queue()->defer($this->begin(), $this->noting('written'));
            $this->queue()->probe(new TransactionCommitting(self::postgresAnswering($answer)));

            DB::commit();

            self::assertSame(['written'], $this->ran);
        }
    }

    /**
     * Only the connection the work waits on is asked, and only PostgreSQL has
     * such a state, so no other engine pays for the question.
     *
     * @return void
     */
    public function testOnlyPostgresWithWorkWaitingIsAsked(): void
    {
        $this->queue()->defer($this->begin(), $this->noting('written'));

        $other = \Mockery::mock(Connection::class);

        $other->allows('getName')->andReturn('another');
        $other->allows('getDriverName')->andReturn('pgsql');
        $other->shouldNotReceive('scalar');

        $this->queue()->probe(new TransactionCommitting($other));

        $mysql = \Mockery::mock(Connection::class);

        $mysql->allows('getName')->andReturn(self::CONNECTION);
        $mysql->allows('getDriverName')->andReturn('mysql');
        $mysql->shouldNotReceive('scalar');

        $this->queue()->probe(new TransactionCommitting($mysql));

        DB::commit();

        self::assertSame(['written'], $this->ran);
    }

    /**
     * With no transactions manager, or none swapped in yet, work is still held
     * by the transaction it was deferred on.
     *
     * @return void
     */
    public function testAQueueWithNoManagerHoldsWorkOnTheTransaction(): void
    {
        $transaction = new DatabaseTransactionRecord(self::CONNECTION, 2, new DatabaseTransactionRecord(self::CONNECTION, 1));
        $container   = new Container;
        $queue       = new CommitQueue($container);

        $queue->defer($transaction, $this->noting('work'));

        self::assertSame([], $this->ran);

        $transaction->executeCallbacks();

        self::assertSame(['work'], $this->ran);

        $queue->probe(new TransactionCommitting(DB::connection(self::CONNECTION)));
    }

    /**
     * A PostgreSQL connection whose `select 1` gives the answer: a failure to
     * throw, or a live transaction's result.
     *
     * @param  ?\Throwable  $answer
     * @return \Illuminate\Database\Connection
     */
    private static function postgresAnswering(?\Throwable $answer): Connection
    {
        $connection = \Mockery::mock(Connection::class);

        $connection->allows('getName')->andReturn(self::CONNECTION);
        $connection->allows('getDriverName')->andReturn('pgsql');

        $expectation = $connection->expects('scalar')->with('select 1', [], false);

        $answer === null ? $expectation->andReturn(1) : $expectation->andThrow($answer);

        return $connection;
    }

    /**
     * A failed statement with the SQLSTATE.
     *
     * @param  string  $state
     * @return \Illuminate\Database\QueryException
     */
    private static function answer(string $state): QueryException
    {
        $previous = new \PDOException("SQLSTATE[{$state}]: Failed.");

        $previous->errorInfo = [$state, 7, ''];

        return new QueryException(self::CONNECTION, 'select 1', [], $previous);
    }

    /**
     * The queue the application holds.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\CommitQueue
     */
    private function queue(): CommitQueue
    {
        return app(CommitQueue::class);
    }

    /**
     * Open a transaction and return its record.
     *
     * @return \Illuminate\Database\DatabaseTransactionRecord
     */
    private function begin(): DatabaseTransactionRecord
    {
        DB::beginTransaction();

        return $this->pending();
    }

    /**
     * The innermost open transaction's record.
     *
     * @return \Illuminate\Database\DatabaseTransactionRecord
     */
    private function pending(): DatabaseTransactionRecord
    {
        $manager = app('db.transactions');

        self::assertInstanceOf(DatabaseTransactionsManager::class, $manager);

        $transaction = $manager->callbackApplicableTransactions()->last();

        self::assertInstanceOf(DatabaseTransactionRecord::class, $transaction);

        return $transaction;
    }

    /**
     * Work that notes it ran.
     *
     * @param  string  $name
     * @return \Closure(): void
     */
    private function noting(string $name): \Closure
    {
        return function () use ($name): void {
            $this->ran[] = $name;
        };
    }
}
