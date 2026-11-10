<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Monolog\Handler\NullHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Delivery\CaptureSignal;
use SineMacula\Laravel\AuditLog\Delivery\FailureHandler;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxWriter;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SearchesForSecrets;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Integration tests for failures that end a host's transaction, through
 * Laravel's own transaction handling on the framework version the suite runs
 * on. A store raises inside `$connection->transaction()`, so
 * `handleTransactionException()` runs as it does for a real insert, and on
 * MySQL and PostgreSQL the engine raises real lock wait timeouts, real
 * deadlocks and real lost connections between processes.
 *
 * Inside a host a concurrency error propagates as the sanitised
 * `DeadlockException`, whatever the failure mode, and a lost connection as the
 * sanitised `AuditWriteFailedException`. Neither is spilled or reported by the
 * package, and each says `AuditWriteFailed`. Laravel still recognises the
 * deadlock, so a host's `transaction()` retries it, at the outermost level
 * only. With no host open the same failures follow the failure rule.
 *
 * A captured record follows the `REPORT` rule whatever the mode, and a host's
 * failure is still the one thing it lets out: thrown sanitised from a
 * synchronous capture inside a host, and signalled as fatal, while one outside
 * a host, or met by a write deferred to the commit, is spilled, reported and
 * signalled, and the capture returns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailureClassifier::class)]
#[CoversClass(FailureHandler::class)]
#[CoversClass(OutboxWriter::class)]
#[CoversClass(RecordDelivery::class)]
final class HostFatalFailuresTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore, InteractsWithOutbox, RunsKilledChildren, SearchesForSecrets, SeedsTheOutbox;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string The message of the sanitised deadlock. */
    private const string SANITISED = 'Deadlock found when trying to get lock; an audit write was abandoned inside the host transaction.';

    /** @var int The code of the sanitised deadlock. */
    private const int SANITISED_CODE = 40001;

    /** @var string A table the host transaction writes to. */
    private const string HOST_TABLE = 'audit_fatal_host_writes';

    /** @var string A second session on the worker's database. */
    private const string READER = 'audit_reader';

    /** @var string The spill channel, which writes nowhere; the lines are captured as they are logged. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var string The id the two sides of a real race contend for. */
    private const string CONTENDED_ID = '01932b4e-8a40-7000-8000-00000000f001';

    /** @var string The file a child leaves what happened to it in. */
    private const string OUTCOME = 'outcome';

    /** @var int How many rows the parent writes before a real deadlock, so MySQL takes the child, the smaller transaction, as its victim. */
    private const int PARENT_WEIGHT_ROWS = 20;

    /** @var int How long a look for another session's lock wait goes on before it is a failure, in seconds. */
    private const int LOCK_WAIT_TIMEOUT_SECONDS = 60;

    /** @var int How long a look for another session's lock wait sleeps between looks, in microseconds: more than the 0.1 seconds without a read that InnoDB waits before it refreshes `innodb_trx`. */
    private const int LOCK_WAIT_POLL_MICROSECONDS = 150000;

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditWriteFailed> Every `AuditWriteFailed` heard. */
    private array $failures = [];

    /** @var list<string> The class each capture's signal was told, in order. */
    private array $signalled = [];

    /**
     * Create the table the host writes to, bind the reporter, capture the spill
     * lines and hear each `AuditWriteFailed`.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::dropIfExists(self::HOST_TABLE);

        Schema::create(self::HOST_TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('name', 32);
        });

        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        $this->captureLogLines();

        Event::listen(AuditWriteFailed::class, function (AuditWriteFailed $failure): void {
            $this->failures[] = $failure;
        });
    }

    /**
     * Roll back any transaction a failed test left open, then drop what the
     * test added, and remove what the children shared once the migrations have
     * rolled back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Str::createUuidsNormally();

        foreach (DB::getConnections() as $connection) {
            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }

        $this->removeOutboxProbeTable();

        Schema::dropIfExists(self::HOST_TABLE);

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * In report mode a deadlock inside a host still propagates, as the fixed
     * sanitised exception: nothing is spilled or reported, and the event says
     * it.
     *
     * @return void
     */
    public function testADeadlockInsideAHostPropagatesInReportMode(): void
    {
        $host = $this->host();

        $this->bindStoreRaising(self::deadlock());

        $host->beginTransaction();

        $thrown = $this->deadlockFrom(static fn (): AuditRecord => self::immediateRecord());

        self::assertDeadlockIsSanitised($thrown);
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
        self::assertCount(1, $this->failures);
        self::assertSame(DeadlockException::class, $this->failures[0]->exception);
    }

    /**
     * Rows of `[what the record asks for, failure mode]`: every rule a record
     * can have, each of which a deadlock inside a host overrides.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\PendingRecord, 1: string}>
     */
    public static function provideRules(): iterable
    {
        yield from [
            'immediate in report mode' => [static fn (PendingRecord $record): PendingRecord => $record->immediately(), 'report'],
            'immediate in throw mode'  => [static fn (PendingRecord $record): PendingRecord => $record->immediately(), 'throw'],
            'fail closed'              => [static fn (PendingRecord $record): PendingRecord => $record->failClosed(), 'report'],
            'transactional'            => [static fn (PendingRecord $record): PendingRecord => $record->transactional(), 'report'],
        ];
    }

    /**
     * Whatever the rule, a deadlock inside a host is the same sanitised
     * exception, with no spill and no report.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\PendingRecord  $asks
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideRules')]
    public function testADeadlockInsideAHostPropagatesWhateverTheRule(\Closure $asks, string $mode): void
    {
        $host = $this->host();

        app(ConfigRepository::class)->set('audit-log.failure.mode', $mode);

        $this->bindStoreRaising(self::deadlock());

        $host->beginTransaction();

        self::assertDeadlockIsSanitised($this->deadlockFrom(static fn (): AuditRecord => $asks(AuditLog::event(self::CODE))->record()));
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
        self::assertCount(1, $this->failures);
    }

    /**
     * A host's `transaction()` with attempts to spare recognises the sanitised
     * deadlock, rolls back and runs its closure again: one business change and
     * one entry commit, and the abandoned attempt leaves only its event.
     *
     * @return void
     */
    public function testTheHostsTransactionRetryStillWorks(): void
    {
        $host     = $this->host();
        $attempts = 0;

        $this->bindStoreRaisingOnce(self::deadlock());

        $host->transaction(function () use (&$attempts): void {
            $attempts++;

            $this->writeTheBusinessChange();

            self::immediateRecord();
        }, 2);

        self::assertSame(2, $attempts);
        self::assertSame(0, $host->transactionLevel());
        self::assertSame(1, $this->hostRows());
        self::assertSame(1, $this->entryCount());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
        self::assertCount(1, $this->failures);
    }

    /**
     * A host whose attempts run out gets the sanitised deadlock itself, with
     * nothing of the abandoned work kept.
     *
     * @return void
     */
    public function testAnExhaustedRetryReachesTheCallerSanitised(): void
    {
        $host     = $this->host();
        $attempts = 0;

        $this->bindStoreRaising(self::deadlock());

        $thrown = $this->deadlockFrom(function () use ($host, &$attempts): void {
            $host->transaction(function () use (&$attempts): void {
                $attempts++;

                $this->writeTheBusinessChange();

                self::immediateRecord();
            }, 2);
        });

        self::assertSame(2, $attempts);
        self::assertDeadlockIsSanitised($thrown);
        self::assertSame(0, $host->transactionLevel());
        self::assertSame(0, $this->hostRows());
        self::assertCount(2, $this->failures);
    }

    /**
     * The exception that reaches the host holds nothing of the failure it
     * replaced, with every frame's arguments kept: not its message, its SQL,
     * its bindings or the record, and what it replaced would have held them, so
     * the search is one that can fail.
     *
     * @return void
     */
    public function testTheSanitisedExceptionHoldsNoBinding(): void
    {
        $host     = $this->host();
        $failure  = self::deadlock();
        $previous = ini_set('zend.exception_ignore_args', '0');

        self::assertTrue(self::holdsText($failure, self::SECRET));

        $this->bindStoreRaising($failure);

        $host->beginTransaction();

        try {
            $thrown = $this->deadlockFrom(static fn (): AuditRecord => AuditLog::event(self::CODE)->immediately()->withProperties(['amount' => self::SECRET])->record());
        } finally {
            ini_set('zend.exception_ignore_args', $previous === false ? '0' : $previous);
        }

        self::assertNull($thrown->getPrevious());
        self::assertHoldsNoSecret($thrown, 'the sanitised exception');
        self::assertHoldsNoSecret($this->failures, 'the event');
        self::assertHoldsNoSecret($this->spillLines(), 'the spill');
    }

    /**
     * The level a deadlock leaves is the host's own: Laravel gives up only the
     * store's nested transaction, at every depth, and the host decides what
     * happens next.
     *
     * @return void
     */
    public function testTheTransactionLevelIsTheHostsAfterADeadlock(): void
    {
        $host    = $this->host();
        $manager = app('db.transactions');

        self::assertInstanceOf(DatabaseTransactionsManager::class, $manager);

        $this->bindStoreRaising(self::deadlock());

        foreach ([1, 2, 3] as $level) {
            $host->beginTransaction();

            $this->deadlockFrom(static fn (): AuditRecord => self::immediateRecord());

            self::assertSame($level, $host->transactionLevel());
            self::assertCount($level, $manager->callbackApplicableTransactions());
        }

        $host->rollBack(0);

        self::assertSame(0, $host->transactionLevel());
    }

    /**
     * In report mode a lost connection inside a host propagates as the
     * sanitised exception, since the transaction is gone: nothing is spilled or
     * reported, and the event says it.
     *
     * @return void
     */
    public function testALostConnectionInsideAHostPropagatesInReportMode(): void
    {
        $host = $this->host();

        $this->bindStoreRaising(self::lostConnection());

        $host->beginTransaction();

        $thrown = $this->failedWriteFrom(static fn (): AuditRecord => self::immediateRecord());

        self::assertSame(QueryException::class, $thrown->exceptionClass);
        self::assertSame(FailedOperation::STORE->value, $thrown->operation);
        self::assertSame(self::CONNECTION, $thrown->connection);
        self::assertNull($thrown->getPrevious());
        self::assertStringNotContainsString(self::SECRET, $thrown->getMessage());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
        self::assertCount(1, $this->failures);
    }

    /**
     * A deadlock inside a nested host transaction is not retried at that level,
     * however many attempts it has, since the engine ended the whole
     * transaction: the outermost `transaction()` runs everything again.
     *
     * @return void
     */
    public function testANestedDeadlockIsTheHostsToRetry(): void
    {
        $host  = $this->host();
        $outer = 0;
        $inner = 0;

        $this->bindStoreRaisingOnce(self::deadlock());

        $host->transaction(function () use ($host, &$outer, &$inner): void {
            $outer++;

            $this->writeTheBusinessChange();

            $host->transaction(static function () use (&$inner): void {
                $inner++;

                self::immediateRecord();
            }, 3);
        }, 2);

        self::assertSame(2, $outer);
        self::assertSame(2, $inner);
        self::assertSame(0, $host->transactionLevel());
        self::assertSame(1, $this->hostRows());
        self::assertSame(1, $this->entryCount());
    }

    /**
     * A stack whose database destination deadlocks has tried its other
     * destination by the time it throws, and the stack's flag makes the failure
     * the sanitised deadlock.
     *
     * @return void
     */
    public function testAStackOfADeadlockingDatabasePropagates(): void
    {
        $host   = $this->host();
        $called = 0;

        $log = new CallbackStore(static function () use (&$called): void {
            $called++;
        });

        app()->instance(AuditStore::class, new StackAuditStore(['database' => $this->storeRaising(self::deadlock()), 'log' => $log]));

        $host->beginTransaction();

        self::assertDeadlockIsSanitised($this->deadlockFrom(static fn (): AuditRecord => self::immediateRecord()));
        self::assertSame(1, $called);
        self::assertSame(1, $host->transactionLevel());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * A stack whose database destination loses its connection propagates the
     * sanitised exception by the stack's flag.
     *
     * @return void
     */
    public function testAStackOfALostDatabasePropagates(): void
    {
        $host = $this->host();

        $log = new CallbackStore(static function (): void {});

        app()->instance(AuditStore::class, new StackAuditStore(['database' => $this->storeRaising(self::lostConnection()), 'log' => $log]));

        $host->beginTransaction();

        $thrown = $this->failedWriteFrom(static fn (): AuditRecord => self::immediateRecord());

        self::assertNull($thrown->getPrevious());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * An outbox insert that deadlocks inside its savepoint goes through
     * Laravel's handling too, and reaches the host sanitised whatever the
     * record's timing; there is no spill to bind.
     *
     * @return void
     */
    public function testAnOutboxInsertDeadlockPropagates(): void
    {
        $this->outboxModeOn();

        $host = $this->outboxConnection();

        $this->raiseOnOutboxInserts(self::deadlock());

        foreach (['after commit' => AuditLog::event(self::CODE), 'immediately' => AuditLog::event(self::CODE)->immediately()] as $timing => $record) {
            $host->beginTransaction();

            self::assertDeadlockIsSanitised($this->deadlockFrom(static fn (): AuditRecord => $record->record()), $timing);
            self::assertSame(1, $host->transactionLevel(), $timing);

            $host->rollBack();
        }

        self::assertSame(0, $this->outboxCount());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
        self::assertCount(2, $this->failures);
        self::assertSame(Outbox::class, $this->failures[0]->store);
    }

    /**
     * A host's `transaction()` retries an outbox insert's deadlock too: the
     * second attempt's row is the one that commits.
     *
     * @return void
     */
    public function testAnOutboxInsertDeadlockIsRetriedByTheHost(): void
    {
        $this->outboxModeOn();

        $host     = $this->outboxConnection();
        $attempts = 0;

        $this->raiseOnOutboxInserts(self::deadlock(), 1);

        $host->transaction(function () use (&$attempts): void {
            $attempts++;

            $this->writeTheBusinessChange();

            AuditLog::event(self::CODE)->record();
        }, 2);

        self::assertSame(2, $attempts);
        self::assertSame(1, $this->hostRows());
        self::assertSame(1, $this->outboxCount());
    }

    /**
     * An outbox insert that loses its connection inside a host propagates as
     * the sanitised exception, naming the outbox.
     *
     * @return void
     */
    public function testAnOutboxInsertLostConnectionPropagates(): void
    {
        $this->outboxModeOn();

        $this->raiseOnOutboxInserts(self::lostConnection());

        $this->outboxConnection()->beginTransaction();

        $thrown = $this->failedWriteFrom(static fn (): AuditRecord => self::immediateRecord());

        self::assertSame(FailedOperation::OUTBOX->value, $thrown->operation);
        self::assertSame(Outbox::class, $thrown->store);
        self::assertNull($thrown->getPrevious());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * Rows of `[what the store raises]`: the two failures fatal to a host.
     *
     * @return iterable<string, array{0: \Closure(): \Illuminate\Database\QueryException}>
     */
    public static function provideFatalFailures(): iterable
    {
        yield from [
            'a deadlock'        => [static fn (): QueryException => self::deadlock()],
            'a lost connection' => [static fn (): QueryException => self::lostConnection()],
        ];
    }

    /**
     * With no host transaction open there is nothing to end, so either failure
     * follows the rule: in report mode it is spilled and reported, and the
     * caller goes on.
     *
     * @param  \Closure(): \Illuminate\Database\QueryException  $failure
     * @return void
     */
    #[DataProvider('provideFatalFailures')]
    public function testAFatalFailureOutsideAHostFollowsTheRule(\Closure $failure): void
    {
        $this->bindStoreRaising($failure());

        $record = self::immediateRecord();

        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->failures);
        self::assertSame($record->id, $this->failures[0]->id);
    }

    /**
     * An after-commit write runs once the host has gone, so either failure
     * follows the rule there too: the commit stands, and the record is spilled.
     *
     * @param  \Closure(): \Illuminate\Database\QueryException  $failure
     * @return void
     */
    #[DataProvider('provideFatalFailures')]
    public function testAFatalFailureOfADeferredWriteLeavesTheCommitStanding(\Closure $failure): void
    {
        $host = $this->host();

        $this->bindStoreRaising($failure());

        $host->transaction(function (): void {
            $this->writeTheBusinessChange();

            AuditLog::event(self::CODE)->record();

            self::assertSame([], $this->failures);
        });

        self::assertSame(1, $this->hostRows());
        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->failures);
    }

    /**
     * A capture's deadlock inside a host transaction is the one failure that
     * reaches the dispatching flow: the same sanitised exception as for any
     * record, under the `throw` mode too, which a capture never reads, with
     * nothing spilled or reported, and the signal told once that it was fatal.
     *
     * @return void
     */
    public function testACapturesDeadlockInsideAHostTransactionPropagatesSanitised(): void
    {
        $host   = $this->host();
        $signal = $this->signal();

        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        $this->bindStoreRaising(self::deadlock());

        $host->beginTransaction();

        self::assertDeadlockIsSanitised($this->deadlockFrom(static fn () => self::deliverCaptured($signal)));
        self::assertSame(1, $host->transactionLevel());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
        self::assertCount(1, $this->failures);
        self::assertSame(DeadlockException::class, $this->failures[0]->exception);
        self::assertSame([DeadlockException::class], $this->signalled);
        self::assertTrue($signal->isFatal());
    }

    /**
     * A capture's lost connection inside a host transaction propagates as the
     * sanitised failed write, holding nothing of the failure, and the signal is
     * told once that it was fatal.
     *
     * @return void
     */
    public function testACapturesLostConnectionInsideAHostTransactionPropagatesSanitised(): void
    {
        $signal = $this->signal();

        $this->bindStoreRaising(self::lostConnection());

        $this->host()->beginTransaction();

        $thrown = $this->failedWriteFrom(static fn () => self::deliverCaptured($signal));

        self::assertSame(QueryException::class, $thrown->exceptionClass);
        self::assertSame(FailedOperation::STORE->value, $thrown->operation);
        self::assertNull($thrown->getPrevious());
        self::assertStringNotContainsString(self::SECRET, $thrown->getMessage());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
        self::assertCount(1, $this->failures);
        self::assertSame([QueryException::class], $this->signalled);
        self::assertTrue($signal->isFatal());
    }

    /**
     * A capture's outbox insert inside the host's transaction on the outbox
     * connection is not deferred, so its deadlock reaches the dispatching flow
     * sanitised, whatever the record's timing, and the signal says it was
     * fatal.
     *
     * @return void
     */
    public function testACapturesOutboxInsertDeadlockInsideTheHostPropagatesSanitised(): void
    {
        $this->outboxModeOn();

        $host = $this->outboxConnection();

        $this->raiseOnOutboxInserts(self::deadlock());

        foreach ([Timing::AFTER_COMMIT, Timing::IMMEDIATE] as $timing) {
            $signal = $this->signal();

            $host->beginTransaction();

            self::assertDeadlockIsSanitised($this->deadlockFrom(static fn () => self::deliverCaptured($signal, $timing)), $timing->name);
            self::assertFalse($signal->isDeferred(), $timing->name);
            self::assertTrue($signal->isFatal(), $timing->name);

            $host->rollBack();
        }

        self::assertSame(0, $this->outboxCount());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
        self::assertSame([DeadlockException::class, DeadlockException::class], $this->signalled);
    }

    /**
     * With no transaction open a capture's deadlock or lost connection ends
     * nothing, so it follows the `REPORT` rule under the `throw` mode too: the
     * capture returns, the record is spilled and reported once, and the signal
     * is told once, not fatal.
     *
     * @param  \Closure(): \Illuminate\Database\QueryException  $failure
     * @return void
     */
    #[DataProvider('provideFatalFailures')]
    public function testOutsideATransactionACapturesFailureIsReported(\Closure $failure): void
    {
        $signal = $this->signal();
        $record = RecordFactory::captured();

        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        $this->bindStoreRaising($failure());

        app(RecordDelivery::class)->deliver($record, Timing::IMMEDIATE, null, false, $signal);

        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->failures);
        self::assertSame($record->id, $this->failures[0]->id);
        self::assertSame([QueryException::class], $this->signalled);
        self::assertFalse($signal->isFatal());
    }

    /**
     * A deferred capture's write runs once the host has committed, so either
     * failure ends nothing there: the commit stands, the record is spilled and
     * reported once, and the signal is told at the commit, not fatal.
     *
     * @param  \Closure(): \Illuminate\Database\QueryException  $failure
     * @return void
     */
    #[DataProvider('provideFatalFailures')]
    public function testADeferredCapturesFatalFailureLeavesTheCommitStanding(\Closure $failure): void
    {
        $signal = $this->signal();

        $this->bindStoreRaising($failure());

        $this->host()->transaction(function () use ($signal): void {
            $this->writeTheBusinessChange();

            self::deliverCaptured($signal, Timing::AFTER_COMMIT);

            self::assertTrue($signal->isDeferred());
            self::assertSame([], $this->signalled);
        });

        self::assertSame(1, $this->hostRows());
        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->failures);
        self::assertSame([QueryException::class], $this->signalled);
        self::assertFalse($signal->isFatal());
    }

    /**
     * On MySQL an insert that waits on another session's row past its lock wait
     * timeout, inside a host, raises Laravel's concurrency error, whose message
     * holds the row. What reaches the host is the fixed sanitised deadlock, and
     * the other session's row is untouched.
     *
     * @return void
     */
    public function testOnMySqlARealLockWaitTimeoutPropagatesSanitised(): void
    {
        $this->skipUnlessOn('mysql');

        $finalised = $this->contendedRecord();

        $pid = $this->startChild(function (): void {
            $this->awaitGate('entry-held');

            $host = DB::connection();

            $host->statement('SET SESSION innodb_lock_wait_timeout = 1');
            $host->beginTransaction();

            $this->reportOutcome(static function (): void {
                self::pinTheContendedId();
                self::recordHoldingTheSecret();
            });

            $this->appendToChildFile(self::OUTCOME, (string) $host->transactionLevel());

            $host->rollBack();
        });

        $holder = DB::connection();

        $holder->beginTransaction();

        $this->store()->store($finalised);

        $this->openGate('entry-held');

        $this->assertKilled($this->waitForChild($pid));

        $holder->commit();

        [$outcome, $level] = $this->childFileLines(self::OUTCOME);

        self::assertSame(self::sanitisedOutcome(), json_decode($outcome, true, flags: JSON_THROW_ON_ERROR));
        self::assertSame('1', $level);
        self::assertSame(1, $this->entryCount());
        self::assertSame($finalised->hmac, $this->storedRow(self::CONTENDED_ID)['hmac']);
    }

    /**
     * On MySQL a real deadlock of which the audit insert is the victim
     * propagates sanitised when the host has no attempts to spare.
     *
     * @return void
     */
    public function testOnMySqlARealDeadlockPropagatesSanitised(): void
    {
        $this->skipUnlessOn('mysql');

        $this->assertARealDeadlockPropagatesSanitised();
    }

    /**
     * On MySQL a real deadlock of which the audit insert is the victim is
     * retried by the host's `transaction()`, and the retry commits.
     *
     * @return void
     */
    public function testOnMySqlARealDeadlockRetries(): void
    {
        $this->skipUnlessOn('mysql');

        $this->assertARealDeadlockRetries();
    }

    /**
     * On PostgreSQL a real deadlock of which the audit insert is the victim
     * propagates sanitised when the host has no attempts to spare.
     *
     * @return void
     */
    public function testOnPostgresARealDeadlockPropagatesSanitised(): void
    {
        $this->skipUnlessOn('pgsql');

        $this->assertARealDeadlockPropagatesSanitised();
    }

    /**
     * On PostgreSQL a real deadlock of which the audit insert is the victim is
     * retried by the host's `transaction()`, and the retry commits.
     *
     * @return void
     */
    public function testOnPostgresARealDeadlockRetries(): void
    {
        $this->skipUnlessOn('pgsql');

        $this->assertARealDeadlockRetries();
    }

    /**
     * On a database server, a session ended under a host's transaction loses
     * that transaction: the savepoint of the audit insert fails, and what
     * reaches the host is the sanitised exception, unspilled. Laravel forgets
     * the transaction when the host rolls back, and the host's work is gone.
     *
     * @return void
     */
    public function testARealLostConnectionInsideAHostPropagatesSanitised(): void
    {
        $this->skipUnlessOn('mysql', 'pgsql');

        $host = $this->host();

        $host->beginTransaction();

        $this->writeTheBusinessChange();

        $this->endTheSessionOf($host);

        $thrown = $this->failedWriteFrom(static fn (): AuditRecord => self::immediateRecord());

        self::assertSame(\PDOException::class, $thrown->exceptionClass);
        self::assertSame(self::CONNECTION, $thrown->connection);
        self::assertNull($thrown->getPrevious());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
        self::assertCount(1, $this->failures);

        $this->assertThrows(static fn () => $host->rollBack(), \PDOException::class);

        self::assertSame(0, $host->transactionLevel());
        self::assertSame(0, $this->hostRows());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A real serialisation failure in the audit savepoint: Laravel wraps it in
     * a `DeadlockException` with the code 0 and no phrase on its list, and it
     * has ended the host's transaction all the same. Under the report rule it
     * is the sanitised deadlock, with no spill.
     *
     * @return void
     */
    public function testOnPostgresASerialisationFailurePropagatesSanitised(): void
    {
        $this->skipUnlessOn('pgsql');

        $this->bindStoreConflictingWithAnotherSession();

        $host = $this->host();

        $host->beginTransaction();

        $this->takeASnapshotThenConflict($host);

        self::assertDeadlockIsSanitised($this->deadlockFrom(static fn (): AuditRecord => self::immediateRecord()));
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
        self::assertCount(1, $this->failures);
    }

    /**
     * The same failure lets the host's `transaction()` retry: its second
     * attempt commits with the record.
     *
     * @return void
     */
    public function testOnPostgresASerialisationFailureIsRetriedByTheHost(): void
    {
        $this->skipUnlessOn('pgsql');

        $this->bindStoreConflictingWithAnotherSession();

        $host     = $this->host();
        $attempts = 0;

        $host->transaction(function () use ($host, &$attempts): void {
            $attempts++;

            if ($attempts === 1) {
                $this->takeASnapshotThenConflict($host);
            }

            self::immediateRecord();
        }, 2);

        self::assertSame(2, $attempts);
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * An after-commit record's spill is not bound to a serialisation failure's
     * dead transaction, which would write a replayable line for work rolled
     * back: the code and class PostgreSQL gives reach the classifier through
     * Laravel's wrapper, whose own code is 0.
     *
     * @return void
     */
    public function testASerialisationFailureOfAnOutboxInsertLeavesNoSpill(): void
    {
        $this->outboxModeOn();

        $host = $this->outboxConnection();

        $this->raiseOnOutboxInserts(self::serialisationFailureOn((string) $host->getName()));

        $host->beginTransaction();

        self::assertDeadlockIsSanitised($this->deadlockFrom(static fn (): AuditRecord => AuditLog::event(self::CODE)->record()));

        $host->commit();

        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * A lost connection on another connection than the one a transaction is
     * open on ended nothing there, so a store's failure follows the rule.
     *
     * @return void
     */
    public function testAFatalFailureNamingAnotherConnectionFollowsTheRule(): void
    {
        $this->bindStoreRaising(self::queryFailureOn('another', 'SQLSTATE[HY000]: General error: 2006 MySQL server has gone away'));

        $this->host()->beginTransaction();

        self::immediateRecord();

        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
        self::assertSame(1, $this->host()->transactionLevel());
    }

    /**
     * Spill to a channel that writes nowhere, and register a second session.
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

        $config->set('logging.channels.' . self::SPILL_CHANNEL, ['driver' => 'monolog', 'handler' => NullHandler::class]);
        $config->set('audit-log.failure.log_channel', self::SPILL_CHANNEL);
        $config->set('database.connections.' . self::READER, $config->array('database.connections.' . self::CONNECTION));
    }

    /**
     * Bind a store that updates the row another session has changed, in a
     * savepoint, as a real store's own statement would.
     *
     * @return void
     */
    private function bindStoreConflictingWithAnotherSession(): void
    {
        $host = $this->host();

        $host->table(self::HOST_TABLE)->insert(['name' => 'work']);

        app()->instance(AuditStore::class, new CallbackStore(static function () use ($host): void {
            $host->transaction(static function () use ($host): void {
                $host->table(self::HOST_TABLE)->update(['name' => 'audit']);
            });
        }));
    }

    /**
     * Fix the transaction's snapshot at `REPEATABLE READ`, then have another
     * session change the row and commit, so the next update of it cannot be
     * serialised.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     */
    private function takeASnapshotThenConflict(Connection $connection): void
    {
        $connection->statement('set transaction isolation level repeatable read');
        $connection->table(self::HOST_TABLE)->count();

        DB::connection(self::READER)->table(self::HOST_TABLE)->update(['name' => 'other']);
    }

    /**
     * Assert a host with no attempts to spare gets the sanitised deadlock from
     * a real deadlock, with its work rolled back and the other session's kept.
     *
     * @return void
     */
    private function assertARealDeadlockPropagatesSanitised(): void
    {
        $this->raceIntoADeadlock(1);

        [$attempts, $outcome] = $this->childFileLines(self::OUTCOME);

        self::assertSame('1', $attempts);
        self::assertSame(self::sanitisedOutcome(), json_decode($outcome, true, flags: JSON_THROW_ON_ERROR));
        self::assertSame(1, $this->entryCount());
        self::assertSame('parent', $this->contendedRowName());
    }

    /**
     * Assert a host with an attempt to spare retries a real deadlock: its
     * second attempt commits with a record of its own, after the other
     * session's.
     *
     * @return void
     */
    private function assertARealDeadlockRetries(): void
    {
        $this->raceIntoADeadlock(2);

        [$attempts, $outcome] = $this->childFileLines(self::OUTCOME);

        self::assertSame('2', $attempts);
        self::assertSame(['thrown' => null], json_decode($outcome, true, flags: JSON_THROW_ON_ERROR));
        self::assertSame(2, $this->entryCount());
        self::assertSame('child', $this->contendedRowName());
    }

    /**
     * Run two sessions into a deadlock the audit insert is the victim of, and
     * leave in the shared file how many attempts the child's host made and what
     * it got.
     *
     * This process writes the entry the child will insert under the same id,
     * along with enough other rows that MySQL takes the child as the smaller
     * transaction, and tells it to go. The child takes a row of the host's
     * table, then waits until this process waits on that row, and records. The
     * cycle closes on its insert, which waits on this process's entry: MySQL
     * finds it there, and on PostgreSQL, where a session looks only once it has
     * waited for its own `deadlock_timeout`, this process's is too long to find
     * it first. Only the first attempt contends; a retry takes its own id.
     *
     * @param  positive-int  $hostAttempts
     * @return void
     */
    private function raceIntoADeadlock(int $hostAttempts): void
    {
        $finalised = $this->contendedRecord();
        $parent    = DB::connection();

        $parent->table(self::HOST_TABLE)->insert(['name' => 'seed']);

        $pid = $this->startChild(function () use ($hostAttempts): void {
            $this->awaitGate('entry-held');
            $this->contendAsTheHost($hostAttempts);
        });

        if ($parent->getDriverName() === 'pgsql') {
            $parent->statement('SET deadlock_timeout = \'10min\'');
        }

        $parent->beginTransaction();

        $this->store()->store($finalised);

        foreach (range(1, self::PARENT_WEIGHT_ROWS) as $row) {
            $parent->table(self::HOST_TABLE)->insert(['name' => "weight {$row}"]);
        }

        $this->openGate('entry-held');
        $this->awaitGate('row-held');

        $parent->table(self::HOST_TABLE)->where('id', 1)->update(['name' => 'parent']);

        $parent->commit();

        $this->assertKilled($this->waitForChild($pid));
    }

    /**
     * In the child: run the host's transaction, with the attempts given, and
     * leave in the shared file how many it made and what it got.
     *
     * @param  positive-int  $hostAttempts
     * @return void
     */
    private function contendAsTheHost(int $hostAttempts): void
    {
        $host     = DB::connection();
        $attempts = 0;

        if ($host->getDriverName() === 'pgsql') {
            $host->statement('SET deadlock_timeout = \'50ms\'');
        }

        $outcome = $this->outcomeOf(function () use ($host, $hostAttempts, &$attempts): void {
            $host->transaction(function () use ($host, &$attempts): void {
                $this->attemptTheContendedWrite($host, ++$attempts);
            }, $hostAttempts);
        });

        $this->appendToChildFile(self::OUTCOME, (string) $attempts);
        $this->appendToChildFile(self::OUTCOME, json_encode($outcome, JSON_THROW_ON_ERROR));
    }

    /**
     * In the child: take the host's row and record. The first attempt tells the
     * parent it holds the row, waits until the parent waits on it, and records
     * under the id the parent holds, which closes the cycle; a retry records
     * under an id of its own.
     *
     * @param  \Illuminate\Database\Connection  $host
     * @param  int  $attempt
     * @return void
     */
    private function attemptTheContendedWrite(Connection $host, int $attempt): void
    {
        $host->table(self::HOST_TABLE)->where('id', 1)->update(['name' => 'child']);

        if ($attempt === 1) {
            $this->openGate('row-held');
            $this->awaitAnotherSessionsLockWait($host);

            self::pinTheContendedId();
        } else {
            Str::createUuidsNormally();
        }

        self::recordHoldingTheSecret();
    }

    /**
     * Wait until another session is waiting on a lock, which on each engine its
     * activity tables say.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     *
     * @throws \RuntimeException
     */
    private function awaitAnotherSessionsLockWait(Connection $connection): void
    {
        $query = $connection->getDriverName() === 'pgsql'
            ? 'select count(*) as value from pg_stat_activity where wait_event_type = \'Lock\' and datname = current_database()'
            : 'select count(*) as value from information_schema.innodb_trx t join information_schema.processlist p on p.id = t.trx_mysql_thread_id'
                . ' where t.trx_state = \'LOCK WAIT\' and p.db = database()';

        $deadline = microtime(true) + self::LOCK_WAIT_TIMEOUT_SECONDS;

        while (self::numberFrom($connection, $query) === 0) {
            if (microtime(true) > $deadline) {
                throw new \RuntimeException('No other session ever waited on a lock.');
            }

            usleep(self::LOCK_WAIT_POLL_MICROSECONDS);
        }
    }

    /**
     * End the connection's session from a second session, and wait until the
     * server says it is gone.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     *
     * @throws \RuntimeException
     */
    private function endTheSessionOf(Connection $connection): void
    {
        $reader = DB::connection(self::READER);
        $pgsql  = $connection->getDriverName() === 'pgsql';

        $session = self::numberFrom($connection, $pgsql ? 'select pg_backend_pid() as value' : 'select connection_id() as value');

        $reader->statement($pgsql ? "select pg_terminate_backend({$session})" : "KILL {$session}");

        $alive = $pgsql
            ? "select count(*) as value from pg_stat_activity where pid = {$session}"
            : "select count(*) as value from information_schema.processlist where id = {$session}";

        $deadline = microtime(true) + self::LOCK_WAIT_TIMEOUT_SECONDS;

        while (self::numberFrom($reader, $alive) > 0) {
            if (microtime(true) > $deadline) {
                throw new \RuntimeException('The session was never ended.');
            }

            usleep(self::LOCK_WAIT_POLL_MICROSECONDS);
        }
    }

    /**
     * The number the query reads as its `value` column.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $query
     * @return int
     */
    private static function numberFrom(Connection $connection, string $query): int
    {
        $value = ((array) $connection->selectOne($query))['value'] ?? null;

        self::assertIsNumeric($value);

        return (int) $value;
    }

    /**
     * Leave in the shared file what the work threw, for the parent to read.
     *
     * @param  \Closure(): void  $work
     * @return void
     */
    private function reportOutcome(\Closure $work): void
    {
        $this->appendToChildFile(self::OUTCOME, json_encode($this->outcomeOf($work), JSON_THROW_ON_ERROR));
    }

    /**
     * What the work threw, and what the failure path did about it: the class,
     * message, code and whether it has a previous exception, how many spill
     * lines and reports were made, and how many events were said.
     *
     * @param  \Closure(): void  $work
     * @return array{thrown: ?class-string, message?: string, code?: int|string, chained?: bool, spilled?: int, reported?: int, said?: int}
     */
    private function outcomeOf(\Closure $work): array
    {
        try {
            $work();
        } catch (\Throwable $thrown) {
            return [
                'thrown'   => $thrown::class,
                'message'  => $thrown->getMessage(),
                'code'     => $thrown->getCode(),
                'chained'  => $thrown->getPrevious() !== null,
                'spilled'  => count($this->spillLines()),
                'reported' => count($this->reporter->reports()),
                'said'     => count($this->failures),
            ];
        }

        return ['thrown' => null];
    }

    /**
     * The outcome a sanitised deadlock leaves: its fixed text and code, with
     * nothing chained, spilled or reported, and one event.
     *
     * @return array{thrown: class-string, message: string, code: int, chained: bool, spilled: int, reported: int, said: int}
     */
    private static function sanitisedOutcome(): array
    {
        return [
            'thrown'   => DeadlockException::class,
            'message'  => self::SANITISED,
            'code'     => self::SANITISED_CODE,
            'chained'  => false,
            'spilled'  => 0,
            'reported' => 0,
            'said'     => 1,
        ];
    }

    /**
     * The name on the row the two sides of a real deadlock contend for.
     *
     * @return string
     */
    private function contendedRowName(): string
    {
        $name = DB::table(self::HOST_TABLE)->where('id', 1)->value('name');

        self::assertIsString($name);

        return $name;
    }

    /**
     * The record under the contended id, finalised by this process.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function contendedRecord(): FinalisedRecord
    {
        return $this->finalisedRecord(RecordFactory::captured(id: self::CONTENDED_ID));
    }

    /**
     * Record immediately, holding a secret the failure's message would carry.
     *
     * @return void
     */
    private static function recordHoldingTheSecret(): void
    {
        AuditLog::event(self::CODE)->immediately()->withProperties(['amount' => self::SECRET])->record();
    }

    /**
     * Have every record take the contended id, until a retry unpins it.
     *
     * @return void
     */
    private static function pinTheContendedId(): void
    {
        Str::createUuidsUsing(static fn (): UuidInterface => Uuid::fromString(self::CONTENDED_ID));
    }

    /**
     * Skip unless the suite runs against one of the drivers.
     *
     * @param  string  ...$drivers
     * @return void
     */
    private function skipUnlessOn(string ...$drivers): void
    {
        if (in_array(DB::connection()->getDriverName(), $drivers, true)) {
            return;
        }

        self::markTestSkipped(sprintf('Only %s raises this failure for real here.', implode(' and ', $drivers)));
    }

    /**
     * The store raising the failure on every call.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    private function bindStoreRaising(#[\SensitiveParameter] \Throwable $failure): void
    {
        app()->instance(AuditStore::class, $this->storeRaising($failure));
    }

    /**
     * The store raising the failure on its first call and storing every record
     * after that.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    private function bindStoreRaisingOnce(#[\SensitiveParameter] \Throwable $failure): void
    {
        $raising = $this->storeRaising($failure);
        $real    = $this->store();
        $raised  = false;

        app()->instance(AuditStore::class, new CallbackStore(static function (FinalisedRecord $record) use ($raising, $real, &$raised): void {
            if ($raised) {
                $real->store($record);

                return;
            }

            $raised = true;

            $raising->store($record);
        }, true, [self::CONNECTION]));
    }

    /**
     * A store that raises the failure inside `$connection->transaction()` on
     * the storage connection, as the database store's own insert does, so
     * Laravel's `handleTransactionException()` handles it. It says it is
     * durable and joins that connection, so every rule accepts it.
     *
     * @param  \Throwable  $failure
     * @return \Tests\Fixtures\Stores\CallbackStore
     */
    private function storeRaising(#[\SensitiveParameter] \Throwable $failure): CallbackStore
    {
        $connection = $this->storageConnection();

        return new CallbackStore(static function () use ($connection, $failure): void {
            $connection->transaction(static function () use ($failure): never {
                throw $failure;
            });
        }, true, [self::CONNECTION]);
    }

    /**
     * Raise the failure from the next outbox inserts, the number given or all
     * of them, at the statement: inside `$connection->transaction()` when a
     * transaction is open, as a real insert raises it.
     *
     * @param  \Throwable  $failure
     * @param  int  $times
     * @return void
     */
    private function raiseOnOutboxInserts(#[\SensitiveParameter] \Throwable $failure, int $times = PHP_INT_MAX): void
    {
        $this->outboxConnection()->beforeExecuting(static function (string $query) use ($failure, &$times): void {
            if ($times === 0 || preg_match('/^insert into \S*audit_log_outbox/', $query) !== 1) {
                return;
            }

            $times--;

            throw $failure;
        });
    }

    /**
     * Write the host's business change.
     *
     * @return void
     */
    private function writeTheBusinessChange(): void
    {
        $this->host()->table(self::HOST_TABLE)->insert(['name' => 'work']);
    }

    /**
     * The number of business changes that committed.
     *
     * @return int
     */
    private function hostRows(): int
    {
        return $this->host()->table(self::HOST_TABLE)->count();
    }

    /**
     * The connection the host transacts on, which is also the storage
     * connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function host(): Connection
    {
        return DB::connection(self::CONNECTION);
    }

    /**
     * Assert the exception is the sanitised deadlock: the fixed text and code,
     * and nothing chained.
     *
     * @param  \Illuminate\Database\DeadlockException  $thrown
     * @param  string  $message
     * @return void
     */
    private static function assertDeadlockIsSanitised(DeadlockException $thrown, string $message = ''): void
    {
        self::assertSame(self::SANITISED, $thrown->getMessage(), $message);
        self::assertSame(self::SANITISED_CODE, $thrown->getCode(), $message);
        self::assertNull($thrown->getPrevious(), $message);
    }

    /**
     * The sanitised deadlock the work throws.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(): mixed  $work
     * @return \Illuminate\Database\DeadlockException
     */
    private function deadlockFrom(\Closure $work): DeadlockException
    {
        try {
            $work();
        } catch (DeadlockException $thrown) {
            return $thrown;
        }

        self::fail('Expected the deadlock to be thrown.');
    }

    /**
     * The sanitised exception the work throws.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(): mixed  $work
     * @return \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function failedWriteFrom(\Closure $work): AuditWriteFailedException
    {
        try {
            $work();
        } catch (AuditWriteFailedException $thrown) {
            return $thrown;
        }

        self::fail('Expected the failed write to be thrown.');
    }

    /**
     * Record immediately in the default way.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function immediateRecord(): AuditRecord
    {
        return AuditLog::event(self::CODE)->immediately()->record();
    }

    /**
     * Deliver a captured record with the capture's signal, as a capture
     * delivers it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $signal
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @return void
     */
    private static function deliverCaptured(#[\SensitiveParameter] CaptureSignal $signal, Timing $timing = Timing::IMMEDIATE): void
    {
        app(RecordDelivery::class)->deliver(RecordFactory::captured(), $timing, null, false, $signal);
    }

    /**
     * A capture's signal that keeps the class it is told.
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
     * What PostgreSQL raises for a serialisation failure, as Laravel throws it:
     * its code is the string `40001`, which no constructor of the driver's
     * exception takes, and no phrase on Laravel's list is in its message.
     *
     * @param  string  $connection
     * @return \Illuminate\Database\QueryException
     */
    private static function serialisationFailureOn(string $connection): QueryException
    {
        $driver = new class ('SQLSTATE[40001]: Serialization failure: 7 ERROR:  could not serialize access due to concurrent update') extends \PDOException {
            /**
             * Constructor.
             *
             * @param  string  $message
             */
            public function __construct(string $message)
            {
                parent::__construct($message);

                $this->code      = '40001';
                $this->errorInfo = ['40001', 7, ''];
            }
        };

        return new QueryException($connection, 'insert into entries values (?)', ['x'], $driver);
    }

    /**
     * A failed statement on the connection, with the driver's message.
     *
     * @param  string  $connection
     * @param  string  $message
     * @return \Illuminate\Database\QueryException
     */
    private static function queryFailureOn(string $connection, string $message): QueryException
    {
        return new QueryException($connection, 'insert into entries values (?)', ['x'], new \PDOException($message));
    }

    /**
     * A failure Laravel recognises as a deadlock, whose message and bindings
     * hold the secret as a real one holds the row.
     *
     * @return \Illuminate\Database\QueryException
     */
    private static function deadlock(): QueryException
    {
        return self::queryFailure('SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction');
    }

    /**
     * A failure Laravel recognises as a lost connection, whose message and
     * bindings hold the secret as a real one holds the row.
     *
     * @return \Illuminate\Database\QueryException
     */
    private static function lostConnection(): QueryException
    {
        return self::queryFailure('SQLSTATE[HY000]: General error: 2006 MySQL server has gone away');
    }

    /**
     * A query failure with the driver's message, holding the secret in its
     * bindings and its message.
     *
     * @param  string  $message
     * @return \Illuminate\Database\QueryException
     */
    private static function queryFailure(string $message): QueryException
    {
        return new QueryException(self::CONNECTION, 'insert into "audit_log_entries" ("note") values (?)', [self::SECRET], new \PDOException($message . ' ' . self::SECRET));
    }
}
