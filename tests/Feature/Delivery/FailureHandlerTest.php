<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Monolog\Handler\NullHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Delivery\CaptureSignal;
use SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule;
use SineMacula\Laravel\AuditLog\Delivery\FailedWrite;
use SineMacula\Laravel\AuditLog\Delivery\FailureHandler;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use SineMacula\Laravel\AuditLog\Stores\StackDeliveryException;
use Symfony\Component\HttpFoundation\Response;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\ThrowingLogHandler;
use Tests\TestCase;

/**
 * Feature tests for what happens once a record could not be written: the spill,
 * report and event each rule asks for, and what is thrown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailureHandler::class)]
final class FailureHandlerTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore, SearchesForSecrets;

    /** @var string The spill channel, which writes nowhere; the lines are captured as they are logged. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var string The channel a test breaks the spill with. */
    private const string BROKEN_CHANNEL = 'audit-broken';

    /** @var string The store every failed write names. */
    private const string STORE = DatabaseAuditStore::class;

    /** @var string A failure Laravel reads as a concurrency error. */
    private const string DEADLOCK = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock';

    /** @var string A failure Laravel reads as a lost connection. */
    private const string LOST = 'SQLSTATE[HY000]: General error: 2006 MySQL server has gone away';

    /** @var string A failure Laravel reads as neither. */
    private const string BROKEN = 'The step is broken';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var ?string What the reporter fails with, once it has kept what it was asked to report, if anything. */
    private ?string $reporterFailure = null;

    /** @var int How many reports succeed before the reporter fails. */
    private int $reportsBeforeFailing = 0;

    /** @var ?string What a listener of `AuditWriteFailed` fails with, once it has kept the event, if anything. */
    private ?string $listenerFailure = null;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditWriteFailed> The events dispatched, in order. */
    private array $events = [];

    /** @var list<array{0: string, 1: bool}> Each step as it ran, in order, with whether the write guard was active. */
    private array $steps = [];

    /** @var list<string> The class each capture's signal passed on, in order. */
    private array $signalled = [];

    /** @var bool Whether a capture's signal fails once it has kept what it was told. */
    private bool $signalFails = false;

    /**
     * Bind the reporter, observe each step and capture the spill lines.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->reporter = new RecordingExceptionHandler;

        $this->bindReporter();
        $this->captureLogLines();

        $this->onLogLine(function (MessageLogged $logged): void {
            if (!str_starts_with($logged->message, FailureSpill::MARKER)) {
                return;
            }

            $this->steps[] = ['spill', $this->guard()->isActive()];
        });

        Event::listen(AuditWriteFailed::class, function (AuditWriteFailed $event): void {
            $this->events[] = $event;
            $this->steps[]  = ['event', $this->guard()->isActive()];

            if ($this->listenerFailure !== null) {
                $message = $this->listenerFailure . ': ' . self::SECRET;

                throw $this->listenerFailure === self::LOST ? new \PDOException($message) : new \RuntimeException($message);
            }
        });
    }

    /**
     * Roll back any transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection();

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        parent::tearDown();
    }

    /**
     * Under the `REPORT` rule the record is spilled, the failure reported and
     * the event dispatched, and the code that recorded goes on.
     *
     * @return void
     */
    public function testReportDoesEachStepAndContinues(): void
    {
        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT);

        self::assertSame(['spill', 'report', 'event'], $this->stepNames());
        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->events);
    }

    /**
     * The failure is reported once, as the sanitised exception and never as the
     * original.
     *
     * @return void
     */
    public function testReportsOnce(): void
    {
        $failed = $this->failedWrite($this->failure());

        $this->handle($failed, FailureRule::REPORT);

        $reports = $this->reporter->reports();

        self::assertCount(1, $reports);
        self::assertInstanceOf(AuditWriteFailedException::class, $reports[0]);
        self::assertSame($failed->record->id, $reports[0]->recordId);
        self::assertSame('invoice.approved', $reports[0]->eventCode);
        self::assertSame('store', $reports[0]->operation);
        self::assertSame(self::STORE, $reports[0]->store);
        self::assertSame(QueryException::class, $reports[0]->exceptionClass);
        self::assertSame('23000', $reports[0]->sqlState);
        self::assertSame(1062, $reports[0]->driverCode);
        self::assertSame('testing', $reports[0]->connection);
        self::assertNull($reports[0]->destination);
        self::assertHoldsNoSecret($reports, 'the reports');
    }

    /**
     * `AuditWriteFailed` is dispatched once.
     *
     * @return void
     */
    public function testDispatchesTheEventOnce(): void
    {
        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT);

        self::assertCount(1, $this->events);
    }

    /**
     * The record is spilled as one line, with its integrity fields.
     *
     * @return void
     */
    public function testSpillsOneLine(): void
    {
        $failed = $this->failedWrite($this->failure());

        $this->handle($failed, FailureRule::REPORT);

        self::assertNotNull($failed->finalised);
        self::assertSame([FailureSpill::line($failed->finalised->toArray())], $this->spillLines());
    }

    /**
     * The spill goes before the report and the event, since it is the record's
     * only lasting trace and a reporter may end the process.
     *
     * @return void
     */
    public function testTheSpillGoesFirst(): void
    {
        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT);

        self::assertSame('spill', $this->stepNames()[0]);
    }

    /**
     * The event carries the record's id and code and the store's and failure's
     * classes, and nothing of the record or the failure's text.
     *
     * @return void
     */
    public function testTheEventCarriesNoProperties(): void
    {
        $failed = $this->failedWrite($this->failure());

        $this->handle($failed, FailureRule::REPORT);

        self::assertSame([
            'id'        => $failed->record->id,
            'code'      => 'invoice.approved',
            'store'     => self::STORE,
            'exception' => QueryException::class,
        ], get_object_vars($this->events[0]));
        self::assertHoldsNoSecret($this->events, 'the events');
    }

    /**
     * Under the `SPILL_AND_THROW` rule the record is spilled and the event
     * dispatched, then the sanitised exception is thrown.
     *
     * @return void
     */
    public function testSpillAndThrowSpillsThenThrows(): void
    {
        $failed = $this->failedWrite($this->failure());

        $thrown = $this->thrownBy($failed, FailureRule::SPILL_AND_THROW);

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame($failed->record->id, $thrown->recordId);
        self::assertSame(['spill', 'event'], $this->stepNames());
        self::assertCount(1, $this->spillLines());
    }

    /**
     * Rows of `[rule]`: each rule that throws.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule}>
     */
    public static function provideThrowingRules(): iterable
    {
        yield from [
            'spill and throw' => [FailureRule::SPILL_AND_THROW],
            'throw'           => [FailureRule::THROW],
        ];
    }

    /**
     * A failure that is thrown is not also reported by the package, since a
     * handler that reports what reaches it would then report it twice.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @return void
     */
    #[DataProvider('provideThrowingRules')]
    public function testAThrownFailureIsNotAlsoReportedByThePackage(FailureRule $rule): void
    {
        $this->thrownBy($this->failedWrite($this->failure()), $rule);

        self::assertSame([], $this->reporter->reports());
        self::assertCount(1, $this->events);
    }

    /**
     * Under the `THROW` rule the event is dispatched and the sanitised
     * exception thrown, and nothing is spilled.
     *
     * @return void
     */
    public function testThrowEmitsTheEventAndNeverASpill(): void
    {
        $thrown = $this->thrownBy($this->failedWrite($this->failure()), FailureRule::THROW);

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame(['event'], $this->stepNames());
        self::assertSame([], $this->spillLines());
    }

    /**
     * The thrown exception has no previous exception and holds nothing of the
     * record or of the failure's text, frames included.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @return void
     */
    #[DataProvider('provideThrowingRules')]
    public function testTheThrownExceptionHasNoPrevious(FailureRule $rule): void
    {
        $thrown = $this->thrownBy($this->failedWrite($this->failure()), $rule);

        self::assertNull($thrown->getPrevious());
        self::assertHoldsNoSecret($thrown, 'the thrown exception');
    }

    /**
     * A spill that fails stops neither the report nor the event.
     *
     * @return void
     */
    public function testAFailedSpillStopsNothingElse(): void
    {
        $this->breakSpill(self::BROKEN);

        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT);

        self::assertSame(['report', 'report', 'event'], $this->stepNames());
        self::assertCount(1, $this->events);
    }

    /**
     * A reporter that fails stops neither the spill nor the event.
     *
     * @return void
     */
    public function testABrokenReporterStopsNothingElse(): void
    {
        $this->reporterFailure = self::BROKEN;

        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT);

        self::assertSame(['spill', 'report', 'report', 'event'], $this->stepNames());
        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->events);
    }

    /**
     * A listener that throws stops neither the spill nor the report, which both
     * ran before it.
     *
     * @return void
     */
    public function testAThrowingListenerStopsNothingElse(): void
    {
        $this->listenerFailure = self::BROKEN;

        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT);

        self::assertSame(['spill', 'report', 'event', 'report'], $this->stepNames());
        self::assertCount(1, $this->spillLines());
    }

    /**
     * A failed spill is reported as a sanitised exception naming the spill and
     * its failure's class, holding nothing else.
     *
     * @return void
     */
    public function testAFailedSpillIsReportedPayloadFree(): void
    {
        $this->breakSpill(self::BROKEN);

        $failed = $this->failedWrite($this->failure());

        $this->handle($failed, FailureRule::REPORT);

        $reports = $this->reporter->reports();

        self::assertCount(2, $reports);
        self::assertInstanceOf(AuditWriteFailedException::class, $reports[0]);
        self::assertSame($failed->record->id, $reports[0]->recordId);
        self::assertSame('spill', $reports[0]->operation);
        self::assertSame(self::STORE, $reports[0]->store);
        self::assertSame(\RuntimeException::class, $reports[0]->exceptionClass);
        self::assertNull($reports[0]->connection);
        self::assertNull($reports[0]->getPrevious());
        self::assertSame(['spill', 'store'], $this->reportedOperations());
        self::assertHoldsNoSecret($reports, 'the reports');
    }

    /**
     * A throwing listener is reported as a sanitised exception naming the
     * notification and its failure's class, holding nothing else.
     *
     * @return void
     */
    public function testAThrowingListenerIsReportedPayloadFree(): void
    {
        $this->listenerFailure = self::BROKEN;

        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT);

        $reports = $this->reporter->reports();

        self::assertCount(2, $reports);
        self::assertInstanceOf(AuditWriteFailedException::class, $reports[1]);
        self::assertSame('notify', $reports[1]->operation);
        self::assertSame(\RuntimeException::class, $reports[1]->exceptionClass);
        self::assertNull($reports[1]->getPrevious());
        self::assertHoldsNoSecret($reports, 'the reports');
    }

    /**
     * Under the `REPORT` rule nothing escapes, even when the spill, the
     * reporter and a listener all fail.
     *
     * @return void
     */
    public function testInReportModeNothingEscapesWhenEveryStepFails(): void
    {
        $this->breakEveryStep();

        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT);

        self::assertSame([], $this->spillLines());
        self::assertCount(1, $this->events);
    }

    /**
     * Under a rule that throws, the write's own sanitised exception escapes
     * even when the spill, the reporter and a listener all fail.
     *
     * @return void
     */
    public function testInThrowModeTheOriginalFailureEscapesWhenEveryStepFails(): void
    {
        $this->breakEveryStep();

        $thrown = $this->thrownBy($this->failedWrite($this->failure()), FailureRule::SPILL_AND_THROW);

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame('store', $thrown->operation);
        self::assertSame(QueryException::class, $thrown->exceptionClass);
    }

    /**
     * A reporter that fails while reporting a step's failure is contained: each
     * report is tried, and nothing escapes.
     *
     * @return void
     */
    public function testABrokenReporterOfASecondaryFailureIsContained(): void
    {
        $this->reporter = new RecordingExceptionHandler(true);

        $this->breakSpill(self::BROKEN);

        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT);

        $operations = array_map(static fn (\Throwable $report): ?string => $report instanceof AuditWriteFailedException ? $report->operation : null, $this->reporter->reports());

        self::assertSame(['spill', 'store', 'notify'], $operations);
        self::assertCount(1, $this->events);
    }

    /**
     * A record that failed before it was finalised is spilled marked
     * `unsigned`, with no signature, and only that line is tried.
     *
     * @return void
     */
    public function testAnUnfinalisedRecordIsSpilledUnsigned(): void
    {
        $failed = $this->failedWrite(new \LogicException('No signing key.'), finalised: false);

        $this->handle($failed, FailureRule::REPORT);

        self::assertSame([FailureSpill::line(['unsigned' => true, ...$failed->record->toArray()])], $this->spillLines());
        self::assertStringNotContainsString('"hmac"', $this->spillLines()[0]);
        self::assertSame(['store'], $this->reportedOperations());
    }

    /**
     * A transactional record that failed before it was finalised is not
     * spilled, unsigned or otherwise, and is thrown.
     *
     * @return void
     */
    public function testAnUnfinalisedTransactionalRecordIsNotSpilled(): void
    {
        $thrown = $this->thrownBy($this->failedWrite(new \LogicException('No signing key.'), finalised: false), FailureRule::THROW);

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame(\LogicException::class, $thrown->exceptionClass);
        self::assertSame([], $this->spillLines());
    }

    /**
     * A spill bound to a commit is written when that transaction commits, and
     * not before.
     *
     * @return void
     */
    public function testASpillBoundToACommitWaitsForIt(): void
    {
        $bound = $this->beginTransaction();

        $this->handle($this->failedWrite($this->failure(), hostOpen: true), FailureRule::REPORT, $bound);

        $beforeTheCommit = $this->spillLines();

        DB::commit();

        self::assertSame([], $beforeTheCommit);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * A spill bound to a commit is never written when that transaction rolls
     * back, so a replay never brings back a record of work that was undone.
     *
     * @return void
     */
    public function testASpillBoundToACommitIsDiscardedOnRollback(): void
    {
        $bound = $this->beginTransaction();

        $this->handle($this->failedWrite($this->failure(), hostOpen: true), FailureRule::REPORT, $bound);

        DB::rollBack();

        self::assertSame([], $this->spillLines());
        self::assertSame(0, DB::transactionLevel());
    }

    /**
     * A bound spill that fails at the commit, even with a deadlock, throws
     * nothing from the commit and is reported sanitised.
     *
     * @return void
     */
    public function testASpillBoundToACommitCannotThrowFromTheCommit(): void
    {
        $bound = $this->beginTransaction();

        $this->handle($this->failedWrite($this->failure(), hostOpen: true), FailureRule::REPORT, $bound);

        $this->breakSpill(self::DEADLOCK);

        DB::commit();

        $reports = $this->reporter->reports();

        self::assertCount(2, $reports);
        self::assertInstanceOf(AuditWriteFailedException::class, $reports[1]);
        self::assertSame('spill', $reports[1]->operation);
        self::assertHoldsNoSecret($reports, 'the reports');
    }

    /**
     * The callback a bound spill leaves on the transaction holds the failed
     * write sealed, so no trace shows the record.
     *
     * @return void
     */
    public function testABoundSpillHoldsTheRecordSealed(): void
    {
        $bound = $this->beginTransaction();

        $this->handle($this->failedWrite($this->failure(), hostOpen: true), FailureRule::REPORT, $bound);

        /** @var list<callable> $callbacks */
        $callbacks = $bound->getCallbacks();

        self::assertCount(1, $callbacks);
        self::assertHoldsNoSecret($callbacks, 'the bound callbacks');
    }

    /**
     * The report and the event go out at once, without waiting for the commit
     * the spill is bound to.
     *
     * @return void
     */
    public function testDiagnosticsDoNotWaitForTheCommit(): void
    {
        $bound = $this->beginTransaction();

        $this->handle($this->failedWrite($this->failure(), hostOpen: true), FailureRule::REPORT, $bound);

        self::assertSame(['report', 'event'], $this->stepNames());
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->events);
    }

    /**
     * A bound spill that fails at the commit stops no commit callback after it.
     *
     * @return void
     */
    public function testTheFirstCommitBoundFailureLeavesLaterCallbacksRunning(): void
    {
        $bound = $this->beginTransaction();
        $later = false;

        $this->handle($this->failedWrite($this->failure(), hostOpen: true), FailureRule::REPORT, $bound);

        $bound->addCallback(static function () use (&$later): void {
            $later = true;
        });

        $this->breakSpill(self::BROKEN);

        DB::commit();

        self::assertTrue($later);
    }

    /**
     * An aborted-transaction failure drops the bound spill, since PostgreSQL
     * rolls such a transaction back while reporting the commit a success.
     *
     * @return void
     */
    public function testAnAbortedHostDiscardsABoundSpill(): void
    {
        $bound = $this->beginTransaction();

        $this->handle($this->failedWrite($this->queryFailure('25P02', 7, 'current transaction is aborted'), hostOpen: true), FailureRule::REPORT, $bound);

        self::assertSame([], $bound->getCallbacks());

        DB::commit();

        self::assertSame([], $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->events);
    }

    /**
     * A rule that never spills binds nothing to the commit.
     *
     * @return void
     */
    public function testARuleThatNeverSpillsBindsNothing(): void
    {
        $bound = $this->beginTransaction();

        $this->thrownBy($this->failedWrite($this->failure(), hostOpen: true), FailureRule::THROW, $bound);

        self::assertSame([], $bound->getCallbacks());
    }

    /**
     * Rows of `[rule]`: every rule.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule}>
     */
    public static function provideRules(): iterable
    {
        yield from [
            'report'          => [FailureRule::REPORT],
            'spill and throw' => [FailureRule::SPILL_AND_THROW],
            'throw'           => [FailureRule::THROW],
        ];
    }

    /**
     * A deadlock while a transaction is open has ended that transaction, so it
     * propagates as the sanitised deadlock whatever the rule says.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @return void
     */
    #[DataProvider('provideRules')]
    public function testADeadlockInAHostTransactionPropagatesWhateverTheRule(FailureRule $rule): void
    {
        $this->beginTransaction();

        $thrown = $this->thrownBy($this->failedWrite($this->deadlock(), hostOpen: $this->isTransactionOpen()), $rule);

        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertSame('Deadlock found when trying to get lock; an audit write was abandoned inside the host transaction.', $thrown->getMessage());
        self::assertSame(40001, $thrown->getCode());
    }

    /**
     * The sanitised deadlock is what Laravel retries: the host's
     * `transaction()` runs its closure again, as it would for the original.
     *
     * @return void
     */
    public function testTheSanitisedDeadlockIsRecognisedByLaravel(): void
    {
        $attempts = 0;

        DB::transaction(function () use (&$attempts): void {
            $attempts++;

            if ($attempts > 1) {
                return;
            }

            $this->handle($this->failedWrite($this->deadlock(), hostOpen: $this->isTransactionOpen()), FailureRule::REPORT);
        }, 2);

        self::assertSame(2, $attempts);
        self::assertTrue((new FailureClassifier)->isConcurrencyError(FailureClassifier::sanitisedDeadlock()));
    }

    /**
     * The sanitised deadlock has no previous exception and holds nothing of the
     * original.
     *
     * @return void
     */
    public function testTheSanitisedDeadlockHasNoPrevious(): void
    {
        $this->beginTransaction();

        $thrown = $this->thrownBy($this->failedWrite($this->deadlock(), hostOpen: $this->isTransactionOpen()), FailureRule::REPORT);

        self::assertNull($thrown->getPrevious());
        self::assertHoldsNoSecret($thrown, 'the sanitised deadlock');
    }

    /**
     * A lost connection inside an open transaction ended it, so the sanitised
     * exception propagates whatever the rule.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @return void
     */
    #[DataProvider('provideRules')]
    public function testALostConnectionInAHostTransactionPropagatesWhateverTheRule(FailureRule $rule): void
    {
        $this->beginTransaction();

        $thrown = $this->thrownBy($this->failedWrite($this->lostConnection(), hostOpen: $this->isTransactionOpen()), $rule);

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame(QueryException::class, $thrown->exceptionClass);
        self::assertSame('HY000', $thrown->sqlState);
        self::assertNull($thrown->getPrevious());
        self::assertHoldsNoSecret($thrown, 'the thrown exception');
    }

    /**
     * A stack whose destination deadlocked is fatal to the open transaction,
     * read from the flag the stack kept.
     *
     * @return void
     */
    public function testAStackCarryingADeadlockIsHostFatal(): void
    {
        $failure = new StackDeliveryException('01932b4e-8a40-7000-8000-000000000001', ['database' => QueryException::class], true, false, false, []);

        $thrown = $this->thrownBy($this->failedWrite($failure, hostOpen: true), FailureRule::REPORT);

        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertSame([], $this->spillLines());
    }

    /**
     * A stack whose destination lost its connection is fatal to the open
     * transaction, and propagates as the sanitised exception.
     *
     * @return void
     */
    public function testAStackCarryingALostConnectionIsHostFatal(): void
    {
        $failure = new StackDeliveryException('01932b4e-8a40-7000-8000-000000000001', ['database' => QueryException::class], false, true, false, []);

        $thrown = $this->thrownBy($this->failedWrite($failure, hostOpen: true), FailureRule::REPORT);

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame(StackDeliveryException::class, $thrown->exceptionClass);
    }

    /**
     * A stack that flags neither follows the rule, even inside a transaction.
     *
     * @return void
     */
    public function testAStackFlaggingNeitherFollowsTheRule(): void
    {
        $failure = new StackDeliveryException('01932b4e-8a40-7000-8000-000000000001', ['database' => QueryException::class], false, false, false, []);

        $this->handle($this->failedWrite($failure, hostOpen: true), FailureRule::REPORT);

        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
    }

    /**
     * Rows of `[failure]`: each failure fatal to an open transaction.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideFatalFailures(): iterable
    {
        yield from [
            'a deadlock'        => [self::DEADLOCK],
            'a lost connection' => [self::LOST],
        ];
    }

    /**
     * A failure fatal to an open transaction is never spilled, even under the
     * `REPORT` rule, and is not reported, since it is thrown.
     *
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideFatalFailures')]
    public function testAHostFatalFailureIsNeverSpilled(string $message): void
    {
        $this->beginTransaction();

        $this->thrownBy($this->failedWrite($this->fatal($message), hostOpen: $this->isTransactionOpen()), FailureRule::REPORT);

        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * A failure fatal to an open transaction still dispatches the event.
     *
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideFatalFailures')]
    public function testAHostFatalFailureEmitsTheEvent(string $message): void
    {
        $this->beginTransaction();

        $this->thrownBy($this->failedWrite($this->fatal($message), hostOpen: $this->isTransactionOpen()), FailureRule::REPORT);

        self::assertSame(['event'], $this->stepNames());
        self::assertSame(QueryException::class, $this->events[0]->exception);
    }

    /**
     * With no transaction open a deadlock ended nothing, so it follows the
     * rule.
     *
     * @return void
     */
    public function testADeadlockWithNoHostTransactionFollowsTheRule(): void
    {
        $this->assertFollowsTheRule($this->deadlock());
    }

    /**
     * With no transaction open a lost connection ended nothing, so it follows
     * the rule.
     *
     * @return void
     */
    public function testALostConnectionWithNoHostTransactionFollowsTheRule(): void
    {
        $this->assertFollowsTheRule($this->lostConnection());
    }

    /**
     * A statement refused because a PostgreSQL transaction was already aborted
     * is not fatal in that sense: it follows the rule, spilled and reported.
     *
     * @return void
     */
    public function testAnAbortedHostFollowsTheRule(): void
    {
        $this->beginTransaction();

        $this->handle($this->failedWrite($this->queryFailure('25P02', 7, 'current transaction is aborted'), hostOpen: $this->isTransactionOpen()), FailureRule::REPORT);

        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
        self::assertSame('store', $this->firstReport()->operation);
        self::assertSame('25P02', $this->firstReport()->sqlState);
    }

    /**
     * Rows of `[step]`: each step that can deadlock.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSteps(): iterable
    {
        yield from [
            'a deadlocking spill channel' => ['spill'],
            'a deadlocking reporter'      => ['report'],
            'a deadlocking listener'      => ['event'],
        ];
    }

    /**
     * A step that deadlocks inside an open transaction propagates its sanitised
     * deadlock even under `REPORT`, and is not also reported.
     *
     * @param  string  $step
     * @return void
     */
    #[DataProvider('provideSteps')]
    public function testAHostFatalSecondaryFailurePropagatesSanitised(string $step): void
    {
        $this->breakStep($step, self::DEADLOCK);
        $this->beginTransaction();

        $thrown = $this->thrownBy($this->failedWrite($this->failure(), hostOpen: $this->isTransactionOpen()), FailureRule::REPORT);

        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertNull($thrown->getPrevious());
        self::assertSame(['store'], $this->reportedOperations());
        self::assertHoldsNoSecret($thrown, 'the sanitised deadlock');
    }

    /**
     * A step that loses its connection while a transaction is open propagates
     * the sanitised exception of its own failure.
     *
     * @return void
     */
    public function testAHostLostConnectionInAStepPropagatesSanitised(): void
    {
        $this->listenerFailure = self::LOST;

        $thrown = $this->thrownBy($this->failedWrite($this->failure(), hostOpen: true), FailureRule::REPORT);

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame('notify', $thrown->operation);
        self::assertSame(\PDOException::class, $thrown->exceptionClass);
        self::assertSame(['store'], $this->reportedOperations());
        self::assertHoldsNoSecret($thrown, 'the thrown exception');
    }

    /**
     * A step that deadlocks while a transaction is open stops no later step:
     * the report and the event still run before the deadlock is thrown.
     *
     * @return void
     */
    public function testAHostFatalSecondaryFailureStillLetsTheOtherStepsRun(): void
    {
        $this->breakSpill(self::DEADLOCK);

        $this->thrownBy($this->failedWrite($this->failure(), hostOpen: true), FailureRule::REPORT);

        self::assertSame(['report', 'event'], $this->stepNames());
        self::assertSame(['store'], $this->reportedOperations());
    }

    /**
     * The write's own failure, fatal to the open transaction, is what is
     * thrown, before any step's.
     *
     * @return void
     */
    public function testTheWritesOwnFatalFailureIsThrownBeforeAStepsOwn(): void
    {
        $this->listenerFailure = self::DEADLOCK;

        $thrown = $this->thrownBy($this->failedWrite($this->lostConnection(), hostOpen: true), FailureRule::REPORT);

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame('store', $thrown->operation);
    }

    /**
     * Of two steps fatal to the open transaction, the first to fail is the one
     * thrown.
     *
     * @return void
     */
    public function testTheFirstFatalStepIsTheOneThrown(): void
    {
        $this->breakSpill(self::DEADLOCK);

        $this->listenerFailure = self::LOST;

        $thrown = $this->thrownBy($this->failedWrite($this->failure(), hostOpen: true), FailureRule::SPILL_AND_THROW);

        self::assertInstanceOf(DeadlockException::class, $thrown);
    }

    /**
     * A step's failure fatal to an open transaction is thrown in place of the
     * write's own sanitised exception.
     *
     * @return void
     */
    public function testAFatalStepIsThrownInPlaceOfTheRulesException(): void
    {
        $this->breakSpill(self::DEADLOCK);

        $thrown = $this->thrownBy($this->failedWrite($this->failure(), hostOpen: true), FailureRule::SPILL_AND_THROW);

        self::assertInstanceOf(DeadlockException::class, $thrown);
    }

    /**
     * With no transaction open a step's deadlock ended nothing, so it is
     * reported and goes no further.
     *
     * @return void
     */
    public function testASecondaryDeadlockWithNoHostTransactionIsContained(): void
    {
        $this->listenerFailure = self::DEADLOCK;

        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT);

        self::assertSame(['store', 'notify'], $this->reportedOperations());
    }

    /**
     * Each step runs inside the write guard, so a record made from inside one
     * is refused rather than written.
     *
     * @param  string  $step
     * @return void
     */
    #[DataProvider('provideSteps')]
    public function testTheGuardIsActiveInEachStep(string $step): void
    {
        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT);

        self::assertContains([$step, true], $this->steps);
        self::assertNotContains([$step, false], $this->steps);
    }

    /**
     * A spill bound to a commit runs inside the write guard when the commit
     * runs it, though the failure path has long ended.
     *
     * @return void
     */
    public function testTheGuardIsActiveInABoundSpill(): void
    {
        $bound = $this->beginTransaction();

        $this->handle($this->failedWrite($this->failure(), hostOpen: true), FailureRule::REPORT, $bound);

        self::assertFalse($this->guard()->isActive());

        DB::commit();

        self::assertContains(['spill', true], $this->steps);
        self::assertFalse($this->guard()->isActive());
    }

    /**
     * The guard is released once the failure path ends, so a later record is
     * written.
     *
     * @return void
     */
    public function testTheGuardIsReleasedAfterTheFailurePath(): void
    {
        $this->breakEveryStep();

        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT);

        self::assertFalse($this->guard()->isActive());
    }

    /**
     * The guard is released when the handler throws, whatever it throws.
     *
     * @return void
     */
    public function testTheGuardIsReleasedWhenTheHandlerThrows(): void
    {
        $this->thrownBy($this->failedWrite($this->failure()), FailureRule::SPILL_AND_THROW);

        self::assertFalse($this->guard()->isActive());

        $this->thrownBy($this->failedWrite($this->deadlock(), hostOpen: true), FailureRule::REPORT);

        self::assertFalse($this->guard()->isActive());
    }

    /**
     * Every handler parameter holding the record, a failure, an exception or a
     * closure capturing either is marked sensitive.
     *
     * @return void
     */
    public function testEveryPayloadParameterIsMarkedSensitive(): void
    {
        $checked = 0;

        foreach ((new \ReflectionClass(FailureHandler::class))->getMethods() as $method) {
            foreach ($method->getParameters() as $parameter) {
                $type = $parameter->getType();
                $name = $type instanceof \ReflectionNamedType ? $type->getName() : '';

                if (!in_array($name, [FailedWrite::class, \Throwable::class, AuditWriteFailedException::class, \Closure::class], true)) {
                    continue;
                }

                $checked++;

                self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class), "{$method->getName()}() does not mark \${$parameter->getName()} sensitive.");
            }
        }

        self::assertGreaterThanOrEqual(14, $checked);
    }

    /**
     * A stack's failure names each destination that failed, in the report and
     * in what is thrown, since in sync mode nothing else records which it was.
     *
     * @return void
     */
    public function testAStackFailureNamesItsDestinations(): void
    {
        $failures = ['siem' => \RuntimeException::class, 'archive' => \LogicException::class];
        $failure  = new StackDeliveryException('01932b4e-8a40-7000-8000-000000000001', $failures, false, false, false, []);

        $this->handle($this->failedWrite($failure), FailureRule::REPORT);

        $reported = $this->reporter->reports()[0];

        self::assertInstanceOf(AuditWriteFailedException::class, $reported);
        self::assertSame('siem,archive', $reported->destination);
        self::assertStringContainsString('destination siem,archive', $reported->getMessage());

        $thrown = $this->thrownBy($this->failedWrite($failure), FailureRule::SPILL_AND_THROW);

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame('siem,archive', $thrown->destination);
    }

    /**
     * A failure that is no stack's names no destination.
     *
     * @return void
     */
    public function testAnyOtherFailureNamesNoDestination(): void
    {
        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT);

        $reported = $this->reporter->reports()[0];

        self::assertInstanceOf(AuditWriteFailedException::class, $reported);
        self::assertNull($reported->destination);
    }

    /**
     * A stack hiding an aborted host still discards the bound spill, since
     * replaying it would bring back work PostgreSQL rolled back.
     *
     * @return void
     */
    public function testAStackCarryingAnAbortedHostDiscardsABoundSpill(): void
    {
        $bound   = $this->beginTransaction();
        $failure = new StackDeliveryException('01932b4e-8a40-7000-8000-000000000001', ['database' => QueryException::class], false, false, true, []);

        $this->handle($this->failedWrite($failure, hostOpen: true), FailureRule::REPORT, $bound);

        self::assertSame([], $bound->getCallbacks());

        DB::commit();

        self::assertSame([], $this->spillLines());
        self::assertSame(['store'], $this->reportedOperations());
    }

    /**
     * A stack's concurrency error on a connection with no transaction open
     * ended nothing there, so the record follows the rule.
     *
     * @return void
     */
    public function testAStackDeadlockOnAnotherConnectionFollowsTheRule(): void
    {
        $failure = new StackDeliveryException('01932b4e-8a40-7000-8000-000000000001', ['database' => QueryException::class], true, false, false, ['audit']);

        $this->handle($this->failedWrite($failure, hostOpen: true), FailureRule::REPORT);

        self::assertCount(1, $this->spillLines());
        self::assertSame(['store'], $this->reportedOperations());
    }

    /**
     * The write's own deadlock on another connection than the one holding a
     * transaction ended nothing there, so it follows the rule.
     *
     * @return void
     */
    public function testADeadlockOnAConnectionWithNoTransactionFollowsTheRule(): void
    {
        $failure = new QueryException('audit', 'insert into entries values (?)', ['x'], new \PDOException(self::DEADLOCK));

        $this->handle($this->failedWrite($failure, hostOpen: true), FailureRule::REPORT);

        self::assertCount(1, $this->spillLines());
        self::assertSame(['store'], $this->reportedOperations());
    }

    /**
     * A listener's deadlock on the host's connection ended the host's
     * transaction, so it propagates though the write was on another connection.
     *
     * @return void
     */
    public function testAStepFailingOnTheHostsConnectionPropagatesFromADedicatedStore(): void
    {
        Event::listen(AuditWriteFailed::class, static function (): never {
            throw new QueryException('host', 'update hosts set x = 1', [], new \PDOException(self::DEADLOCK));
        });

        $thrown = $this->thrownBy($this->failedWriteOpenOn('host'), FailureRule::REPORT);

        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertNull($thrown->getPrevious());
    }

    /**
     * The same listener's deadlock on a connection with no transaction open
     * ended nothing, so it is reported and contained.
     *
     * @return void
     */
    public function testAStepFailingOnAnIdleConnectionIsContained(): void
    {
        Event::listen(AuditWriteFailed::class, static function (): never {
            throw new QueryException('idle', 'update hosts set x = 1', [], new \PDOException(self::DEADLOCK));
        });

        $this->handle($this->failedWriteOpenOn('host'), FailureRule::REPORT);

        self::assertSame(['store', 'notify'], $this->reportedOperations());
    }

    /**
     * A step's failure naming no connection is assumed to have touched what is
     * open: nothing else could say otherwise, and containing it is the harm.
     *
     * @return void
     */
    public function testAStepFailingWithNoConnectionNamedCountsForAnyOpen(): void
    {
        $this->listenerFailure = self::DEADLOCK;

        $thrown = $this->thrownBy($this->failedWriteOpenOn('host'), FailureRule::REPORT);

        self::assertInstanceOf(DeadlockException::class, $thrown);
    }

    /**
     * A spill channel or listener raising one of Laravel's phrases without a
     * database failure ended no transaction, so it is only reported.
     *
     * @return void
     */
    public function testAPhraseOutsideTheDatabaseIsContainedInAStep(): void
    {
        $this->breakStep('spill', 'Failed to open stream: No such file or directory');

        $this->handle($this->failedWrite($this->failure(), hostOpen: true), FailureRule::REPORT);

        self::assertSame(['spill', 'store'], $this->reportedOperations());
    }

    /**
     * A store raising a phrase that is no database failure leaves the spill and
     * the report to do their work, inside a host too.
     *
     * @return void
     */
    public function testAStoreRaisingAPhraseOutsideTheDatabaseFollowsTheRule(): void
    {
        $failure = new \RuntimeException('cURL error 56: Recv failure: Connection reset by peer');

        $this->handle($this->failedWrite($failure, hostOpen: true), FailureRule::REPORT);

        self::assertCount(1, $this->spillLines());
        self::assertSame(['store'], $this->reportedOperations());
    }

    /**
     * A reporter that deadlocks while a host is open has ended that host, so it
     * propagates once the other steps have run.
     *
     * @return void
     */
    public function testAReporterFailingOverAStepsFailurePropagates(): void
    {
        $this->listenerFailure      = 'The listener failed.';
        $this->reporterFailure      = self::DEADLOCK;
        $this->reportsBeforeFailing = 1;

        $thrown = $this->thrownBy($this->failedWrite($this->failure(), hostOpen: true), FailureRule::REPORT);

        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertNull($thrown->getPrevious());
        self::assertCount(1, $this->events);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * A bound spill runs after the commit, so nothing it raises can propagate,
     * its reporter's failure included.
     *
     * @return void
     */
    public function testAReporterFailingOverABoundSpillGoesNoFurther(): void
    {
        $bound = $this->beginTransaction();

        $this->handle($this->failedWrite($this->failure(), hostOpen: true), FailureRule::REPORT, $bound);

        $this->breakStep('spill', 'The channel failed');

        $this->reporterFailure      = self::DEADLOCK;
        $this->reportsBeforeFailing = 1;

        DB::commit();

        self::assertSame(0, DB::transactionLevel());
    }

    /**
     * A reporter that fails with nothing open ended nothing, so it stays
     * ignored.
     *
     * @return void
     */
    public function testAReporterFailingWithNothingOpenStaysIgnored(): void
    {
        $this->listenerFailure      = 'The listener failed.';
        $this->reporterFailure      = self::DEADLOCK;
        $this->reportsBeforeFailing = 1;

        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT);

        self::assertCount(1, $this->events);
    }

    /**
     * A deferred write dropped because its commit proved a rollback writes,
     * spills and dispatches nothing, and is reported with its SQLSTATE.
     *
     * @return void
     */
    public function testAbandoningAWriteOnlyReportsIt(): void
    {
        $previous = new \PDOException('SQLSTATE[25P02]: In failed sql transaction');

        $previous->errorInfo = ['25P02', 7, ''];

        $aborted = new QueryException(self::CONNECTION, 'select 1', [], $previous);
        $record  = $this->record();

        (new FailureHandler(app()))->abandon($record, $aborted, FailedOperation::STORE, self::STORE);

        $reported = $this->reporter->reports()[0];

        self::assertInstanceOf(AuditWriteFailedException::class, $reported);
        self::assertSame($record->id, $reported->recordId);
        self::assertSame('25P02', $reported->sqlState);
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->events);
        self::assertHoldsNoSecret($reported, 'the report');
    }

    /**
     * A reporter that fails over an abandoned write throws nothing, since a
     * commit callback must not throw for work that was undone.
     *
     * @return void
     */
    public function testAbandoningAWriteWithABrokenReporterThrowsNothing(): void
    {
        $this->reporterFailure = 'The reporter failed.';

        (new FailureHandler(app()))->abandon($this->record(), new \PDOException('Aborted.'), FailedOperation::STORE, self::STORE);

        self::assertFalse($this->guard()->isActive());
    }

    /**
     * A capture's failed write is spilled, reported and said once under
     * `REPORT`, then its signal is told, not as fatal.
     *
     * @return void
     */
    public function testACaptureIsSpilledReportedAndSignalledOnce(): void
    {
        $signal = $this->signal();

        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT, null, $signal);

        self::assertSame(['spill', 'report', 'event', 'signal'], $this->stepNames());
        self::assertCount(1, $this->spillLines());
        self::assertSame(['store'], $this->reportedOperations());
        self::assertCount(1, $this->events);
        self::assertSame([QueryException::class], $this->signalled);
        self::assertTrue($signal->hasFailed());
        self::assertFalse($signal->isFatal());
        self::assertSame(QueryException::class, $signal->exceptionClass());
    }

    /**
     * The signal is told outside the write guard, after it is released, so what
     * the capture does with it is the capture's to guard.
     *
     * @return void
     */
    public function testTheSignalIsToldOutsideTheGuard(): void
    {
        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT, null, $this->signal());

        self::assertSame([['signal', false]], array_slice($this->steps, -1));
    }

    /**
     * A synchronous capture's failure fatal to the open transaction is thrown
     * sanitised, never spilled or reported, and signalled as fatal.
     *
     * @return void
     */
    public function testASynchronousCapturesFatalFailureIsThrownAndSignalledFatal(): void
    {
        $signal = $this->signal();

        $this->beginTransaction();

        $thrown = $this->thrownBy($this->failedWrite($this->deadlock(), hostOpen: $this->isTransactionOpen()), FailureRule::REPORT, null, $signal);

        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertNull($thrown->getPrevious());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
        self::assertCount(1, $this->events);
        self::assertSame([QueryException::class], $this->signalled);
        self::assertTrue($signal->isFatal());
    }

    /**
     * A deferred capture's fatal failure runs after the capture returned, so it
     * is spilled and reported inside the write guard, never thrown.
     *
     * @return void
     */
    public function testADeferredCapturesFatalFailureIsReportedAndSignalled(): void
    {
        $signal = $this->signal();

        $signal->defer();

        $this->beginTransaction();

        $this->handle($this->failedWrite($this->deadlock(), hostOpen: $this->isTransactionOpen()), FailureRule::REPORT, null, $signal);

        $reports = $this->reporter->reports();

        self::assertCount(1, $reports);
        self::assertInstanceOf(DeadlockException::class, $reports[0]);
        self::assertNull($reports[0]->getPrevious());
        self::assertSame(['spill', 'event', 'signal', 'report'], $this->stepNames());
        self::assertTrue($this->steps[0][1], 'The spill runs inside the write guard.');
        self::assertTrue($this->steps[3][1], 'The report runs inside the write guard.');
        self::assertCount(1, $this->spillLines());
        self::assertSame([QueryException::class], $this->signalled);
        self::assertFalse($signal->isFatal());
        self::assertFalse($this->guard()->isActive());
        self::assertHoldsNoSecret($reports, 'the reports');
    }

    /**
     * A deferred capture's failed spill is reported and goes no further, since
     * nothing may leave the commit callback.
     *
     * @return void
     */
    public function testADeferredCapturesFailedSpillIsReportedAndNeverThrown(): void
    {
        $signal = $this->signal();

        $signal->defer();

        $this->breakSpill(self::DEADLOCK);

        $this->handle($this->failedWrite($this->deadlock(), hostOpen: true), FailureRule::REPORT, null, $signal);

        self::assertSame(['spill', DeadlockException::class], $this->reportedOperations());
        self::assertSame([], $this->spillLines());
        self::assertSame([QueryException::class], $this->signalled);
        self::assertFalse($this->guard()->isActive());
    }

    /**
     * A deferred capture's lost connection is reported as the sanitised
     * exception of the write, never thrown.
     *
     * @return void
     */
    public function testADeferredCapturesLostConnectionIsReportedAndSignalled(): void
    {
        $signal = $this->signal();

        $signal->defer();

        $this->handle($this->failedWrite($this->lostConnection(), hostOpen: true), FailureRule::REPORT, null, $signal);

        self::assertSame(['store'], $this->reportedOperations());
        self::assertSame(QueryException::class, $this->firstReport()->exceptionClass);
        self::assertSame([QueryException::class], $this->signalled);
    }

    /**
     * A deferred capture's step that deadlocks while a transaction is open is
     * reported too, after the write's own failure, and never thrown.
     *
     * @return void
     */
    public function testADeferredCapturesFatalStepIsReportedAndNeverThrown(): void
    {
        $signal = $this->signal();

        $signal->defer();

        $this->listenerFailure = self::DEADLOCK;

        $this->handle($this->failedWrite($this->failure(), hostOpen: true), FailureRule::REPORT, null, $signal);

        self::assertSame(['store', DeadlockException::class], $this->reportedOperations());
        self::assertSame([QueryException::class], $this->signalled);
        self::assertFalse($signal->isFatal());
    }

    /**
     * A reporter that fails over a deferred capture's fatal failure is ignored:
     * nothing may leave a commit callback.
     *
     * @return void
     */
    public function testADeferredCapturesBrokenReporterThrowsNothing(): void
    {
        $signal = $this->signal();

        $signal->defer();

        $this->reporterFailure = self::DEADLOCK;

        $this->handle($this->failedWrite($this->deadlock(), hostOpen: true), FailureRule::REPORT, null, $signal);

        self::assertCount(1, $this->reporter->reports());
        self::assertTrue($signal->hasFailed());
        self::assertFalse($this->guard()->isActive());
    }

    /**
     * A deferred capture whose failure is not fatal follows the rule as any
     * other: reported once, by the step, and not again.
     *
     * @return void
     */
    public function testADeferredCapturesOrdinaryFailureIsReportedOnce(): void
    {
        $signal = $this->signal();

        $signal->defer();

        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT, null, $signal);

        self::assertSame(['store'], $this->reportedOperations());
        self::assertCount(1, $this->spillLines());
        self::assertSame([QueryException::class], $this->signalled);
    }

    /**
     * A signal whose callback throws stops no step, and nothing escapes under
     * the `REPORT` rule.
     *
     * @return void
     */
    public function testAThrowingSignalCallbackStopsNoStep(): void
    {
        $this->signalFails = true;

        $signal = $this->signal();

        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT, null, $signal);

        self::assertSame(['spill', 'report', 'event', 'signal'], $this->stepNames());
        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->events);
        self::assertTrue($signal->hasFailed());
    }

    /**
     * A signal whose callback throws does not stop a synchronous capture's
     * fatal failure from being thrown, sanitised, in place of the callback's.
     *
     * @return void
     */
    public function testAThrowingSignalCallbackLeavesAFatalFailureThrown(): void
    {
        $this->signalFails = true;

        $thrown = $this->thrownBy($this->failedWrite($this->deadlock(), hostOpen: true), FailureRule::REPORT, null, $this->signal());

        self::assertInstanceOf(DeadlockException::class, $thrown);
    }

    /**
     * A signal already told keeps its first failure: a second failed write of
     * the same capture tells it nothing more.
     *
     * @return void
     */
    public function testASignalIsToldOnlyOnce(): void
    {
        $signal = $this->signal();

        $this->handle($this->failedWrite($this->failure()), FailureRule::REPORT, null, $signal);
        $this->handle($this->failedWrite(new \RuntimeException('Another failure.')), FailureRule::REPORT, null, $signal);

        self::assertSame([QueryException::class], $this->signalled);
        self::assertSame(QueryException::class, $signal->exceptionClass());
    }

    /**
     * What a deferred capture's write lets out beyond the failure path is
     * reported once, payload-free, and signalled; nothing is spilled or said.
     *
     * @return void
     */
    public function testContainingAnEscapedFailureReportsAndSignals(): void
    {
        $signal = $this->signal();
        $record = $this->record();

        (new FailureHandler(app()))->contain($record, $this->deadlock(), FailedOperation::STORE, self::STORE, $signal);

        $report = $this->firstReport();

        self::assertCount(1, $this->reporter->reports());
        self::assertSame($record->id, $report->recordId);
        self::assertSame(QueryException::class, $report->exceptionClass);
        self::assertSame('store', $report->operation);
        self::assertSame(self::STORE, $report->store);
        self::assertNull($report->getPrevious());
        self::assertSame([QueryException::class], $this->signalled);
        self::assertFalse($signal->isFatal());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->events);
        self::assertHoldsNoSecret($report, 'the report');
    }

    /**
     * Containing an escaped failure with a broken reporter throws nothing, and
     * still tells the signal.
     *
     * @return void
     */
    public function testContainingAnEscapedFailureWithABrokenReporterThrowsNothing(): void
    {
        $this->reporterFailure = self::DEADLOCK;

        $signal = $this->signal();

        (new FailureHandler(app()))->contain($this->record(), new \RuntimeException('Escaped.'), FailedOperation::STORE, self::STORE, $signal);

        self::assertSame([\RuntimeException::class], $this->signalled);
        self::assertFalse($this->guard()->isActive());
    }

    /**
     * The report of an escaped failure runs inside the write guard.
     *
     * @return void
     */
    public function testContainingAnEscapedFailureReportsInsideTheGuard(): void
    {
        (new FailureHandler(app()))->contain($this->record(), new \RuntimeException('Escaped.'), FailedOperation::STORE, self::STORE, $this->signal());

        self::assertSame([['report', true], ['signal', false]], $this->steps);
    }

    /**
     * Spill to a channel that writes nowhere.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('logging.channels.' . self::SPILL_CHANNEL, ['driver' => 'monolog', 'handler' => NullHandler::class]);
        $config->set('audit-log.failure.log_channel', self::SPILL_CHANNEL);
    }

    /**
     * Assert the failure, with no transaction open, is spilled and reported
     * under `REPORT` and spilled and thrown under `SPILL_AND_THROW`.
     *
     * @param  \Illuminate\Database\QueryException  $failure
     * @return void
     */
    private function assertFollowsTheRule(QueryException $failure): void
    {
        $this->handle($this->failedWrite($failure), FailureRule::REPORT);

        self::assertCount(1, $this->spillLines());
        self::assertSame(['store'], $this->reportedOperations());

        $this->captureLogLines();

        $thrown = $this->thrownBy($this->failedWrite($failure), FailureRule::SPILL_AND_THROW);

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame(QueryException::class, $thrown->exceptionClass);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * Handle the failed write under the rule, bound to the commit given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\FailedWrite  $failed
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  ?\Illuminate\Database\DatabaseTransactionRecord  $commitBound
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function handle(FailedWrite $failed, FailureRule $rule, ?DatabaseTransactionRecord $commitBound = null, ?CaptureSignal $capture = null): void
    {
        (new FailureHandler(app()))->handle($failed, $rule, $commitBound, $capture);
    }

    /**
     * What handling the failed write under the rule throws; it must throw.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\FailedWrite  $failed
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  ?\Illuminate\Database\DatabaseTransactionRecord  $commitBound
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @return \RuntimeException
     */
    private function thrownBy(FailedWrite $failed, FailureRule $rule, ?DatabaseTransactionRecord $commitBound = null, ?CaptureSignal $capture = null): \RuntimeException
    {
        try {
            $this->handle($failed, $rule, $commitBound, $capture);
        } catch (\RuntimeException $thrown) {
            return $thrown;
        }

        self::fail('Expected the failed write to be thrown.');
    }

    /**
     * A failed write of a record whose properties hold the secret, finalised
     * unless told otherwise, on the worker's connection.
     *
     * @param  \Throwable  $failure
     * @param  bool  $hostOpen
     * @param  bool  $finalised
     * @return \SineMacula\Laravel\AuditLog\Delivery\FailedWrite
     */
    private function failedWrite(\Throwable $failure, bool $hostOpen = false, bool $finalised = true): FailedWrite
    {
        $record = $this->record();

        return new FailedWrite($record, $finalised ? $this->finaliser()->finalise($record) : null, $failure, FailedOperation::STORE, self::STORE, self::CONNECTION, $hostOpen);
    }

    /**
     * A failed write on a dedicated audit connection, with no transaction open
     * there, while a transaction is open on the connection named.
     *
     * @param  string  $host
     * @return \SineMacula\Laravel\AuditLog\Delivery\FailedWrite
     */
    private function failedWriteOpenOn(string $host): FailedWrite
    {
        $record = $this->record();

        return new FailedWrite($record, $this->finaliser()->finalise($record), $this->failure(), FailedOperation::STORE, self::STORE, 'audit', false, [$host]);
    }

    /**
     * A captured record whose properties hold the secret.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function record(): AuditRecord
    {
        return RecordFactory::captured(['note' => self::SECRET]);
    }

    /**
     * A duplicate-key failure whose message and bindings hold the secret, as
     * Laravel throws it: neither a concurrency error nor a lost connection.
     *
     * @return \Illuminate\Database\QueryException
     */
    private function failure(): QueryException
    {
        return $this->queryFailure('23000', 1062, 'Duplicate entry');
    }

    /**
     * A deadlock whose message and bindings hold the secret, as Laravel throws
     * it.
     *
     * @return \Illuminate\Database\QueryException
     */
    private function deadlock(): QueryException
    {
        return $this->fatal(self::DEADLOCK);
    }

    /**
     * A lost connection whose message and bindings hold the secret, as Laravel
     * throws it.
     *
     * @return \Illuminate\Database\QueryException
     */
    private function lostConnection(): QueryException
    {
        return $this->fatal(self::LOST);
    }

    /**
     * The deadlock or the lost connection the message describes.
     *
     * @param  string  $message
     * @return \Illuminate\Database\QueryException
     */
    private function fatal(string $message): QueryException
    {
        return $message === self::DEADLOCK
            ? $this->queryFailure('40001', 1213, $message)
            : $this->queryFailure('HY000', 2006, $message);
    }

    /**
     * A query failure with the SQLSTATE and driver code, whose message and
     * bindings hold the secret.
     *
     * @param  string  $state
     * @param  int  $code
     * @param  string  $message
     * @return \Illuminate\Database\QueryException
     */
    private function queryFailure(string $state, int $code, string $message): QueryException
    {
        $previous = new \PDOException($message . ' ' . self::SECRET);

        $previous->errorInfo = [$state, $code, $message . ' ' . self::SECRET];

        return new QueryException(self::CONNECTION, 'insert into "audit_log_entries" ("note") values (?)', [self::SECRET], $previous);
    }

    /**
     * Open a transaction on the worker's connection and return its record, the
     * one a spill binds to.
     *
     * @return \Illuminate\Database\DatabaseTransactionRecord
     */
    private function beginTransaction(): DatabaseTransactionRecord
    {
        DB::beginTransaction();

        $manager = app('db.transactions');

        self::assertInstanceOf(DatabaseTransactionsManager::class, $manager);

        $record = $manager->callbackApplicableTransactions()->last();

        self::assertInstanceOf(DatabaseTransactionRecord::class, $record);

        return $record;
    }

    /**
     * Whether a transaction is open on the worker's connection.
     *
     * @return bool
     */
    private function isTransactionOpen(): bool
    {
        return DB::transactionLevel() > 0;
    }

    /**
     * A capture's signal that notes when it is told and the class it passes on,
     * then fails when a test has said so.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\CaptureSignal
     */
    private function signal(): CaptureSignal
    {
        return new CaptureSignal(function (string $exceptionClass): void {
            $this->steps[]     = ['signal', $this->guard()->isActive()];
            $this->signalled[] = $exceptionClass;

            if ($this->signalFails) {
                throw new \RuntimeException('The capture failed to say so: ' . self::SECRET);
            }
        });
    }

    /**
     * The shared write guard.
     *
     * @return \SineMacula\Laravel\AuditLog\Runtime\WriteGuard
     */
    private function guard(): WriteGuard
    {
        return app(WriteGuard::class);
    }

    /**
     * Make the step fail with the message: the spill, the reporter or a
     * listener.
     *
     * @param  string  $step
     * @param  string  $message
     * @return void
     */
    private function breakStep(string $step, string $message): void
    {
        if ($step === 'spill') {

            $this->breakSpill($message);

            return;
        }

        if ($step === 'report') {

            $this->reporterFailure = $message;

            return;
        }

        $this->listenerFailure = $message;
    }

    /**
     * Make the spill fail through a channel whose handler throws the message
     * and the secret.
     *
     * @param  string  $message
     * @return void
     */
    private function breakSpill(string $message): void
    {
        $config = app(ConfigRepository::class);

        $config->set('logging.channels.' . self::BROKEN_CHANNEL, ThrowingLogHandler::channel($message));
        $config->set('audit-log.failure.log_channel', self::BROKEN_CHANNEL);
    }

    /**
     * Make the spill, the reporter and a listener all fail.
     *
     * @return void
     */
    private function breakEveryStep(): void
    {
        $this->breakSpill(self::BROKEN);

        $this->reporterFailure = self::BROKEN;
        $this->listenerFailure = self::BROKEN;
    }

    /**
     * The names of the steps that ran, in order.
     *
     * @return list<string>
     */
    private function stepNames(): array
    {
        return array_map(static fn (array $step): string => $step[0], $this->steps);
    }

    /**
     * The operation each report names, in order; a report that is not the
     * sanitised exception is named by its class.
     *
     * @return list<string>
     */
    private function reportedOperations(): array
    {
        return array_map(
            static fn (\Throwable $report): string => $report instanceof AuditWriteFailedException ? $report->operation : $report::class,
            $this->reporter->reports(),
        );
    }

    /**
     * The first report, which must be the sanitised exception.
     *
     * @return \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function firstReport(): AuditWriteFailedException
    {
        $report = $this->reporter->reports()[0] ?? null;

        self::assertInstanceOf(AuditWriteFailedException::class, $report);

        return $report;
    }

    /**
     * Bind a reporter that notes the step, hands the exception to the recording
     * reporter, then fails when a test has said so.
     *
     * @return void
     */
    private function bindReporter(): void
    {
        $report = function (\Throwable $exception): void {
            $this->steps[] = ['report', $this->guard()->isActive()];

            $this->reporter->report($exception);

            if ($this->reporterFailure !== null && count($this->reporter->reports()) > $this->reportsBeforeFailing) {
                throw new \RuntimeException($this->reporterFailure . ': ' . self::SECRET);
            }
        };

        $this->app?->instance(ExceptionHandler::class, new class ($report) implements ExceptionHandler {
            /**
             * Constructor.
             *
             * @param  \Closure(\Throwable): void  $report
             */
            public function __construct(

                /** What reporting an exception does. */
                private readonly \Closure $report,
            ) {}

            /**
             * Report the exception through the closure.
             *
             * @param  \Throwable  $e
             * @return void
             */
            #[\Override]
            public function report(\Throwable $e): void
            {
                ($this->report)($e);
            }

            /**
             * Report everything.
             *
             * @param  \Throwable  $e
             * @return bool
             */
            #[\Override]
            public function shouldReport(\Throwable $e): bool
            {
                return true;
            }

            /**
             * Render a bare response.
             *
             * @param  mixed  $request
             * @param  \Throwable  $e
             * @return \Symfony\Component\HttpFoundation\Response
             */
            #[\Override]
            public function render(mixed $request, \Throwable $e): Response
            {
                return new Response('', 500);
            }

            /**
             * Render nothing to the console.
             *
             * @param  mixed  $output
             * @param  \Throwable  $e
             * @return void
             */
            #[\Override]
            public function renderForConsole(mixed $output, \Throwable $e): void {}
        });
    }
}
