<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Illuminate\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Delivery\RecordedNotifier;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Runtime\ReadGuard;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for the notifier that dispatches `AuditRecorded` and contains
 * or rethrows its listeners' failures.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordedNotifier::class)]
final class RecordedNotifierTest extends TestCase
{
    use SearchesForSecrets;

    /** @var string The id the notifications name. */
    private const string ID = '0195f4a2-7b1c-7000-8000-000000000001';

    /** @var string The code the notifications name. */
    private const string CODE = 'invoice.approved';

    /** @var string The category the notifications name. */
    private const string CATEGORY = 'finance';

    /** @var string A package code, under the reserved prefix. */
    private const string PACKAGE_CODE = 'audit_log.trail_read';

    /** @var string A driver's message of a deadlock. */
    private const string DEADLOCK = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock';

    /** @var string A driver's message of a lost connection. */
    private const string LOST_CONNECTION = 'SQLSTATE[HY000]: General error: 2006 MySQL server has gone away';

    /**
     * The event is dispatched once, carrying the id, the code and the category.
     *
     * @return void
     */
    public function testDispatchesAuditRecorded(): void
    {
        Event::fake([AuditRecorded::class]);

        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY);

        Event::assertDispatchedTimes(AuditRecorded::class, 1);
        Event::assertDispatched(AuditRecorded::class, static fn (AuditRecorded $event): bool => $event->id === self::ID
            && $event->code                                                                                === self::CODE
            && $event->category                                                                            === self::CATEGORY);
    }

    /**
     * A listener's exception is reported, the very exception, and goes no
     * further.
     *
     * @return void
     */
    public function testAThrowingListenerIsReportedAndContained(): void
    {
        $handler   = $this->recordingHandler();
        $exception = new \RuntimeException('The listener failed.');

        $this->listenerThrows($exception);

        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY);

        self::assertSame([$exception], $handler->reports());
    }

    /**
     * A reporter that throws as well goes no further either.
     *
     * @return void
     */
    public function testAThrowingReporterIsContained(): void
    {
        $handler = $this->recordingHandler(throwsOnReport: true);

        $this->listenerThrows(new \RuntimeException('The listener failed.'));

        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY);

        self::assertCount(1, $handler->reports());
    }

    /**
     * A reporter that records an event whose listener fails again is reported
     * to once, the latch dropping the second report.
     *
     * @return void
     */
    public function testAReporterRecordingOnAListenerFailureDoesNotLoop(): void
    {
        $reports = 0;
        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report')->andReturnUsing(function () use (&$reports): void {
            $reports++;

            if ($reports > 5) {
                self::fail('The reporter was called in a loop.');
            }

            $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY);
        });

        app()->instance(ExceptionHandler::class, $handler);

        $this->listenerThrows(new \RuntimeException('The listener failed.'));

        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY);

        self::assertSame(1, $reports);
    }

    /**
     * The latch lets go once a report ends, so a later listener failure is
     * reported too.
     *
     * @return void
     */
    public function testEachSeparateFailureIsReported(): void
    {
        $handler = $this->recordingHandler();

        $this->listenerThrows(new \RuntimeException('The listener failed.'));

        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY);
        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY);

        self::assertCount(2, $handler->reports());
    }

    /**
     * A dispatcher that cannot even be resolved is contained like a listener
     * that throws, because the record is already stored by then.
     *
     * @return void
     */
    public function testADispatcherThatCannotBeResolvedIsContained(): void
    {
        $handler   = new RecordingExceptionHandler;
        $container = new Container;

        $container->instance(ExceptionHandler::class, $handler);

        (new RecordedNotifier($container))->notify(self::ID, self::CODE, self::CATEGORY, ['testing']);

        self::assertCount(1, $handler->reports());
    }

    /**
     * Rows of `[driver's message, class thrown]`: a deadlock and a lost
     * connection, each holding the secret in its SQL and bindings.
     *
     * @return iterable<string, array{0: string, 1: class-string<\RuntimeException>}>
     */
    public static function provideHostFatalFailures(): iterable
    {
        yield from [
            'a deadlock'        => [self::DEADLOCK, DeadlockException::class],
            'a lost connection' => [self::LOST_CONNECTION, AuditWriteFailedException::class],
        ];
    }

    /**
     * Inside a host transaction a listener's deadlock or lost connection is
     * thrown sanitised, with no previous, and not reported.
     *
     * @param  string  $message
     * @param  class-string<\RuntimeException>  $thrown
     * @return void
     */
    #[DataProvider('provideHostFatalFailures')]
    public function testAHostFatalListenerFailureInsideAHostPropagatesSanitised(string $message, string $thrown): void
    {
        $handler = $this->recordingHandler();
        $failure = self::queryFailure($message);

        $this->listenerThrows($failure);

        try {
            $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY, ['testing']);

            self::fail('Expected the listener\'s failure to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($thrown, $exception::class);
            self::assertNotSame($failure, $exception);
            self::assertNull($exception->getPrevious());
        }

        self::assertSame([], $handler->reports());
    }

    /**
     * A listener's deadlock is thrown as the sanitised deadlock, which Laravel
     * still recognises, so an outer `transaction()` retries it.
     *
     * @return void
     */
    public function testAListenersDeadlockIsTheSanitisedDeadlock(): void
    {
        $this->listenerThrows(self::queryFailure(self::DEADLOCK));

        try {
            $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY, ['testing']);

            self::fail('Expected the deadlock to propagate.');
        } catch (DeadlockException $exception) {
            self::assertSame(FailureClassifier::sanitisedDeadlock()->getMessage(), $exception->getMessage());
            self::assertSame(40001, $exception->getCode());
            self::assertTrue((new FailureClassifier)->isConcurrencyError($exception));
        }
    }

    /**
     * A listener's lost connection is thrown as a failed notification naming
     * only the record, its code, the operation and the failure's class.
     *
     * @return void
     */
    public function testAListenersLostConnectionNamesTheNotification(): void
    {
        $this->listenerThrows(self::queryFailure(self::LOST_CONNECTION));

        try {
            $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY, ['testing']);

            self::fail('Expected the lost connection to propagate.');
        } catch (AuditWriteFailedException $exception) {
            self::assertSame(self::ID, $exception->recordId);
            self::assertSame(self::CODE, $exception->eventCode);
            self::assertSame('notify', $exception->operation);
            self::assertSame(QueryException::class, $exception->exceptionClass);
            self::assertSame('testing', $exception->connection);
        }
    }

    /**
     * Rows of `[driver's message]`: a deadlock and a lost connection.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideHostFatalMessages(): iterable
    {
        yield from [
            'a deadlock'        => [self::DEADLOCK],
            'a lost connection' => [self::LOST_CONNECTION],
        ];
    }

    /**
     * With no host transaction open, a listener's deadlock or lost connection
     * ended nothing, so it is reported and contained like any other.
     *
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideHostFatalMessages')]
    public function testAHostFatalListenerFailureWithNoHostIsContained(string $message): void
    {
        $handler = $this->recordingHandler();
        $failure = self::queryFailure($message);

        $this->listenerThrows($failure);

        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY);

        self::assertSame([$failure], $handler->reports());
    }

    /**
     * With a host transaction open, a listener's ordinary failure ended nothing
     * either, so it is reported and contained.
     *
     * @return void
     */
    public function testAnOrdinaryListenerFailureInsideAHostIsContained(): void
    {
        $handler   = $this->recordingHandler();
        $exception = new \RuntimeException('The listener failed.');

        $this->listenerThrows($exception);

        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY, ['testing']);

        self::assertSame([$exception], $handler->reports());
    }

    /**
     * The sanitised failure holds nothing of the original: not its message, its
     * SQL or its bindings, anywhere in what it carries or its trace.
     *
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideHostFatalMessages')]
    public function testTheSanitisedFailureHoldsNoSecret(string $message): void
    {
        $failure = self::queryFailure($message);

        $this->recordingHandler();
        $this->listenerThrows($failure);

        try {
            $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY, ['testing']);

            self::fail('Expected the listener\'s failure to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertTrue(self::holdsText($failure, self::SECRET), 'The planted secret is not in the original failure.');
            self::assertHoldsNoSecret($exception, 'the sanitised failure');
        }
    }

    /**
     * A listener's deadlock ends the transaction on the connection it happened
     * on, whichever that is: a host's own, though the store writes elsewhere.
     *
     * @return void
     */
    public function testAListenerFailingOnAnOpenConnectionPropagates(): void
    {
        $this->listenerThrows(new QueryException('host', 'update hosts set x = 1', [], new \PDOException(self::DEADLOCK)));

        $this->expectException(DeadlockException::class);

        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY, ['host']);
    }

    /**
     * A listener's deadlock on a connection with no transaction open ended
     * nothing, whatever is open elsewhere, so it is contained.
     *
     * @return void
     */
    public function testAListenerFailingOnAnIdleConnectionIsContained(): void
    {
        $handler = $this->recordingHandler();
        $failure = new QueryException('idle', 'update hosts set x = 1', [], new \PDOException(self::DEADLOCK));

        $this->listenerThrows($failure);

        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY, ['host']);

        self::assertSame([$failure], $handler->reports());
    }

    /**
     * A listener's deadlock naming no connection may have ended any open
     * transaction, so with one open it propagates.
     *
     * @return void
     */
    public function testAListenersUnnamedDeadlockPropagatesWhileATransactionIsOpen(): void
    {
        $this->listenerThrows(new \PDOException(self::DEADLOCK));

        $this->expectException(DeadlockException::class);

        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY, ['host']);
    }

    /**
     * The same deadlock with nothing open ended nothing, so it is contained.
     *
     * @return void
     */
    public function testAListenersUnnamedDeadlockWithNothingOpenIsContained(): void
    {
        $handler = $this->recordingHandler();
        $failure = new \PDOException(self::DEADLOCK);

        $this->listenerThrows($failure);

        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY);

        self::assertSame([$failure], $handler->reports());
    }

    /**
     * A phrase in a listener's failure that is no database failure, such as a
     * cache server gone away, ended no transaction, so it is contained.
     *
     * @return void
     */
    public function testAPhraseOutsideTheDatabaseIsContained(): void
    {
        $handler = $this->recordingHandler();
        $failure = new \RuntimeException('Redis server went away');

        $this->listenerThrows($failure);

        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY, ['testing']);

        self::assertSame([$failure], $handler->reports());
    }

    /**
     * A reporter that deadlocks while a host is open has ended that host, so
     * the sanitised deadlock propagates.
     *
     * @return void
     */
    public function testAReporterEndingAnOpenTransactionPropagates(): void
    {
        $this->reporterRaising(new QueryException('testing', 'insert into logs values (1)', [], new \PDOException(self::DEADLOCK)));

        $this->listenerThrows(new \RuntimeException('The listener failed.'));

        try {
            $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY, ['testing']);

            self::fail('Expected the reporter\'s deadlock to propagate.');
        } catch (DeadlockException $thrown) {
            self::assertNull($thrown->getPrevious());
            self::assertSame(FailureClassifier::sanitisedDeadlock()->getMessage(), $thrown->getMessage());
        }
    }

    /**
     * The same reporter with nothing open ended nothing, so it stays ignored.
     *
     * @return void
     */
    public function testAReporterFailingWithNothingOpenIsIgnored(): void
    {
        $this->reporterRaising(new QueryException('testing', 'insert into logs values (1)', [], new \PDOException(self::DEADLOCK)));

        $this->listenerThrows(new \RuntimeException('The listener failed.'));

        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY);

        $this->addToAssertionCount(1);
    }

    /**
     * A package record's listeners run inside the read guard, which is closed
     * again once they have run.
     *
     * @return void
     */
    public function testAPackageRecordsListenersRunInsideTheReadGuard(): void
    {
        $heard = $this->guardStatesHeard();

        $this->notifier()->notify(self::ID, self::PACKAGE_CODE, 'audit');

        self::assertSame([true], $heard->states);
        self::assertFalse(app(ReadGuard::class)->isActive());
    }

    /**
     * The listeners of the application's own records run outside the read
     * guard, a code resembling the reserved prefix included.
     *
     * @return void
     */
    public function testAnApplicationRecordsListenersRunOutsideIt(): void
    {
        $heard = $this->guardStatesHeard();

        $this->notifier()->notify(self::ID, self::CODE, self::CATEGORY);
        $this->notifier()->notify(self::ID, 'audit_logs.read', self::CATEGORY);
        $this->notifier()->notify(self::ID, 'app.audit_log.read', self::CATEGORY);

        self::assertSame([false, false, false], $heard->states);
    }

    /**
     * A throwing package-record listener is reported and contained, and the
     * read guard closes, forgetting its refusal.
     *
     * @return void
     */
    public function testTheReadGuardClosesWhenAListenerThrows(): void
    {
        $handler   = $this->recordingHandler();
        $exception = new \RuntimeException('The listener failed.');

        Event::listen(AuditRecorded::class, static function () use ($exception): never {
            app(ReadGuard::class)->isFirstRefusal();

            throw $exception;
        });

        $this->notifier()->notify(self::ID, self::PACKAGE_CODE, 'audit');

        $guard = app(ReadGuard::class);

        self::assertSame([$exception], $handler->reports());
        self::assertFalse($guard->isActive());
        self::assertTrue($guard->during(static fn (): bool => $guard->isFirstRefusal()));
    }

    /**
     * A package record's listener that ends the host's transaction is thrown
     * sanitised, and the read guard is closed.
     *
     * @return void
     */
    public function testAHostFatalPackageListenerFailureClosesTheGuard(): void
    {
        $this->listenerThrows(self::queryFailure(self::DEADLOCK));

        try {
            $this->notifier()->notify(self::ID, self::PACKAGE_CODE, 'audit', ['testing']);

            self::fail('Expected the listener\'s deadlock to propagate.');
        } catch (DeadlockException $thrown) {
            self::assertSame(FailureClassifier::sanitisedDeadlock()->getMessage(), $thrown->getMessage());
        }

        self::assertFalse(app(ReadGuard::class)->isActive());
    }

    /**
     * A query exception holding the secret in its SQL and bindings, failing
     * with the driver's message on the testing connection.
     *
     * @param  string  $message
     * @return \Illuminate\Database\QueryException
     */
    private static function queryFailure(string $message): QueryException
    {
        return new QueryException('testing', 'update invoices set note = ? where note = \'' . self::SECRET . '\'', [self::SECRET], new \PDOException($message));
    }

    /**
     * The notifier, as the container builds it.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\RecordedNotifier
     */
    private function notifier(): RecordedNotifier
    {
        return app(RecordedNotifier::class);
    }

    /**
     * Bind a handler that keeps what it is asked to report and return it.
     *
     * @param  bool  $throwsOnReport
     * @return \Tests\Fixtures\Privacy\RecordingExceptionHandler
     */
    private function recordingHandler(bool $throwsOnReport = false): RecordingExceptionHandler
    {
        $handler = new RecordingExceptionHandler($throwsOnReport);

        app()->instance(ExceptionHandler::class, $handler);

        return $handler;
    }

    /**
     * Bind a handler whose `report()` throws the failure.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    private function reporterRaising(\Throwable $failure): void
    {
        $reporter = \Mockery::mock(ExceptionHandler::class);

        $reporter->allows('report')->andThrow($failure);

        app()->instance(ExceptionHandler::class, $reporter);
    }

    /**
     * Register a listener of `AuditRecorded` that keeps whether the read guard
     * is active each time it is told, and return what it keeps.
     *
     * @return object{states: list<bool>}
     */
    private function guardStatesHeard(): object
    {
        $heard = new class {
            /** @var list<bool> Whether the read guard was active, at each notification. */
            public array $states = [];
        };

        Event::listen(AuditRecorded::class, static function () use ($heard): void {
            $heard->states[] = app(ReadGuard::class)->isActive();
        });

        return $heard;
    }

    /**
     * Register a listener of `AuditRecorded` that throws the failure.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    private function listenerThrows(\Throwable $failure): void
    {
        Event::listen(AuditRecorded::class, static function () use ($failure): never {
            throw $failure;
        });
    }
}
