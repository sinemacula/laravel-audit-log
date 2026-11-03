<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\DatabaseTransactionRecord;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use SineMacula\Laravel\AuditLog\Stores\StackDeliveryException;
use SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics;

/**
 * What happens once a record could not be written: the record is spilled, the
 * failure is reported, `AuditWriteFailed` is dispatched, and the failure is
 * thrown or not, each as the record's failure rule says.
 *
 * The spill goes first, because it is the only lasting trace of the record and
 * a reporter may block or end the process. Each step runs on its own, so one
 * that fails stops no other: its failure is reported as an
 * `AuditWriteFailedException` of its own, and goes no further. Under the
 * `REPORT` rule the code that recorded goes on; under the others the failure is
 * thrown and not also reported, since a handler would then report it twice.
 * Nothing thrown is the original failure: it is replaced by an
 * `AuditWriteFailedException` that holds no value of the record and has no
 * previous exception.
 *
 * A concurrency error or a lost connection on a connection with a transaction
 * open has ended that transaction, whatever the rule says, so it is never
 * spilled or reported and always thrown: a concurrency error as a sanitised
 * `DeadlockException`, which Laravel still retries, and a lost connection as
 * the sanitised exception. The same failure raised by a step on any connection
 * with a transaction open, or by the reporter of a step's own failure, is
 * thrown once the remaining steps have run. A statement refused because a
 * PostgreSQL transaction was already aborted is not fatal in this sense and
 * follows the rule.
 *
 * A spill bound to a commit is written when that transaction commits and never
 * when it rolls back, so a replay never brings back a record of work that was
 * undone. It waits in the commit queue and never throws, so it stops no later
 * commit callback. Every step, and a bound spill, runs inside the write guard,
 * so a record made from inside one is refused rather than written.
 *
 * A record captured from an event carries its capture's signal, and always
 * follows the `REPORT` rule. Once the steps have run, the signal is told the
 * failure once, as fatal when it is thrown to the capture. A synchronous
 * capture's failure fatal to an open transaction is thrown as for any record;
 * a deferred one's runs inside a commit callback, long after the capture
 * returned, so it is reported instead, inside the write guard, and never
 * thrown. The work it records has already committed, so the record is spilled
 * first, at once and bound to no transaction, as the only trace left of it. A
 * signal whose callback fails stops no step.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FailureHandler
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container each step resolves what it needs from, when it runs. */
        private Container $container,
    ) {}

    /**
     * Spill, report and dispatch `AuditWriteFailed` as the rule says, then
     * throw what the rule, or a failure fatal to an open transaction, requires.
     * With a transaction to bind to, the spill waits for that transaction's
     * commit, and is dropped when the failure shows the transaction was already
     * aborted. With a capture's signal, the signal is then told the failure
     * once, and a deferred capture's fatal failure is spilled at once and
     * reported, not thrown.
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
    public function handle(
        #[\SensitiveParameter] FailedWrite $failed,
        FailureRule $rule,
        ?DatabaseTransactionRecord $commitBound = null,
        #[\SensitiveParameter] ?CaptureSignal $capture = null,
    ): void {
        $exception = $this->exceptionOf($failed->failure, $failed->operation, $failed, $failed->connection);
        $fatal     = $this->fatalOf($failed->failure, $exception, $failed->openConnections(), $failed->hostOpen);
        $guard     = $this->container->make(WriteGuard::class);

        if ($fatal !== null && $capture?->isDeferred() === true) {
            $guard->during(fn (): ?\RuntimeException => $this->attempt(fn () => $this->spillNow($failed), FailedOperation::SPILL, $failed, false));
        }

        $secondary = $guard->during(fn (): ?\RuntimeException => $this->steps($guard, $failed, $rule, $fatal === null, $exception, $commitBound));

        $thrown = $fatal ?? $secondary ?? ($rule === FailureRule::REPORT ? null : $exception);

        $capture?->fail($exception->exceptionClass, $thrown !== null && !$capture->isDeferred());

        if ($thrown === null) {
            return;
        }

        if ($capture?->isDeferred() === true) {

            $this->reportDeferred($thrown);

            return;
        }

        throw $thrown;
    }

    /**
     * Report a deferred write dropped because the transaction it waited for was
     * already aborted, so its commit is really a rollback: nothing is written,
     * spilled or dispatched, as for any other rollback, and the report names
     * the record, since the application saw its commit succeed. A reporter that
     * fails is ignored: no commit callback may throw for work that was undone.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \Throwable  $aborted
     * @param  \SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation  $operation
     * @param  string  $store
     * @return void
     */
    public function abandon(#[\SensitiveParameter] AuditRecord $record, #[\SensitiveParameter] \Throwable $aborted, FailedOperation $operation, string $store): void
    {
        $this->reportDeferred(new AuditWriteFailedException(WriteDiagnostics::of($aborted, $record->id, $record->event, $operation, $store)));
    }

    /**
     * Report what a deferred capture's write let out beyond the failure path,
     * named by its class alone, and tell the capture's signal, so nothing
     * leaves the commit callback the write runs in. A reporter that fails is
     * ignored, and a signal already told keeps its first failure.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \Throwable  $failure
     * @param  \SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation  $operation
     * @param  string  $store
     * @param  \SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @return void
     */
    public function contain(
        #[\SensitiveParameter] AuditRecord $record,
        #[\SensitiveParameter] \Throwable $failure,
        FailedOperation $operation,
        string $store,
        #[\SensitiveParameter] CaptureSignal $capture,
    ): void {
        $this->abandon($record, $failure, $operation, $store);

        $capture->fail(get_debug_type($failure), false);
    }

    /**
     * Report a sanitised failure that cannot be thrown, because it would leave
     * a commit callback, inside the write guard. A reporter that fails is
     * ignored: no commit callback may throw.
     *
     * @param  \RuntimeException  $thrown
     * @return void
     */
    private function reportDeferred(#[\SensitiveParameter] \RuntimeException $thrown): void
    {
        try {
            $this->container->make(WriteGuard::class)->during(function () use ($thrown): void {
                $this->container->make(ExceptionHandler::class)->report($thrown);
            });
        } catch (\Throwable) {
            // The write ran inside a commit callback, which nothing may leave,
            // and there is nowhere left to say so
        }
    }

    /**
     * Run each step the rule asks for, in order, and return the first failure
     * of a step that is fatal to the open transaction, sanitised, or `null`. A
     * failure fatal to the transaction is neither spilled nor reported.
     *
     * @param  \SineMacula\Laravel\AuditLog\Runtime\WriteGuard  $guard
     * @param  \SineMacula\Laravel\AuditLog\Delivery\FailedWrite  $failed
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  bool  $recoverable
     * @param  \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException  $exception
     * @param  ?\Illuminate\Database\DatabaseTransactionRecord  $commitBound
     * @return ?\RuntimeException
     */
    private function steps(
        WriteGuard $guard,
        #[\SensitiveParameter] FailedWrite $failed,
        FailureRule $rule,
        bool $recoverable,
        #[\SensitiveParameter] AuditWriteFailedException $exception,
        ?DatabaseTransactionRecord $commitBound,
    ): ?\RuntimeException {
        $reporter = fn () => $this->container->make(ExceptionHandler::class)->report($exception);

        $secondaries = [
            $recoverable && $rule !== FailureRule::THROW ? $this->spill($guard, $failed, $commitBound) : null,
            $recoverable && $rule === FailureRule::REPORT ? $this->attempt($reporter, FailedOperation::NOTIFY, $failed) : null,
            $this->attempt(fn () => $this->dispatch($failed, $exception), FailedOperation::NOTIFY, $failed),
        ];

        return array_values(array_filter($secondaries, static fn (?\RuntimeException $secondary): bool => $secondary !== null))[0] ?? null;
    }

    /**
     * Spill the record now, or bind the spill to the transaction's commit, and
     * return the failure of a spill written now that is fatal to the open
     * transaction, sanitised, or `null`.
     *
     * A failure that shows the transaction was already aborted drops the bound
     * spill: PostgreSQL ends such a transaction with a rollback while reporting
     * the commit a success, so its commit callbacks would run for work that was
     * undone.
     *
     * @param  \SineMacula\Laravel\AuditLog\Runtime\WriteGuard  $guard
     * @param  \SineMacula\Laravel\AuditLog\Delivery\FailedWrite  $failed
     * @param  ?\Illuminate\Database\DatabaseTransactionRecord  $commitBound
     * @return ?\RuntimeException
     */
    private function spill(WriteGuard $guard, #[\SensitiveParameter] FailedWrite $failed, ?DatabaseTransactionRecord $commitBound): ?\RuntimeException
    {
        if ($commitBound === null) {
            return $this->attempt(fn () => $this->spillNow($failed), FailedOperation::SPILL, $failed);
        }

        $failure = $failed->failure;

        if ($failure instanceof StackDeliveryException ? $failure->causedByAbortedHost : (new FailureClassifier)->isAbortedHost($failure)) {
            return null;
        }

        $sealed = new \SensitiveParameterValue($failed);

        $this->container->make(CommitQueue::class)->defer($commitBound, function () use ($guard, $sealed): void {
            $this->spillAtCommit($guard, $sealed);
        });

        return null;
    }

    /**
     * Write a spill bound to a commit, inside the write guard, as that commit
     * runs it. Its failure is reported and goes no further, since nothing may
     * be thrown from a commit callback.
     *
     * The failed write reaches the callback sealed: the commit's own frames
     * hold the transaction and the callbacks bound to it, so a failure's trace
     * would otherwise reach the record through them.
     *
     * @param  \SineMacula\Laravel\AuditLog\Runtime\WriteGuard  $guard
     * @param  \SensitiveParameterValue  $sealed
     * @return void
     */
    private function spillAtCommit(WriteGuard $guard, \SensitiveParameterValue $sealed): void
    {
        /** @var \SineMacula\Laravel\AuditLog\Delivery\FailedWrite $failed */
        $failed = $sealed->getValue();

        $guard->during(fn (): ?\RuntimeException => $this->attempt(fn () => $this->spillNow($failed), FailedOperation::SPILL, $failed, false));
    }

    /**
     * Write the spill line: the finalised record with its integrity fields, or
     * the captured record marked unsigned when finalising it failed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\FailedWrite  $failed
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     */
    private function spillNow(#[\SensitiveParameter] FailedWrite $failed): void
    {
        $spill = $this->container->make(FailureSpill::class);

        if ($failed->finalised === null) {

            $spill->spillUnsigned($failed->record);

            return;
        }

        $spill->spillFinalised($failed->finalised);
    }

    /**
     * Run the step, and report its failure as a sanitised exception of its own
     * that goes no further. A failure fatal to a transaction that was open on
     * any connection is returned sanitised instead, unreported, when it may
     * propagate; a bound spill runs after the commit and never propagates.
     *
     * @param  \Closure(): void  $step
     * @param  \SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation  $operation
     * @param  \SineMacula\Laravel\AuditLog\Delivery\FailedWrite  $failed
     * @param  bool  $mayPropagate
     * @return ?\RuntimeException
     */
    private function attempt(
        #[\SensitiveParameter] \Closure $step,
        FailedOperation $operation,
        #[\SensitiveParameter] FailedWrite $failed,
        bool $mayPropagate = true,
    ): ?\RuntimeException {
        try {
            $step();
        } catch (\Throwable $failure) {
            $exception = $this->exceptionOf($failure, $operation, $failed, null);

            return ($mayPropagate ? $this->secondaryFatalOf($failure, $exception, $failed) : null) ?? $this->report($exception, $failed, $mayPropagate);
        }

        return null;
    }

    /**
     * Dispatch `AuditWriteFailed` with the record's id and code, the store's
     * class and the failure's class.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\FailedWrite  $failed
     * @param  \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException  $exception
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function dispatch(#[\SensitiveParameter] FailedWrite $failed, #[\SensitiveParameter] AuditWriteFailedException $exception): void
    {
        $event = new AuditWriteFailed($failed->record->id, $failed->record->event, $failed->store, $exception->exceptionClass);

        $this->container->make(Dispatcher::class)->dispatch($event);
    }

    /**
     * Report a step's sanitised failure. A reporter that fails here is ignored,
     * unless its failure ended a transaction that was open and may propagate,
     * which is returned sanitised.
     *
     * @param  \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException  $exception
     * @param  \SineMacula\Laravel\AuditLog\Delivery\FailedWrite  $failed
     * @param  bool  $mayPropagate
     * @return ?\RuntimeException
     */
    private function report(#[\SensitiveParameter] AuditWriteFailedException $exception, #[\SensitiveParameter] FailedWrite $failed, bool $mayPropagate): ?\RuntimeException
    {
        try {
            $this->container->make(ExceptionHandler::class)->report($exception);
        } catch (\Throwable $failure) {
            // A failure of the failure path that cannot be reported has nowhere
            // left to be said, and must not stop the remaining steps, unless it
            // has ended a transaction the caller is still inside
            return $mayPropagate ? $this->secondaryFatalOf($failure, $this->exceptionOf($failure, FailedOperation::NOTIFY, $failed, null), $failed) : null;
        }

        return null;
    }

    /**
     * What a failure of a step would be thrown as if it ended a transaction
     * that was open on any connection the application holds. A step can touch
     * any of them, so a failure that names no connection counts when any was
     * open.
     *
     * @param  \Throwable  $failure
     * @param  \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException  $exception
     * @param  \SineMacula\Laravel\AuditLog\Delivery\FailedWrite  $failed
     * @return ?\RuntimeException
     */
    private function secondaryFatalOf(
        #[\SensitiveParameter] \Throwable $failure,
        #[\SensitiveParameter] AuditWriteFailedException $exception,
        #[\SensitiveParameter] FailedWrite $failed,
    ): ?\RuntimeException {
        $open = $failed->openConnections();

        return $this->fatalOf($failure, $exception, $open, $open !== []);
    }

    /**
     * What the failure would be thrown as if it ended a transaction that was
     * open: the sanitised deadlock for a concurrency error, the sanitised
     * exception for a lost connection, and `null` for anything else, or for a
     * failure on a connection with no transaction open. A failure that names no
     * connection counts as the caller says.
     *
     * @param  \Throwable  $failure
     * @param  \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException  $exception
     * @param  list<string>  $open
     * @param  bool  $unnamedCounts
     * @return ?\RuntimeException
     */
    private function fatalOf(
        #[\SensitiveParameter] \Throwable $failure,
        #[\SensitiveParameter] AuditWriteFailedException $exception,
        array $open,
        bool $unnamedCounts,
    ): ?\RuntimeException {
        [$concurrency, $lost, $connections] = self::whatEnded($failure);

        return match (true) {
            !(new FailureClassifier)->reachesAnOpenTransaction($connections, $open, $unnamedCounts) => null,
            $concurrency                                                                            => FailureClassifier::sanitisedDeadlock(),
            $lost                                                                                   => $exception,
            default                                                                                 => null,
        };
    }

    /**
     * Whether the failure is a concurrency error, whether it is a lost
     * connection, and the connections it happened on. A stack's failure is read
     * from what it kept of its destinations' failures.
     *
     * @param  \Throwable  $failure
     * @return array{0: bool, 1: bool, 2: array<int, ?string>}
     */
    private static function whatEnded(#[\SensitiveParameter] \Throwable $failure): array
    {
        if ($failure instanceof StackDeliveryException) {
            return [$failure->causedByConcurrency, $failure->causedByLostConnection, $failure->fatalConnections ?: [null]];
        }

        $classifier = new FailureClassifier;

        return [$classifier->isConcurrencyError($failure), $classifier->isLostConnection($failure), [$classifier->connectionOf($failure)]];
    }

    /**
     * The sanitised exception of a failure of the operation on the record,
     * holding nothing of the failure but its diagnostics. A stack's failure
     * names each destination that failed, since nothing else records it in sync
     * mode; an id holds no comma, so the list reads back.
     *
     * @param  \Throwable  $failure
     * @param  \SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation  $operation
     * @param  \SineMacula\Laravel\AuditLog\Delivery\FailedWrite  $failed
     * @param  ?string  $connection
     * @return \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function exceptionOf(
        #[\SensitiveParameter] \Throwable $failure,
        FailedOperation $operation,
        #[\SensitiveParameter] FailedWrite $failed,
        ?string $connection,
    ): AuditWriteFailedException {
        $destination = $failure instanceof StackDeliveryException ? implode(',', array_keys($failure->failures)) : null;

        return new AuditWriteFailedException(WriteDiagnostics::of($failure, $failed->record->id, $failed->record->event, $operation, $failed->store, $connection, $destination));
    }
}
