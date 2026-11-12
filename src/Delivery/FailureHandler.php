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
 * Spills, reports, dispatches `AuditWriteFailed` and throws for a failed write
 * as its failure rule says; each step runs on its own, so one that fails stops
 * no other.
 *
 * The spill goes first because it is the only lasting trace and a reporter may
 * end the process.
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
     * Run the rule's steps, then throw what the rule or a failure fatal to an
     * open transaction requires; a deferred capture's failure is reported
     * instead, since it runs inside a commit callback.
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
     * Report a deferred write dropped because its transaction was already
     * aborted, so its commit was really a rollback; a failing reporter is
     * ignored.
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
     * by its class alone, and signal the capture.
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
     * Report a sanitised failure that cannot be thrown out of a commit
     * callback, ignoring a failing reporter.
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
            // Nothing may leave a commit callback, and there is nowhere left to
            // say so
        }
    }

    /**
     * Run each step the rule asks for and return the first failure fatal to an
     * open transaction, sanitised, or `null`.
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
     * Spill the record now, or bind the spill to the transaction's commit;
     * returns a now-written spill's failure fatal to an open transaction, or
     * `null`.
     *
     * PostgreSQL commits an already aborted transaction as a rollback yet
     * reports success, so such a failure drops the bound spill.
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
     * Write a commit-bound spill inside the write guard, reporting its failure
     * since nothing may leave a commit callback. The failed write arrives
     * sealed so a failure's trace cannot reach the record through the commit's
     * frames.
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
     * Write the spill line: the finalised record, or the captured record marked
     * unsigned when finalising failed.
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
     * Run the step and report its failure as a sanitised exception of its own;
     * a failure fatal to an open transaction is returned instead when it may
     * propagate.
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
     * Dispatch `AuditWriteFailed` for the failed write.
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
     * Report a step's sanitised failure; a reporter's failure is ignored unless
     * it ended an open transaction and may propagate.
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
            // A reporter's failure must not stop the remaining steps, unless it
            // ended a transaction the caller is inside
            return $mayPropagate ? $this->secondaryFatalOf($failure, $this->exceptionOf($failure, FailedOperation::NOTIFY, $failed, null), $failed) : null;
        }

        return null;
    }

    /**
     * What a step's failure is thrown as if it ended an open transaction; a
     * step can touch any connection, so an unnamed one counts when any was
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
     * What the failure is thrown as if it ended an open transaction: the
     * sanitised deadlock, which Laravel still retries, for a concurrency error,
     * the sanitised exception for a lost connection, and `null` otherwise.
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
     * Whether the failure is a concurrency error or a lost connection, and the
     * connections it happened on.
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
     * The sanitised exception of the failure, holding only its diagnostics; a
     * stack's failure names each failed destination, since nothing else records
     * them in sync mode.
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
