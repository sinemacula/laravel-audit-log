<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Runtime\ReadGuard;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics;

/**
 * Dispatches `AuditRecorded` once a record's store has it, containing a
 * listener's failure since the record is already stored.
 *
 * A package record, under `audit_log.`, is dispatched inside the read guard so
 * its listener cannot record another read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordedNotifier
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves the dispatcher, the reporter and the latch on every call. */
        private Container $container,
    ) {}

    /**
     * Dispatch `AuditRecorded`, containing a listener's failure unless it ended
     * a transaction on one of the connections open before the write.
     *
     * @param  string  $id
     * @param  string  $code
     * @param  string  $category
     * @param  list<string>  $openTransactions
     * @return void
     *
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    public function notify(string $id, string $code, string $category, array $openTransactions = []): void
    {
        try {
            $this->dispatch(new AuditRecorded($id, $code, $category));
        } catch (\Throwable $exception) {
            $fatal = self::fatalOf($exception, $id, $code, $openTransactions) ?? $this->report($exception, $id, $code, $openTransactions);

            if ($fatal !== null) {
                throw $fatal;
            }
        }
    }

    /**
     * Dispatch the event, inside the read guard for a package code.
     *
     * @param  \SineMacula\Laravel\AuditLog\Events\AuditRecorded  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function dispatch(#[\SensitiveParameter] AuditRecorded $event): void
    {
        $dispatcher = $this->container->make(Dispatcher::class);

        if (!str_starts_with($event->code, EventCode::RESERVED_PREFIX)) {

            $dispatcher->dispatch($event);

            return;
        }

        $this->container->make(ReadGuard::class)->during(static function () use ($dispatcher, $event): void {
            $dispatcher->dispatch($event);
        });
    }

    /**
     * What a failure is thrown as when it ended an open transaction: the
     * sanitised deadlock for a concurrency error, a failed notification for a
     * lost connection, and `null` otherwise.
     *
     * @param  \Throwable  $exception
     * @param  string  $id
     * @param  string  $code
     * @param  list<string>  $openTransactions
     * @return ?\RuntimeException
     */
    private static function fatalOf(#[\SensitiveParameter] \Throwable $exception, string $id, string $code, array $openTransactions): ?\RuntimeException
    {
        $classifier = new FailureClassifier;

        $reaches = $classifier->reachesAnOpenTransaction([$classifier->connectionOf($exception)], $openTransactions, $openTransactions !== []);

        return match (true) {
            !$reaches                                   => null,
            $classifier->isConcurrencyError($exception) => FailureClassifier::sanitisedDeadlock(),
            $classifier->isLostConnection($exception)   => new AuditWriteFailedException(WriteDiagnostics::of($exception, $id, $code, FailedOperation::NOTIFY, Dispatcher::class)),
            default                                     => null,
        };
    }

    /**
     * Report a listener's failure through the report latch; a reporter's own
     * failure is ignored unless it ended an open transaction, which is
     * returned.
     *
     * @param  \Throwable  $exception
     * @param  string  $id
     * @param  string  $code
     * @param  list<string>  $openTransactions
     * @return ?\RuntimeException
     */
    private function report(#[\SensitiveParameter] \Throwable $exception, string $id, string $code, array $openTransactions): ?\RuntimeException
    {
        $container = $this->container;

        try {
            $container->make(ReportLatch::class)->once(static function () use ($container, $exception): void {
                $container->make(ExceptionHandler::class)->report($exception);
            });
        } catch (\Throwable $failure) {
            // The record is stored, so a broken reporter must not fail the
            // caller unless it ended a transaction the caller is inside
            return self::fatalOf($failure, $id, $code, $openTransactions);
        }

        return null;
    }
}
