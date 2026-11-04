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
 * Dispatches `AuditRecorded` once a record's store has it.
 *
 * The record is already stored, so a listener's failure must not look like a
 * failed write: it is reported and goes no further, and a reporter that fails
 * too is ignored. The report runs through the report latch, so a reporter that
 * records an audit event whose listener fails again is not reported into a
 * loop.
 *
 * The exception is a deadlock, serialisation failure or lost connection raised
 * by a listener or the reporter on a connection with a transaction open, any
 * connection the application holds and not only the storage connection: that
 * has ended the transaction without Laravel knowing, so containing it would let
 * the host go on and commit the rest. It is thrown instead, never the original:
 * a concurrency error as the sanitised deadlock Laravel still retries, and a
 * lost connection as an `AuditWriteFailedException` naming the notification. It
 * is not reported as well, since what is thrown is reported by whoever catches
 * it. A failure on a connection with no transaction open ended nothing, so it
 * is contained whatever else is open.
 *
 * A record of the package's own, under the reserved `audit_log.` prefix, is
 * dispatched inside the read guard, wherever it is delivered: synchronously, at
 * a drain or at a replay. A listener of a read record cannot read the trail
 * again, so a read never records a read whose listeners read once more. Every
 * other code is dispatched outside it, so a listener of the application's own
 * records may read. One limit no guard can reach: a queued listener runs later
 * in a worker, outside every window, so a queued listener of an `audit_log.`
 * code that reads the trail makes one more read record, and one more job, each
 * time it runs. A listener that reads the trail ignores `audit_log.` codes.
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

        /** The container the dispatcher, the reporter and the latch are resolved from on every call. */
        private Container $container,
    ) {}

    /**
     * Dispatch `AuditRecorded` for the record, inside the read guard for a
     * package code, containing a listener's failure unless it ended a
     * transaction on one of the connections named as open, which were read
     * before the write, since Laravel forgets an open transaction when its
     * connection is lost.
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
     * Dispatch the event, inside the read guard when it names a package code,
     * so the guard closes however a listener ends.
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
     * What a failure is thrown as when it ended a transaction that was open:
     * the sanitised deadlock for a concurrency error, a failed notification for
     * a lost connection, and `null` for anything else, which is contained.
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
     * Report a listener's failure, unless a report is already running further
     * up the stack. A reporter that fails too is ignored, since the record is
     * stored, unless its failure ended a transaction that was open, which is
     * returned to be thrown.
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
            // The record is stored; a broken reporter must not undo that for
            // the caller, or stop a later after-commit callback, unless it has
            // ended a transaction the caller is still inside
            return self::fatalOf($failure, $id, $code, $openTransactions);
        }

        return null;
    }
}
