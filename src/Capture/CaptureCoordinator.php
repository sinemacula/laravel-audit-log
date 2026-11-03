<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Database\OpenTransactions;
use SineMacula\Laravel\AuditLog\Delivery\CaptureSignal;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\RecordPipeline;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;

/**
 * Captures an event as a record: the one way a mapped event, a core
 * authentication event, a Gate denial or a watched model's change is written.
 *
 * The source describes the event on a builder with no recorder, inside the
 * mapping window, so nothing it records explicitly is written, and returns that
 * builder or `null` to skip the event. A capture of another event its
 * description sets off is a capture of its own and is written; the same event
 * object captured or dispatched again while it is being described writes
 * nothing, so a mapper that does so never recurses. A builder returned is
 * claimed for its event object, so the object is written once whichever sources
 * see it, and is then written through the record pipeline with the capture's
 * signal: immediately unless the package's model source deferred it, never
 * fail-closed or transactional, and following the `REPORT` rule whatever the
 * failure mode.
 *
 * Nothing leaves a capture but one failure. A failure that ended a transaction
 * open on the connection it happened on (a concurrency error or a lost
 * connection) propagates sanitised from a capture that writes at once, judged
 * against the transactions open before the capture ran, because Laravel forgets
 * a transaction whose connection is lost; it is neither spilled nor reported,
 * and `AuditCaptureFailed` is still dispatched once. Any other failure is
 * reported once, by its class names alone (a failed write as the write's own
 * failure, anything else as a `CaptureFailedException`), `AuditCaptureFailed`
 * is dispatched once, and the capture returns `null`, so the code that
 * dispatched the event goes on. Reports and the event go out inside the write
 * guard, and a reporter or a listener that fails stops nothing.
 *
 * Inside the write guard nothing is captured and nothing is said: writing an
 * entry never produces a record. An event of the package's own is never
 * captured, before any mapping is resolved.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CaptureCoordinator
{
    /** @var string Why a source's return other than its own builder or `null` is refused. */
    private const string NOT_ITS_BUILDER = 'A capture\'s source returns the builder it was given, still to be recorded, or `null`.';

    /** @var string Why a source choosing how its record is written is refused. */
    private const string CHOSE_DELIVERY = 'A capture decides how its record is written, so its source sets no timing, `failClosed()` or `transactional()`.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container of the capture, which everything a capture uses is resolved from. */
        private Container $container,
    ) {}

    /**
     * Capture an event through the mapper registered for it, and return the
     * record written, or `null` when nothing was: the event is the package's
     * own, the write guard is active, no mapping applies, the event has been
     * captured already or is being described now, the mapper skipped it, or the
     * capture failed. Nothing is thrown but a failure fatal to an open
     * transaction.
     *
     * @param  object  $event
     * @return ?\SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \Illuminate\Database\DeadlockException
     * @throws \RuntimeException
     */
    public function mapped(#[\SensitiveParameter] object $event): ?AuditRecord
    {
        try {
            $mapper = $this->mapperOf($event);
        } catch (\Throwable $failure) {
            return $this->contain($failure, get_debug_type($event), null, null, $this->openTransactions());
        }

        if ($mapper === null) {
            return null;
        }

        $container = $this->container;

        return $this->run($event, $mapper, static function (#[\SensitiveParameter] PendingRecord $pending) use ($container, $mapper, $event): ?PendingRecord {
            $instance = $container->make($mapper);

            if (!$instance instanceof EventMapper) {
                throw new \LogicException(sprintf('`%s` does not implement `EventMapper`.', get_debug_type($instance)));
            }

            return $instance->map($event, $pending);
        }, true, false);
    }

    /**
     * Capture an event through one of the package's own sources, which
     * describes it, and return the record written, or `null` when nothing
     * was. With `$once` the event object is captured once whichever sources
     * see it; without, each call may write. An object whose description is
     * running is never described again inside it. Only a source that may defer can
     * choose a timing, and only immediately or after commit.
     *
     * @param  object  $event
     * @param  string  $source
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): ?\SineMacula\Laravel\AuditLog\Records\PendingRecord  $describe
     * @param  bool  $once
     * @param  bool  $mayDefer
     * @return ?\SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \Illuminate\Database\DeadlockException
     * @throws \RuntimeException
     */
    public function captured(
        #[\SensitiveParameter] object $event,
        string $source,
        #[\SensitiveParameter] \Closure $describe,
        bool $once = true,
        bool $mayDefer = false,
    ): ?AuditRecord {
        try {
            if ($this->isGuarded() || $this->isTaken($event, $once)) {
                return null;
            }
        } catch (\Throwable $failure) {
            return $this->contain($failure, get_debug_type($event), $source, null, $this->openTransactions());
        }

        return $this->run($event, $source, $describe, $once, $mayDefer);
    }

    /**
     * The mapper registered for the event, or `null` when the event is the
     * package's own, the write guard is active, nothing is mapped, no mapping
     * applies, or the event object has been captured already or is being
     * described now. A class name alone: the container may make anything of it.
     *
     * @param  object  $event
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function mapperOf(#[\SensitiveParameter] object $event): ?string
    {
        if ($event instanceof AuditLogEvent || $this->isGuarded()) {
            return null;
        }

        $registry = $this->container->make(MapperRegistry::class);

        if (!$registry->hasMappings()) {
            return null;
        }

        $mapper = $registry->mapperFor($event::class);

        return $mapper === null || $this->isTaken($event, true) ? null : $mapper;
    }

    /**
     * Whether the event object is not to be described now: its description is
     * running, or, when it is captured once, it has been claimed.
     *
     * @param  object  $event
     * @param  bool  $once
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function isTaken(#[\SensitiveParameter] object $event, bool $once): bool
    {
        $events = $this->container->make(CapturedEvents::class);

        return $events->isDescribing($event) || ($once && $events->isClaimed($event));
    }

    /**
     * Describe the event, and write the builder its source returned with the
     * capture's signal, containing any failure. The transactions open are read
     * first, since Laravel forgets one whose connection is lost.
     *
     * @param  object  $event
     * @param  string  $source
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): ?\SineMacula\Laravel\AuditLog\Records\PendingRecord  $describe
     * @param  bool  $once
     * @param  bool  $mayDefer
     * @return ?\SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \Illuminate\Database\DeadlockException
     * @throws \RuntimeException
     */
    private function run(#[\SensitiveParameter] object $event, string $source, #[\SensitiveParameter] \Closure $describe, bool $once, bool $mayDefer): ?AuditRecord
    {
        $eventClass = get_debug_type($event);
        $open       = [];
        $signal     = null;

        try {
            $open    = $this->openTransactions();
            $pending = $this->described($event, $describe, $once, $mayDefer);

            if ($pending === null) {
                return null;
            }

            $signal = new CaptureSignal(self::announcer($this->container, $eventClass, $source));
            $record = $this->container->make(RecordPipeline::class)->write($pending, $signal);

            return $signal->hasFailed() ? null : $record;
        } catch (\Throwable $failure) {
            return $this->contain($failure, $eventClass, $source, $signal, $open);
        }
    }

    /**
     * The builder to write: the event described on a builder with no recorder
     * inside the mapping window, with its object marked as being described,
     * checked, and its event object claimed, or `null` when the source skipped
     * the event or the object was claimed meanwhile.
     *
     * @param  object  $event
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): ?\SineMacula\Laravel\AuditLog\Records\PendingRecord  $describe
     * @param  bool  $once
     * @param  bool  $mayDefer
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function described(#[\SensitiveParameter] object $event, #[\SensitiveParameter] \Closure $describe, bool $once, bool $mayDefer): ?PendingRecord
    {
        $events   = $this->container->make(CapturedEvents::class);
        $pending  = new PendingRecord;
        $returned = $events->whileDescribing($event, static fn (): ?PendingRecord => $describe($pending));

        if ($returned === null) {
            return null;
        }

        self::checkReturned($returned, $pending, $mayDefer);

        return !$once || $events->claims($event) ? $pending : null;
    }

    /**
     * Refuse what a source returned unless it is the builder it was given,
     * still to be recorded, with no say in how it is written: no timing, unless
     * the source may defer, and then only immediately or after commit, and
     * neither fail-closed nor transactional.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $returned
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $given
     * @param  bool  $mayDefer
     * @return void
     *
     * @throws \LogicException
     */
    private static function checkReturned(#[\SensitiveParameter] PendingRecord $returned, #[\SensitiveParameter] PendingRecord $given, bool $mayDefer): void
    {
        if ($returned !== $given || $given->isConsumed()) {
            throw new \LogicException(self::NOT_ITS_BUILDER);
        }

        $snapshot = $given->snapshot();

        if ($snapshot->failClosed || $snapshot->timing === Timing::TRANSACTIONAL || ($snapshot->timing !== null && !$mayDefer)) {
            throw new \LogicException(self::CHOSE_DELIVERY);
        }
    }

    /**
     * Contain a capture's failure, and return `null`: a failure its write's
     * signal says is fatal is thrown as it is, a failure the signal has been
     * told of is already handled, and a failure fatal to a transaction open
     * before the capture ran is thrown sanitised once the capture's failure is
     * dispatched. Anything else is reported by class names alone and dispatched
     * as `AuditCaptureFailed`.
     *
     * @param  \Throwable  $failure
     * @param  string  $eventClass
     * @param  ?string  $mapperClass
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $signal
     * @param  list<string>  $open
     * @return null
     *
     * @throws \Illuminate\Database\DeadlockException
     * @throws \RuntimeException
     */
    private function contain(#[\SensitiveParameter] \Throwable $failure, string $eventClass, ?string $mapperClass, #[\SensitiveParameter] ?CaptureSignal $signal, array $open): null
    {
        if ($signal?->isFatal() === true) {
            throw $failure;
        }

        if ($signal?->hasFailed() === true) {
            return null;
        }

        $fatal    = self::fatalOf($failure, $eventClass, $mapperClass, $open);
        $announce = self::announcer($this->container, $eventClass, $mapperClass);

        if ($fatal !== null) {

            $announce(get_debug_type($failure));

            throw $fatal;
        }

        self::report($this->container, CaptureFailedException::of($eventClass, $mapperClass, $failure));

        $announce(get_debug_type($failure));

        return null;
    }

    /**
     * What a failure is thrown as when it ended a transaction open before the
     * capture ran: the sanitised deadlock for a concurrency error, and a
     * capture failure naming its classes alone for a lost connection, on a
     * connection with a transaction open, or on any when it names none and one
     * was open; `null` for anything else.
     *
     * @param  \Throwable  $failure
     * @param  string  $eventClass
     * @param  ?string  $mapperClass
     * @param  list<string>  $open
     * @return ?\RuntimeException
     */
    private static function fatalOf(#[\SensitiveParameter] \Throwable $failure, string $eventClass, ?string $mapperClass, array $open): ?\RuntimeException
    {
        $classifier  = new FailureClassifier;
        $concurrency = $classifier->isConcurrencyError($failure);

        if (!$concurrency && !$classifier->isLostConnection($failure)) {
            return null;
        }

        if (!$classifier->reachesAnOpenTransaction([$classifier->connectionOf($failure)], $open, $open !== [])) {
            return null;
        }

        return $concurrency ? FailureClassifier::sanitisedDeadlock() : CaptureFailedException::of($eventClass, $mapperClass, $failure);
    }

    /**
     * What dispatches `AuditCaptureFailed` for the capture, given the class of
     * its failure: it holds the three class names and the container alone,
     * never the event or the builder, since a deferred write calls it when a
     * commit runs. It dispatches inside the write guard, and nothing it meets
     * goes further.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $eventClass
     * @param  ?string  $mapperClass
     * @return \Closure(string): void
     */
    private static function announcer(Container $container, string $eventClass, ?string $mapperClass): \Closure
    {
        return static function (string $exceptionClass) use ($container, $eventClass, $mapperClass): void {
            try {
                $container->make(WriteGuard::class)->during(static function () use ($container, $eventClass, $mapperClass, $exceptionClass): void {
                    self::dispatchFailure($container, $eventClass, $mapperClass, $exceptionClass);
                });
            } catch (\Throwable) {
                // Saying that a capture failed must never fail the code that
                // dispatched the event, and there is nowhere left to say so
            }
        };
    }

    /**
     * Dispatch `AuditCaptureFailed` with the three class names. A listener's
     * failure is reported by the capture's class names and its own class, and
     * goes no further.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $eventClass
     * @param  ?string  $mapperClass
     * @param  string  $exceptionClass
     * @return void
     */
    private static function dispatchFailure(Container $container, string $eventClass, ?string $mapperClass, string $exceptionClass): void
    {
        try {
            $container->make(Dispatcher::class)->dispatch(new AuditCaptureFailed($eventClass, $mapperClass, $exceptionClass));
        } catch (\Throwable $failure) {
            self::report($container, CaptureFailedException::of($eventClass, $mapperClass, $failure));
        }
    }

    /**
     * Report a capture's failure inside the write guard. A reporter that fails
     * is ignored.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\AuditLog\Capture\CaptureFailedException  $exception
     * @return void
     */
    private static function report(Container $container, #[\SensitiveParameter] CaptureFailedException $exception): void
    {
        try {
            $container->make(WriteGuard::class)->during(static function () use ($container, $exception): void {
                $container->make(ExceptionHandler::class)->report($exception);
            });
        } catch (\Throwable) {
            // A broken reporter has nowhere left to say so, and must not fail
            // the code that dispatched the event
        }
    }

    /**
     * Whether the write guard is active, so nothing is captured.
     *
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function isGuarded(): bool
    {
        return $this->container->make(WriteGuard::class)->isActive();
    }

    /**
     * The connections with a transaction open, read before anything of the
     * capture runs, or none when they cannot be read.
     *
     * @return list<string>
     */
    private function openTransactions(): array
    {
        try {
            return (new OpenTransactions($this->container->make(ConnectionResolverInterface::class)))->names();
        } catch (\Throwable) {
            // With no connections to read none was open, so no failure of the
            // capture can have ended a transaction
            return [];
        }
    }
}
