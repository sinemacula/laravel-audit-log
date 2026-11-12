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
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;

/**
 * Captures events as records, containing every failure but one fatal to a
 * transaction open before the capture, which propagates sanitised.
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
    private const string CHOSE_DELIVERY = 'A capture decides how its record is written, so its source sets no timing but `afterTransaction()`,'
        . ' and no `failClosed()` or `transactional()`.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container everything a capture uses is resolved from. */
        private Container $container,
    ) {}

    /**
     * Capture an event through its registered mapper; `null` when nothing was
     * written. Only a failure fatal to an open transaction is thrown.
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
     * Capture an event a package source describes; `null` when nothing was
     * written. With `$once` the object is written once across sources, and only
     * a source that may defer chooses a timing: immediately or after commit.
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
     * The mapper class for the event, or `null` when it is not captured now.
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
     * Whether the event object is being described or, when captured once,
     * already claimed.
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
     * Describe the event and write its builder, containing any failure. Open
     * transactions are read first because Laravel forgets one whose connection
     * is lost.
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
     * The builder to write, described inside the mapping window and claimed, or
     * `null` when the source skipped the event or it was claimed meanwhile.
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
        $pending  = new PendingRecord(manifests: fn (#[\SensitiveParameter] iterable $subjects): Manifest => $this->container->make(BulkManifests::class)->of($subjects));
        $returned = $events->whileDescribing($event, static fn (): ?PendingRecord => $describe($pending));

        if ($returned === null) {
            return null;
        }

        self::checkReturned($returned, $pending, $mayDefer);

        return !$once || $events->claims($event) ? $pending : null;
    }

    /**
     * Refuse a return other than the given, unconsumed builder, or one that
     * chose fail-closed, transactional or, unless the source may defer, any
     * timing but after the transaction.
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

        $chose = $snapshot->timing !== null && $snapshot->timing !== Timing::AFTER_TRANSACTION && !$mayDefer;

        if ($snapshot->failClosed || $snapshot->timing === Timing::TRANSACTIONAL || $chose) {
            throw new \LogicException(self::CHOSE_DELIVERY);
        }
    }

    /**
     * Contain a capture's failure: rethrow one the signal marks fatal, throw
     * one fatal to an open transaction sanitised, and report anything else by
     * class names alone.
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
     * The sanitised exception for a concurrency error or lost connection that
     * ended a transaction open before the capture, or `null` for any other
     * failure.
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
     * What dispatches `AuditCaptureFailed` inside the write guard. It holds
     * class names and the container alone, since a deferred write calls it at
     * commit.
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
                // Announcing a failure must never fail the caller
            }
        };
    }

    /**
     * Dispatch `AuditCaptureFailed`, reporting a listener's failure instead of
     * throwing it.
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
     * Report a capture's failure inside the write guard, ignoring a reporter
     * that fails.
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
            // A broken reporter must never fail the caller
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
     * Connections with a transaction open, or none when they cannot be read.
     *
     * @return list<string>
     */
    private function openTransactions(): array
    {
        try {
            return (new OpenTransactions($this->container->make(ConnectionResolverInterface::class)))->names();
        } catch (\Throwable) {
            // No connection to read means no transaction was open
            return [];
        }
    }
}
