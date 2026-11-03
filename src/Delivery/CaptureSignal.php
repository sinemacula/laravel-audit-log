<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

/**
 * One capture's failure channel: how a record captured from an event says,
 * once, that it could not be written, to the capture that made it, including
 * when its write waits for a commit and runs long after the capture returned.
 *
 * The delivery marks it deferred before it queues the write, so the failure
 * path knows a failure fatal to an open transaction cannot be thrown to the
 * capture, which has already returned, and is reported instead. The first
 * failure is kept with whether it was fatal, and passed on once; any later one
 * changes nothing. The capture's callback contains its own failures, so one
 * that throws regardless stops nothing here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CaptureSignal
{
    /** @var bool Whether the write waits for a commit. */
    private bool $deferred = false;

    /** @var ?string The class of the first failure, as `get_debug_type()` names it, or `null` while none has been signalled. */
    private ?string $exceptionClass = null;

    /** @var bool Whether the first failure ended a transaction and is thrown to the capture. */
    private bool $fatal = false;

    /**
     * Constructor.
     *
     * @param  \Closure(string): void  $onFailure
     */
    public function __construct(

        /** What the capture does with the class of the first failure, once. */
        #[\SensitiveParameter]
        private readonly \Closure $onFailure,
    ) {}

    /**
     * Mark the write as waiting for a commit, before it is queued.
     *
     * @return void
     */
    public function defer(): void
    {
        $this->deferred = true;
    }

    /**
     * Whether the write waits for a commit.
     *
     * @return bool
     */
    public function isDeferred(): bool
    {
        return $this->deferred;
    }

    /**
     * Keep the first failure, with whether it is fatal, and pass its class on
     * to the capture once; a later failure changes nothing.
     *
     * @param  string  $exceptionClass
     * @param  bool  $fatal
     * @return void
     */
    public function fail(string $exceptionClass, bool $fatal): void
    {
        if ($this->exceptionClass !== null) {
            return;
        }

        $this->exceptionClass = $exceptionClass;
        $this->fatal          = $fatal;

        try {
            ($this->onFailure)($exceptionClass);
        } catch (\Throwable) {
            // The capture's callback contains its own failures, and one that
            // escapes regardless must not stop the failure path it was told by
        }
    }

    /**
     * Whether a failure has been signalled.
     *
     * @return bool
     */
    public function hasFailed(): bool
    {
        return $this->exceptionClass !== null;
    }

    /**
     * Whether the first failure ended a transaction and is thrown to the
     * capture.
     *
     * @return bool
     */
    public function isFatal(): bool
    {
        return $this->fatal;
    }

    /**
     * The class of the first failure, or `null` while none has been signalled.
     *
     * @return ?string
     */
    public function exceptionClass(): ?string
    {
        return $this->exceptionClass;
    }
}
