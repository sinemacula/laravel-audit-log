<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

/**
 * Tells the capture that made a record, once, that the record could not be
 * written, even when the write ran at a later commit.
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

    /** @var ?string Class of the first failure, or `null` while none has been signalled. */
    private ?string $exceptionClass = null;

    /** @var bool Whether the first failure ended a transaction and is thrown to the capture. */
    private bool $fatal = false;

    /**
     * Constructor.
     *
     * @param  \Closure(string): void  $onFailure
     */
    public function __construct(

        /** Receives the class of the first failure, once. */
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
     * Keep the first failure and pass its class to the capture once; a later
     * failure changes nothing.
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
            // The capture's callback contains its own failures; one that
            // escapes must not stop the failure path
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
     * Whether the first failure is fatal and thrown to the capture.
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
