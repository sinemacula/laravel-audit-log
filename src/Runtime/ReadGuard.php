<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

/**
 * Marks the window a read of the trail spans, through its record's
 * notification, so a read entered inside it is refused instead of recursing.
 *
 * It keeps the window with a private `WriteGuard`, so the two windows never
 * drift apart or open each other. Scoped; a queued listener runs outside every
 * window.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReadGuard
{
    /** @var \SineMacula\Laravel\AuditLog\Runtime\WriteGuard The window, kept by a write guard no write shares. */
    private WriteGuard $window;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->window = new WriteGuard;
    }

    /**
     * Whether a window is open, so a read entered now is refused.
     *
     * @return bool
     */
    public function isActive(): bool
    {
        return $this->window->isActive();
    }

    /**
     * Run the work inside a window, closing it however the work ends; the
     * outermost window's end forgets the refusal.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $work
     * @return TResult
     *
     * @param-immediately-invoked-callable $work
     */
    public function during(#[\SensitiveParameter] \Closure $work): mixed
    {
        return $this->window->during($work);
    }

    /**
     * Whether this is the first refusal in the open window, so the caller
     * reports it; always `false` outside a window.
     *
     * @return bool
     */
    public function isFirstRefusal(): bool
    {
        return $this->window->isFirstRefusal();
    }
}
