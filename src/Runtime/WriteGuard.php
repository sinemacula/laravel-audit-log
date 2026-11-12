<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

/**
 * Marks the window in which the package writes a record or handles a failed
 * write, refusing a record made inside it, which would otherwise recurse.
 *
 * Windows nest, and only the first refusal per window is reported. A
 * contributor and a listener of a written record run outside it. Scoped per
 * request or job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class WriteGuard
{
    /** @var int How many windows are open, the outermost included. */
    private int $depth = 0;

    /** @var bool Whether a record has been refused in the open window. */
    private bool $refused = false;

    /**
     * Whether a window is open, so a record made now is refused.
     *
     * @return bool
     */
    public function isActive(): bool
    {
        return $this->depth > 0;
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
        $this->depth++;

        try {
            return $work();
        } finally {
            $this->depth--;

            if ($this->depth === 0) {
                $this->refused = false;
            }
        }
    }

    /**
     * Whether this is the first refusal in the open window, so the caller
     * reports it; always `false` outside a window.
     *
     * @return bool
     */
    public function isFirstRefusal(): bool
    {
        if (!$this->isActive() || $this->refused) {
            return false;
        }

        $this->refused = true;

        return true;
    }
}
