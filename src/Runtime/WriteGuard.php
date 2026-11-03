<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

/**
 * Marks the window in which the package is writing a record or handling a
 * failed write, so a record made from inside that window, by a store, a
 * reporter, a spill channel or a listener of a failed write, is refused rather
 * than written: such a record would fail or be refused the same way, and
 * without the guard would recurse until the process ran out of memory.
 *
 * Windows nest: the guard is active from the start of the outermost window to
 * its end, however that work ends, and a window inside another changes nothing.
 * Only the first refusal in a window is to be reported, so a recursion that is
 * refused many times is diagnosed once; the refusal is forgotten when the
 * outermost window ends.
 *
 * A contributor and a listener of a written record run outside the window, so
 * one that records unconditionally still recurses, and it is the application's
 * to stop. The guard is scoped, so it holds nothing from one request or job to
 * the next, and only a shared instance guards anything.
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
     * Run the work inside a window and return what it returns, closing the
     * window however the work ends; the outermost window's end forgets the
     * refusal.
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
     * Whether this is the first refusal in the open window, so the caller says
     * it: `true` once per outermost window, and `false` after that until the
     * window ends. Outside a window nothing is refused, so it is `false` and
     * nothing is remembered.
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
