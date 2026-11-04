<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

/**
 * Marks the window a read of the trail spans, from its authorisation through
 * its query and the delivery of its record to that record's notification, and
 * the notification of every record of the package's own, wherever it is
 * delivered: a read of the trail entered inside the window is refused, since it
 * would record a read whose listeners could read again, until the process ran
 * out of memory.
 *
 * Windows nest: the guard is active from the start of the outermost window to
 * its end, however that work ends, and a window inside another changes nothing.
 * Only the first refusal in a window is to be reported, so a recursion that is
 * refused many times is diagnosed once; the refusal is forgotten when the
 * outermost window ends. The window is kept exactly as the write guard keeps
 * its own, by a write guard of the read guard's own that no write ever sees, so
 * the two cannot drift apart and neither window opens the other.
 *
 * A queued listener runs later in a worker, outside every window, so the guard
 * cannot reach it. The guard is scoped, so it holds nothing from one request or
 * job to the next, and only a shared instance guards anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReadGuard
{
    /** @var \SineMacula\Laravel\AuditLog\Runtime\WriteGuard The window, kept as a write guard keeps its own and shared with no write. */
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
        return $this->window->during($work);
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
        return $this->window->isFirstRefusal();
    }
}
