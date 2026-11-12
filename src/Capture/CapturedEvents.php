<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

/**
 * The event objects claimed or being described, so one object gives one record,
 * and the mapping window in which explicit writes are refused.
 *
 * Scoped, and holds every event weakly, so nothing outlives its request or job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CapturedEvents
{
    /** @var \WeakMap<object, true> The event objects claimed, each held weakly. */
    private \WeakMap $claimed;

    /** @var \WeakMap<object, true> The event objects whose description is running, each held weakly. */
    private \WeakMap $describing;

    /** @var int How many mapping windows are open, the outermost included. */
    private int $mapping = 0;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->claimed    = new \WeakMap;
        $this->describing = new \WeakMap;
    }

    /**
     * Whether the event object has been claimed. Asking claims nothing.
     *
     * @param  object  $event
     * @return bool
     */
    public function isClaimed(#[\SensitiveParameter] object $event): bool
    {
        return isset($this->claimed[$event]);
    }

    /**
     * Whether this call claims the event object; `false` once it has been
     * claimed.
     *
     * @param  object  $event
     * @return bool
     */
    public function claims(#[\SensitiveParameter] object $event): bool
    {
        if ($this->isClaimed($event)) {
            return false;
        }

        $this->claimed[$event] = true;

        return true;
    }

    /**
     * Run the work inside a mapping window, closing it however the work ends.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $work
     * @return TResult
     *
     * @param-immediately-invoked-callable $work
     */
    public function whileMapping(#[\SensitiveParameter] \Closure $work): mixed
    {
        $this->mapping++;

        try {
            return $work();
        } finally {
            $this->mapping--;
        }
    }

    /**
     * Run the description inside a mapping window with the event object marked
     * as being described, unmarking it however it ends.
     *
     * @template TResult
     *
     * @param  object  $event
     * @param  \Closure(): TResult  $describe
     * @return TResult
     *
     * @param-immediately-invoked-callable $describe
     */
    public function whileDescribing(#[\SensitiveParameter] object $event, #[\SensitiveParameter] \Closure $describe): mixed
    {
        $this->describing[$event] = true;

        try {
            return $this->whileMapping($describe);
        } finally {
            unset($this->describing[$event]);
        }
    }

    /**
     * Whether the event object's description is running now.
     *
     * @param  object  $event
     * @return bool
     */
    public function isDescribing(#[\SensitiveParameter] object $event): bool
    {
        return isset($this->describing[$event]);
    }

    /**
     * Whether a mapping window is open, so an explicit write now is refused.
     *
     * @return bool
     */
    public function isMapping(): bool
    {
        return $this->mapping > 0;
    }
}
