<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

/**
 * The event objects captured so far, and the window in which a mapper runs.
 *
 * An event object is claimed by the first source that returns a builder for it,
 * just before that builder is written, so a class and its interface mapped
 * together, an event dispatched twice, or a mapping and a package listener of
 * the same event give one record; a source that skips the event leaves it for
 * another. A claim is held weakly, so it goes with its event and keeps nothing
 * of it alive.
 *
 * While a mapper, or a package source's description, runs, the mapping window
 * is open and no record is written by the application: a mapper returns its
 * builder and the capture writes it. A capture of another event that the
 * description sets off, a watched model it saves or a Gate check it denies, is
 * still written by its own capture. Windows nest, and each closes however its
 * work ends.
 *
 * The event object being described is marked for as long as its description
 * runs, so a description that captures or dispatches the same object again is
 * not described a second time inside the first: the inner capture writes
 * nothing, and the outer one goes on. The mark is held weakly and removed
 * however the description ends, so a source that skips the event leaves it free
 * for another.
 *
 * It is scoped, so nothing outlives the request or job it was made in, and only
 * a shared instance claims or guards anything.
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
     * Whether this call claims the event object for the source about to write
     * it: `true` the first time, and `false` once it has been claimed.
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
     * Run the work inside a mapping window and return what it returns, closing
     * the window however the work ends.
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
     * Run the description of the event object inside a mapping window, with the
     * object marked as being described, and return what it returns, removing
     * the mark and closing the window however the description ends.
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
     * Whether the event object's description is running now, so capturing it
     * again would describe it inside its own description.
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
