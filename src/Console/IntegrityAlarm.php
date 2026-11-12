<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityCheckFailedException;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;

/**
 * How `audit-log:seal` and `audit-log:verify` raise an integrity alarm:
 * dispatch a payload-free `IntegrityCheckFailed`, then report its exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IntegrityAlarm
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Debug\ExceptionHandler  $handler
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     */
    public function __construct(

        /** The handler the alarm, and a listener's failure, are reported to. */
        private ExceptionHandler $handler,

        /** The dispatcher the event is dispatched through. */
        private Dispatcher $events,
    ) {}

    /**
     * Dispatch the event and report the exception it gives, or the one given
     * for a run that stopped.
     *
     * @param  \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed  $event
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\IntegrityCheckFailedException  $stopped
     * @return void
     */
    public function raise(IntegrityCheckFailed $event, #[\SensitiveParameter] ?IntegrityCheckFailedException $stopped = null): void
    {
        $event    = self::withNameableId($event);
        $events   = $this->events;
        $dispatch = static fn (): ?array => $events->dispatch($event);

        try {
            $dispatch();
        } catch (\Throwable $exception) {
            // A failing listener is reported and must not hide the alarm
            $this->report($exception);
        }

        $this->report($stopped ?? IntegrityCheckFailedException::of($event));
    }

    /**
     * Report the exception, ignoring a reporter that fails too.
     *
     * @param  \Throwable  $exception
     * @return void
     */
    public function report(#[\SensitiveParameter] \Throwable $exception): void
    {
        try {
            $this->handler->report($exception);
        } catch (\Throwable) {
            // The failure is already printed; there is nowhere left to say so
        }
    }

    /**
     * The event with its first bad id kept only when it is a lower-case UUID,
     * since an id read from an altered table may hold control characters.
     *
     * @param  \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed  $event
     * @return \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed
     */
    private static function withNameableId(IntegrityCheckFailed $event): IntegrityCheckFailed
    {
        if ($event->firstBadId === null || preg_match(SealEnvelope::UUID_PATTERN, $event->firstBadId) === 1) {
            return $event;
        }

        return new IntegrityCheckFailed($event->command, $event->integrity, $event->anchoring, $event->finding, null, $event->head, $event->remoteHead, $event->complete);
    }
}
