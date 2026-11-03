<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Events;

use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;

/**
 * Dispatched when an event could not be captured, carrying the class of the
 * event, the class of what translated it and the class of the exception the
 * capture failed with, and nothing else: no value of the event, of the record
 * it would have made or of the exception, whose message can hold them, reaches
 * a listener.
 *
 * It is dispatched once for each capture that failed, synchronously as the
 * capture fails or, for a model change written after its commit, when that
 * commit runs the write. The capture itself returns nothing and the code that
 * dispatched the event goes on. The event is dispatched inside the write guard,
 * so a record made by a listener is refused rather than written.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuditCaptureFailed implements AuditLogEvent
{
    /**
     * Constructor.
     *
     * @param  string  $eventClass
     * @param  ?string  $mapperClass
     * @param  string  $exceptionClass
     */
    public function __construct(

        /** The class of the event, or of the watched model, that was not captured, an anonymous one named without its file. */
        public string $eventClass,

        /** The class of the mapper or the package listener that translated the event, or `null` when more than one mapping matched it. */
        public ?string $mapperClass,

        /** The class of the exception the capture failed with, never its message. */
        public string $exceptionClass,
    ) {}
}
