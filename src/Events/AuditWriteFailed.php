<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Events;

use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;

/**
 * Dispatched when a record could not be written, carrying the record's id and
 * code, the class of the store that failed and the class of the exception it
 * failed with, and nothing else: no value of the record and no text of the
 * exception, whose message can hold the record's values, reaches a listener.
 *
 * The event is dispatched inside the write guard, so a record made by a
 * listener is refused rather than written: it would fail the same way.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuditWriteFailed implements AuditLogEvent
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $code
     * @param  string  $store
     * @param  string  $exception
     */
    public function __construct(

        /** The record's id. */
        public string $id,

        /** The event code naming what happened. */
        public string $code,

        /** The class of the store the write failed on, an anonymous one named without its file. */
        public string $store,

        /** The class of the exception the write failed with, never its message. */
        public string $exception,
    ) {}
}
