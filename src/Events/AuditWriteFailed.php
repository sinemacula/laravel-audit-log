<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Events;

use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;

/**
 * Dispatched when a record could not be written, carrying its id and code and
 * the classes of the store and the exception, never a value of the record or
 * the exception's message.
 *
 * It is dispatched inside the write guard, so a record made by a listener is
 * refused rather than written.
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
