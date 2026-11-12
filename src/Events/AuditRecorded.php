<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Events;

use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;

/**
 * Dispatched when the store has accepted a record, carrying its id, code and
 * category only, outside the write, so a listener's failure never causes
 * another write.
 *
 * Accepted is not always durable: inside a transaction the record is durable
 * only once that commits, and a rollback after this event removes it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuditRecorded implements AuditLogEvent
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $code
     * @param  string  $category
     */
    public function __construct(

        /** The record's id. */
        public string $id,

        /** The event code naming what happened. */
        public string $code,

        /** The category of the code's definition. */
        public string $category,
    ) {}
}
