<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Events;

use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;

/**
 * Dispatched when the store has accepted a record, carrying the record's id,
 * code and category and nothing else, so no value of the record reaches a
 * listener.
 *
 * Accepted is not always durable: for a `transactional()` write, or an
 * immediate write inside a transaction, the record is durable only once that
 * transaction commits, and a rollback after this event removes it. The event is
 * dispatched outside the write, so a failed write dispatches nothing and a
 * listener's failure never causes another write. An exception from a
 * synchronous listener is reported and goes no further, with one exception: a
 * deadlock or a lost connection on a connection with a host transaction open
 * has already ended that transaction, so it propagates sanitised. A queued
 * listener follows Laravel's normal handling. In outbox mode it follows the
 * drain's store and delete, not the insert.
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
