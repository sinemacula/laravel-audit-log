<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery\Enums;

/**
 * How a record reaches its store, under `audit-log.delivery.mode`: written to
 * the store by the code that records it, or put in the outbox for the drain to
 * deliver.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum DeliveryMode: string
{
    // Written to the store by the code that records it
    case SYNC = 'sync';

    // Inserted in the outbox, encrypted, and delivered by the drain
    case OUTBOX = 'outbox';
}
