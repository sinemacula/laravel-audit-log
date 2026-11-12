<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery\Enums;

/**
 * How one attempt to deliver an outbox row's record to every destination ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum DeliveryOutcome: string
{
    // Every destination has the record, so the row may be deleted
    case COMPLETE = 'complete';

    // At least one destination failed, so the row is retried or failed
    case INCOMPLETE = 'incomplete';

    // Another drain owns the row now, so this one writes nothing further
    case STALE = 'stale';
}
