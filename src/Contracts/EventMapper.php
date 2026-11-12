<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * Event mapper contract: translates a dispatched event into the record of what
 * happened.
 *
 * An implementation keeps no state, names its own code rather than deriving one
 * from the event's class, never records anything itself, and never chooses a
 * timing, `failClosed()` or `transactional()`. Anything else it gets wrong,
 * throwing included, is a contained capture failure.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EventMapper
{
    /**
     * The builder given, with its code and translated fields set, or `null` to
     * skip the event.
     *
     * @param  object  $event
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): ?PendingRecord;
}
