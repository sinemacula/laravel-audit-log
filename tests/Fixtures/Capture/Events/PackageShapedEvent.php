<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Events;

use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;

/**
 * An event shaped like one of the package's own: a portal event that also
 * implements the package's event marker, so a broad mapping of `PortalEvent`
 * must still never capture it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PackageShapedEvent implements AuditLogEvent, PortalEvent
{
    /**
     * The id of the user the event is about.
     *
     * @return string
     */
    #[\Override]
    public function userId(): string
    {
        return '42';
    }
}
