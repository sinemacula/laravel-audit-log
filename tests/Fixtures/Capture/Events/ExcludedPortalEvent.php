<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Events;

/**
 * A portal event that a broad mapping of `PortalEvent` excepts, so it is left
 * unmapped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExcludedPortalEvent implements PortalEvent
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
