<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Events;

/**
 * An event of the portal an application signs its users in to, which a broad
 * mapping is registered for: every event of the portal names the user it is
 * about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface PortalEvent // phpcs:ignore SineMacula.Namespaces.RequireContractsNamespace.NotInContracts
{
    /**
     * The id of the user the event is about.
     *
     * @return string
     */
    public function userId(): string;
}
