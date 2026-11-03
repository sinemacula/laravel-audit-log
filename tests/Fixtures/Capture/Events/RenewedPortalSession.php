<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Events;

/**
 * A user's portal session was renewed: a subclass of `PortalSignedIn`, which
 * reaches that class's mapping when it has none of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RenewedPortalSession extends PortalSignedIn {}
