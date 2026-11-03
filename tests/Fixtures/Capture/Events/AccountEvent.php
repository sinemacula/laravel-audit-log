<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Events;

/**
 * An event about an account, a second interface an event can have beside
 * `PortalEvent`, so two broad mappings can both apply to one event: every event
 * of an account names the account it is about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface AccountEvent // phpcs:ignore SineMacula.Namespaces.RequireContractsNamespace.NotInContracts
{
    /**
     * The id of the account the event is about.
     *
     * @return string
     */
    public function accountId(): string;
}
