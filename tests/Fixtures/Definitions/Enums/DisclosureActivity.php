<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Definitions\Enums;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;

/**
 * An application's disclosure activity, defined as a disclosure must be: its
 * definition retains `purpose`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum DisclosureActivity: string implements DefinesAuditEvents
{
    // A document was downloaded
    case DOCUMENT_DOWNLOADED = 'document.downloaded';

    /**
     * The definition of this case's event code.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     */
    #[\Override]
    public function definition(): EventDefinition
    {
        return EventDefinition::for($this)->category('disclosure')->retain('purpose');
    }
}
