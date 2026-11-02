<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Definitions\Enums;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;

/**
 * An application's disclosure activity, defined as a disclosure must not be: no
 * rule names `purpose`, so it goes with the fields no rule names, which a
 * definition drops.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum UnretainedDisclosureActivity: string implements DefinesAuditEvents
{
    // A report was exported
    case REPORT_EXPORTED = 'report.exported';

    /**
     * The definition of this case's event code.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     */
    #[\Override]
    public function definition(): EventDefinition
    {
        return EventDefinition::for($this)->category('disclosure');
    }
}
