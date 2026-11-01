<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Definitions\Enums;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;

/**
 * An enum whose case defines another event code than its own, which a catalogue
 * refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum MisdefinedActivity: string implements DefinesAuditEvents
{
    // A case whose definition is for `app.second`
    case FIRST = 'app.first';

    /**
     * The definition of another event code than this case's.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     */
    #[\Override]
    public function definition(): EventDefinition
    {
        return EventDefinition::for('app.second');
    }
}
