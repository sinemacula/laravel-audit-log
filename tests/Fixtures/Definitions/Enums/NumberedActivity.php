<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Definitions\Enums;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;

/**
 * An integer-backed enum implementing the definitions contract, which cannot
 * define event codes because its values are not strings.
 *
 * Its case defines a code other than its value, so a catalogue that asked the
 * cases for their definitions before checking the backing type would refuse it
 * as defining another event code instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum NumberedActivity: int implements DefinesAuditEvents
{
    // A case whose value is an integer, not a code
    case FIRST = 1;

    /**
     * The definition of `app.first`, which is not this case's value.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     */
    #[\Override]
    public function definition(): EventDefinition
    {
        return EventDefinition::for('app.first');
    }
}
