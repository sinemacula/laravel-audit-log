<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Definitions\Enums;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;

/**
 * An enum whose second case defines another event code than its own, which a
 * catalogue refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum MisdefinedActivity: string implements DefinesAuditEvents
{
    // A case defined correctly
    case VALID = 'app.valid';

    // A case whose definition is for `app.second`
    case FIRST = 'app.first';

    /**
     * The definition of this case's event code, or another for `FIRST`.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     */
    #[\Override]
    public function definition(): EventDefinition
    {
        return match ($this) {
            self::VALID => EventDefinition::for($this),
            self::FIRST => EventDefinition::for('app.second'),
        };
    }
}
