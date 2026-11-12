<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;

/**
 * Event definitions contract: a string-backed enum whose cases are the
 * application's event codes, each defining its own. A case's definition is the
 * same on every call.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface DefinesAuditEvents extends \BackedEnum
{
    /**
     * The definition of this case's own code: `EventDefinition::for($this)`
     * with its version, category and field rules.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     */
    public function definition(): EventDefinition;
}
