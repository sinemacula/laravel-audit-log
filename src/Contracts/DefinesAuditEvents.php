<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;

/**
 * Event definitions contract: a string-backed enum whose cases are the
 * application's event codes, each defining its own.
 *
 * Registered at boot with `AuditLog::define(InvoiceActivity::class)`, which
 * registers every case's definition or, when any is refused, none of them. The
 * contract extends `\BackedEnum`, so only an enum can implement it, and the
 * enum must be backed by strings, since each value is a code. An implementation
 * must keep no state: a case's definition is the same on every call.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface DefinesAuditEvents extends \BackedEnum
{
    /**
     * The definition of this case's event code: `EventDefinition::for($this)`
     * with its version, category and field rules. It must be for this case's
     * own code.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     */
    public function definition(): EventDefinition;
}
