<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Definitions\Enums;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;

/**
 * A second enum defining invoice activity, which puts the approval in another
 * category than `InvoiceActivity` does, so the two conflict.
 *
 * Its new code is declared before the conflicting one, so a catalogue that
 * stored each case as it checked it would have stored the new code before
 * refusing the enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum RevisedInvoiceActivity: string implements DefinesAuditEvents
{
    // An invoice was voided, a code no other enum defines
    case VOIDED = 'invoice.voided';

    // An invoice was approved, in the `billing` category
    case APPROVED = 'invoice.approved';

    /**
     * The definition of this case's event code.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     */
    #[\Override]
    public function definition(): EventDefinition
    {
        return match ($this) {
            self::VOIDED   => EventDefinition::for($this)->category('billing'),
            self::APPROVED => EventDefinition::for($this)->category('billing')->version(2)
                ->retain('amount', 'currency')->pseudonymise('approver_email'),
        };
    }
}
