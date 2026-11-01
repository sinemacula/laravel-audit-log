<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Definitions\Enums;

use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;

/**
 * An application's invoice activity, defined as the design's example defines
 * it: an approval whose payload contract is on its second version, and a failed
 * refund whose card holder is encrypted for the invoice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum InvoiceActivity: string implements DefinesAuditEvents
{
    // An invoice was approved
    case APPROVED = 'invoice.approved';

    // A refund of an invoice failed
    case REFUND_FAILED = 'invoice.refund_failed';

    /**
     * The definition of this case's event code.
     *
     * @return \SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     */
    #[\Override]
    public function definition(): EventDefinition
    {
        return match ($this) {
            self::APPROVED => EventDefinition::for($this)->category('finance')->version(2)
                ->retain('amount', 'currency')->pseudonymise('approver_email'),
            self::REFUND_FAILED => EventDefinition::for($this)->category('finance')
                ->retain('amount')->encrypt('card_holder', owner: KeyOwner::SUBJECT),
        };
    }
}
