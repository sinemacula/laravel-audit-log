<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle\Enums;

/**
 * Why a hold was placed, as its operator states it; recorded only, since a hold
 * of any basis keeps every entry its scope matches.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum HoldBasis: string
{
    // The establishment, exercise or defence of a legal claim
    case LEGAL_CLAIM = 'legal_claim';

    // A regulator's requirement or request
    case REGULATORY = 'regulatory';

    // An internal or external investigation
    case INVESTIGATION = 'investigation';

    // Any other basis, stated by the hold's reason and external reference
    case OTHER = 'other';
}
