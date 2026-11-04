<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle\Enums;

/**
 * Why a hold was placed, as the operator who placed it states it. The package
 * records the basis and decides nothing from it: whether a claim, a regulation
 * or an investigation needs the entries kept is the operator's judgement, and a
 * hold of any basis keeps every entry its scope matches.
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
