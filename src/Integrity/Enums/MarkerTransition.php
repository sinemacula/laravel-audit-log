<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Enums;

/**
 * What an owner marker records: the owner was erased, or an erased owner was
 * reinstated. The owner's latest marker decides whether a key may be created
 * for it: none is while the latest is an erasure.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum MarkerTransition: string
{
    // The owner was erased, and no key is created for it until a reinstatement
    case ERASED = 'erased';

    // An erased owner was reinstated, and its next key is above the floor
    case REINSTATED = 'reinstated';
}
