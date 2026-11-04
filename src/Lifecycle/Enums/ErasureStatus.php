<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle\Enums;

/**
 * How an erasure that was not refused ended: every key of the owner destroyed,
 * some destroyed and the rest kept because holds or preservation block them, or
 * nothing to do because the owner was already erased and holds no key. The
 * erasure's `audit_log.subject_erased` record carries it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ErasureStatus: string
{
    // Every live or superseded key of the owner was destroyed, and the owner
    // marked erased
    case COMPLETE = 'complete';

    // An erasure asked to go ahead in part destroyed the keys nothing blocks,
    // kept the rest with their reasons, and marked the owner erased
    case PARTIAL = 'partial';

    // The owner was already erased and holds no key, so nothing was written
    case ALREADY_ERASED = 'already_erased';
}
