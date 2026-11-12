<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle\Enums;

/**
 * How a rewrap ended; the run's `audit_log.keys_rewrapped` record carries it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RewrapStatus: string
{
    // Every key the run considered was rewrapped or rotated
    case COMPLETE = 'complete';

    // The run skipped a key that failed its signature or did not unwrap,
    // leaving it as it was
    case PARTIAL = 'partial';
}
