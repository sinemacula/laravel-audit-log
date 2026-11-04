<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle\Enums;

/**
 * How a rewrap ended: every key it considered was rewrapped, or rotated, or it
 * skipped a key it could not authenticate or unwrap, which keeps its wrapping
 * until a later run. The run's `audit_log.keys_rewrapped` record carries it.
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

    // The run skipped a key whose row failed its signature or whose wrapped key
    // did not unwrap, and left it as it was
    case PARTIAL = 'partial';
}
