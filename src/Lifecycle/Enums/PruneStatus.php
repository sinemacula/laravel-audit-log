<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle\Enums;

/**
 * How a prune run ended; the run's journal finish row and its
 * `audit_log.pruned` record carry it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum PruneStatus: string
{
    // The run walked every seal and deleted every eligible entry
    case COMPLETE = 'complete';

    // The run hit its time budget, skipped an unauthenticated seal, or kept a
    // held or undelivered entry
    case PARTIAL = 'partial';

    // The run stopped on a failure; the chunks it committed stand
    case FAILED = 'failed';
}
