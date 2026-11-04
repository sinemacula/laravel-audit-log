<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle\Enums;

/**
 * How a prune run ended: every entry it found eligible was deleted, it stopped
 * or left some eligible entries behind, or it failed. The journal's finish row
 * of a run and its `audit_log.pruned` record both carry it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum PruneStatus: string
{
    // The run walked every seal to its boundary and deleted every entry it
    // found eligible
    case COMPLETE = 'complete';

    // The run stopped on its time budget, skipped a seal it could not
    // authenticate, or left an eligible entry that is held or awaits delivery
    case PARTIAL = 'partial';

    // The run stopped on a failure; the chunks it committed stand
    case FAILED = 'failed';
}
