<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores\Enums;

/**
 * The write path step that failed, as named in a failed write's diagnostics.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FailedOperation: string
{
    // Finalising the record: its digest, its signature and its row
    case FINALISE = 'finalise';

    // Writing the finalised record to the store
    case STORE = 'store';

    // Writing the record to the outbox for a later drain
    case OUTBOX = 'outbox';

    // Writing the replayable line a failed write leaves behind
    case SPILL = 'spill';

    // Telling the listeners of the package's event that the record was written
    case NOTIFY = 'notify';

    // Delivering an outbox row to the store or one of its destinations
    case DRAIN = 'drain';
}
