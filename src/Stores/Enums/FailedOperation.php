<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores\Enums;

/**
 * The step of the write path that failed, as a failed write's diagnostics name
 * it: preparing the record, writing it to the store or the outbox, keeping it
 * aside after a failure, dispatching `AuditRecorded`, or delivering it from the
 * outbox.
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
