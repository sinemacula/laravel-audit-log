<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying\Enums;

/**
 * Why a read was refused, as `AuditReadRefusedException::$reason` gives it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ReadRefusal: string
{
    // Entered while a read, a write or an event mapper was running
    case REENTRANT = 'reentrant';

    // A transaction was open that could roll the read's record back
    case IN_TRANSACTION = 'in_transaction';

    // In sync mode, the bound store does not say its return is durable
    case NOT_DURABLE = 'not_durable';

    // In sync mode, the bound store keeps no attachment a read's record needs
    case KEEPS_NO_ARTIFACTS = 'keeps_no_artifacts';

    // The read's record could not be written, or was never acknowledged
    case UNRECORDED = 'unrecorded';

    // The read's record would not have kept its evidence exactly
    case EVIDENCE_ALTERED = 'evidence_altered';

    // The read itself failed: its statement, or formatting what it found
    case FAILED = 'failed';

    // The export was recorded, and its file could not be published
    case PUBLISH_FAILED = 'publish_failed';
}
