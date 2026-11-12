<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records\Enums;

/**
 * Why an envelope read back from the outbox or a spill line was refused, each
 * counted on its own.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum EnvelopeFailure: string
{
    // The signature does not match the envelope's content
    case SIGNATURE_MISMATCH = 'signature_mismatch';

    // The envelope names an integrity key the ring does not hold
    case UNKNOWN_KEY = 'unknown_key';

    // The envelope's record or integrity version is not one this release reads
    case UNSUPPORTED_VERSION = 'unsupported_version';

    // The envelope is not a well-formed record of its version
    case MALFORMED = 'malformed';

    // The envelope ends before its JSON value does
    case TRUNCATED = 'truncated';

    // The envelope says it was never signed
    case UNSIGNED = 'unsigned';

    // The envelope's id is not the id it was kept under
    case ID_MISMATCH = 'id_mismatch';

    // The envelope is larger than any record can be
    case OVERSIZE = 'oversize';
}
