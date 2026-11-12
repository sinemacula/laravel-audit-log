<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Export\Enums;

/**
 * The format an export is written in, one line per entry. Only NDJSON is
 * evidence, each line the canonical encoding its HMAC was signed over; OCSF and
 * CEF are projections that still carry each entry's id.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ExportFormat: string
{
    // Each entry's signed envelope, exactly as stored
    case NDJSON = 'ndjson';

    // Each entry as an OCSF event, a projection
    case OCSF = 'ocsf';

    // Each entry as a CEF line, a projection
    case CEF = 'cef';

    /**
     * Whether each line is the entry's signed envelope, whose HMAC can be
     * checked: true for NDJSON alone.
     *
     * @return bool
     */
    public function isEvidence(): bool
    {
        return match ($this) {
            self::NDJSON => true,
            default      => false,
        };
    }
}
