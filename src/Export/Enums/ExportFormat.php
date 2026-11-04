<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Export\Enums;

/**
 * The format an export of the trail is written in, one line per entry. Only
 * NDJSON is evidence: each of its lines is the canonical encoding the entry was
 * signed over, so its HMAC can be checked line by line. OCSF and CEF are
 * projections a security tool reads, each line carrying the entry's id, so
 * which entries were exported can be checked in every format.
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
