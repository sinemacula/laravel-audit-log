<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle\Enums;

/**
 * The versioned NDJSON formats an import reads.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ImportFormat: string
{
    // A line of the import format, which names it in its `format` field
    case IMPORT_V1 = 'audit-log-import/v1';

    // A line of this package's export, read with `--from-export`
    case EXPORT_V1 = 'audit-log-export/v1';
}
