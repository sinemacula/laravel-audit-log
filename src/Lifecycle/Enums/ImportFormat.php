<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle\Enums;

/**
 * The formats an import reads, each a versioned NDJSON format: the import
 * format, whose every line names it, and the export format of this package,
 * whose lines an import reads as another installation's evidence.
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
