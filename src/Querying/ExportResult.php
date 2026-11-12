<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Querying\Enums\Acknowledgement;

/**
 * A published export; returned only once its journal entry was acknowledged and
 * its bundle and file published.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExportResult
{
    /**
     * Constructor.
     *
     * @param  string  $entryId
     * @param  string  $path
     * @param  string  $manifestPath
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @param  int  $lines
     * @param  string  $fileSha256
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\Acknowledgement  $acknowledgement
     *
     * @internal
     */
    public function __construct(

        /** The id of the `audit_log.trail_exported` entry that journals the export. */
        public string $entryId,

        /** Where the export's file was published. */
        public string $path,

        /** Where the bundle was published: the path plus `.manifest.json`. */
        public string $manifestPath,

        /** The format the file is written in. */
        public ExportFormat $format,

        /** How many lines the file holds, one per entry. */
        public int $lines,

        /** The lower-case hex SHA-256 of the file. */
        public string $fileSha256,

        /** How the journal entry was acknowledged. */
        public Acknowledgement $acknowledgement,
    ) {}
}
