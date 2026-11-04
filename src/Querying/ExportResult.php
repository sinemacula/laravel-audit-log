<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Querying\Enums\Acknowledgement;

/**
 * An export of the trail that has been published: the entry that journals it,
 * where its file and its bundle are, its format, how many lines it holds, the
 * SHA-256 of its file, and how the journal entry was acknowledged before
 * anything was published.
 *
 * It is returned only once the export is published: the journal entry was
 * acknowledged, its bundle published beside it, then its file. An export that
 * fails at any step returns none.
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

        /** Where the export's bundle was published: the file's path with `.manifest.json` added. */
        public string $manifestPath,

        /** The format the file is written in. */
        public ExportFormat $format,

        /** How many lines the file holds, one per entry exported. */
        public int $lines,

        /** The SHA-256 of the file's bytes, as 64 lower-case hexadecimal characters. */
        public string $fileSha256,

        /** How the journal entry was acknowledged: stored, or accepted as a committed outbox row. */
        public Acknowledgement $acknowledgement,
    ) {}
}
