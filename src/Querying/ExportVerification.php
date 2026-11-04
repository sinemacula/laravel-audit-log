<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

/**
 * What the verification of an export found: the export entry its bundle names,
 * how many lines its file holds, and each finding of the chain, once, in the
 * order the chain checks them. An export is verified only when nothing was
 * found.
 *
 * It is returned only once the verification is recorded: the record of a
 * verification that could not be written returns none. A viewer the access
 * policy denies sees the entry missing, exactly as one who may not see it does.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExportVerification
{
    /**
     * Constructor.
     *
     * @param  ?string  $entryId
     * @param  int  $lines
     * @param  list<\SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding>  $findings
     *
     * @internal
     */
    public function __construct(

        /** The id of the `audit_log.trail_exported` entry the bundle names, or `null` when it names none. */
        public ?string $entryId,

        /** How many lines the file holds, none when it was not read. */
        public int $lines,

        /** What the chain found, each once, in the order it checks them; none for an export that verifies. */
        public array $findings,
    ) {}

    /**
     * Whether the export verified: the chain found nothing.
     *
     * @return bool
     */
    public function isVerified(): bool
    {
        return $this->findings === [];
    }
}
