<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

/**
 * What an export's verification found, returned only once it is recorded; a
 * denied viewer sees the entry missing, as one who may not see it does.
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

        /** The export entry the bundle names, or `null` for none. */
        public ?string $entryId,

        /** How many lines the file holds; 0 when it was not read. */
        public int $lines,

        /** The findings, each once, in the order the chain checks them. */
        public array $findings,
    ) {}

    /**
     * Whether the chain found nothing.
     *
     * @return bool
     */
    public function isVerified(): bool
    {
        return $this->findings === [];
    }
}
