<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * What a seal's prune records say of its members.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PruneCoverageResult
{
    /**
     * Constructor.
     *
     * @param  list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>  $findings
     * @param  list<string>  $covered
     * @param  list<string>  $recheck
     */
    public function __construct(

        /** The findings of the records and of the missing members they leave uncovered, each with the id it is found at. */
        public array $findings,

        /** The ids of the missing members a valid record covers. */
        public array $covered,

        /** The ids of the present members a valid record covers, to be read again. */
        public array $recheck,
    ) {}
}
