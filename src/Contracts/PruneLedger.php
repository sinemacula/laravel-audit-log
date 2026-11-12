<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

/**
 * Prune ledger contract: the signed records of the prunes of each seal's
 * entries, which verification asks for.
 *
 * An implementation returns the records the pruner journals, or every pruned
 * member verifies as missing, and keeps no state; verification checks each
 * record itself.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PruneLedger
{
    /**
     * Every record written for the seal, in written order; one that cannot be
     * read is an `UnexpectedValueException`, reported as a forged record.
     *
     * @param  string  $sealId
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>
     *
     * @throws \UnexpectedValueException
     */
    public function recordsFor(string $sealId): array;
}
