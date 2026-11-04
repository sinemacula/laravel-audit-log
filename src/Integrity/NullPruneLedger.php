<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;

/**
 * A prune ledger that has pruned nothing, for an application that never prunes:
 * every seal is asked for its records and has none, so a missing member is
 * reported as missing rather than excused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NullPruneLedger implements PruneLedger
{
    /**
     * The records of the prunes of the seal's entries: never one, since nothing
     * has been pruned.
     *
     * @param  string  $sealId
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>
     */
    #[\Override]
    public function recordsFor(string $sealId): array
    {
        return [];
    }
}
