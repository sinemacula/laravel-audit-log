<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;

/**
 * The prune ledger the package binds by default: nothing has been pruned, so
 * every seal is asked for its members, and a missing member is reported as
 * missing rather than excused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NullPruneLedger implements PruneLedger
{
    /**
     * The record of the prune of the seal's entries: never one, since nothing
     * has been pruned.
     *
     * @param  string  $sealId
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     */
    #[\Override]
    public function recordFor(string $sealId): ?PruneRecord
    {
        return null;
    }
}
