<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;

/**
 * Prune ledger contract: the signed record of each seal whose entries were
 * pruned on purpose, which verification asks for when a seal's members are
 * missing.
 *
 * It is the seam a lifecycle journal binds to, the journal a prune writes its
 * record into in the same transaction as its deletes, on the maintenance
 * connection. The package binds `Integrity\NullPruneLedger`, which has pruned
 * nothing, so a missing member is always reported. A record is trusted only
 * after verification checks its signature and every field it binds against the
 * seal, so an implementation need not check either, and a record never excuses
 * a seal that fails on its own. An implementation must keep no state between
 * calls.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PruneLedger
{
    /**
     * The record of the prune of the seal's entries, as it was written, or
     * `null` when the seal was never pruned.
     *
     * @param  string  $sealId
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     */
    public function recordFor(string $sealId): ?PruneRecord;
}
