<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

/**
 * Prune ledger contract: the signed records of the prunes of each seal's
 * entries, which verification asks for every seal it verifies.
 *
 * A seal may have several records, one per prune transaction that deleted any
 * of its members, each written in the same transaction as its deletes and each
 * setting only the members it deleted, so the bitmaps of one seal's records
 * share no member. The package binds `Lifecycle\JournalPruneLedger`, which
 * reads the prune rows of the lifecycle journal. The pruner only ever writes
 * its records to that journal, so an implementation must return the records the
 * pruner journals, or every pruned member verifies as missing;
 * `Integrity\NullPruneLedger`, which has pruned nothing, suits only an
 * application that never prunes. A record is trusted only after verification
 * checks its signature and every field it binds against the seal, so an
 * implementation need not check either, and a record never excuses a seal that
 * fails on its own. An implementation must keep no state between calls.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PruneLedger
{
    /**
     * Every record written for the seal, in the order they were written, or
     * none when the seal was never pruned. A stored record that cannot be read
     * is an `UnexpectedValueException`, which verification reports as a forged
     * record of the seal.
     *
     * @param  string  $sealId
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>
     *
     * @throws \UnexpectedValueException
     */
    public function recordsFor(string $sealId): array;
}
