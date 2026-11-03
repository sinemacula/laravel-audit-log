<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Integrity;

use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;

/**
 * A prune ledger held in memory: the records a test gives it, by the seal each
 * names, so a test chooses which seals verification finds pruned and with what
 * record, valid, forged or for another seal.
 *
 * A record given for a seal that already has one replaces it. Nothing is
 * checked here: verification checks every record it is given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class InMemoryPruneLedger implements PruneLedger
{
    /** @var array<string, \SineMacula\Laravel\AuditLog\Integrity\PruneRecord> The records given, by the id of the seal each names. */
    private array $records = [];

    /**
     * Keep the record as the prune record of the seal it names.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneRecord  $record
     * @return void
     */
    public function record(PruneRecord $record): void
    {
        $this->records[$record->sealId] = $record;
    }

    /**
     * The record last given for the seal, or `null` when none was.
     *
     * @param  string  $sealId
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     */
    #[\Override]
    public function recordFor(string $sealId): ?PruneRecord
    {
        return $this->records[$sealId] ?? null;
    }
}
