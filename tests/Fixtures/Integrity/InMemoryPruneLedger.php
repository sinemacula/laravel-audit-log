<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Integrity;

use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;

/**
 * A prune ledger held in memory, so a test chooses which seals verification
 * finds pruned and with what records; every record is kept in order and none is
 * checked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class InMemoryPruneLedger implements PruneLedger
{
    /** @var array<string, list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>> The records given, by the id of the seal each names, in the order given. */
    private array $records = [];

    /**
     * Keep the record as one more prune record of the seal it names.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneRecord  $record
     * @return void
     */
    public function add(PruneRecord $record): void
    {
        $this->records[$record->sealId][] = $record;
    }

    /**
     * Every record given for the seal, in the order given, or none.
     *
     * @param  string  $sealId
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>
     */
    #[\Override]
    public function recordsFor(string $sealId): array
    {
        return $this->records[$sealId] ?? [];
    }
}
