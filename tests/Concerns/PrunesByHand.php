<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\PruneBitmap;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use Tests\Fixtures\Integrity\InMemoryPruneLedger;

/**
 * Prunes sealed entries as retention would, without a run: their entries
 * deleted, their seals and members kept, and for each seal they fall in a prune
 * record signed under the seal key that sets exactly their positions, kept in
 * an in-memory ledger the container binds, so the tombstones and verification
 * both find them pruned.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait PrunesByHand
{
    /** @var string The run every hand-made prune record names. */
    protected const string HAND_PRUNE_RUN = '01932b4e-c000-7000-8000-0000000000f1';

    /** @var string When every hand-made prune record says it pruned. */
    protected const string HAND_PRUNED_AT = '2026-11-05T09:00:00.000000Z';

    /**
     * Delete the entries of the ids, each a member of a stored seal, and record
     * their prune in the bound in-memory ledger, binding one first when none
     * is, and return it.
     *
     * @param  string  ...$ids
     * @return \Tests\Fixtures\Integrity\InMemoryPruneLedger
     */
    protected function pruneByHand(string ...$ids): InMemoryPruneLedger
    {
        $connection = DB::connection(StorageConnection::name());
        $bound      = app()->bound(PruneLedger::class) ? app(PruneLedger::class) : null;
        $ledger     = $bound instanceof InMemoryPruneLedger ? $bound : new InMemoryPruneLedger;
        $bySeal     = [];

        foreach ($connection->table(IntegrityTables::membersTable())->whereIn('entry_id', $ids)->get(['checkpoint_id', 'entry_id'])->all() as $member) {
            $bySeal[(string) $member->checkpoint_id][] = (string) $member->entry_id;
        }

        foreach ($bySeal as $sealId => $pruned) {
            $seal    = $connection->table(IntegrityTables::checkpointsTable())->where('id', $sealId)->first();
            $members = array_map(strval(...), $connection->table(IntegrityTables::membersTable())->where('checkpoint_id', $sealId)->pluck('entry_id')->all());

            self::assertNotNull($seal);

            usort($members, strcmp(...));

            $positions = array_map(static fn (string $id): int => (int) array_search($id, $members, true), $pruned);

            sort($positions);

            $ledger->add(app(SealSigner::class)->signPrune(
                (string) $seal->log_id,
                $sealId,
                (string) $seal->seal_digest,
                count($members),
                PruneBitmap::encode($positions, count($members)),
                count($positions),
                self::HAND_PRUNE_RUN,
                self::HAND_PRUNED_AT,
            ));
        }

        $connection->table(EntrySettings::table())->whereIn('id', $ids)->delete();

        app()->instance(PruneLedger::class, $ledger);

        return $ledger;
    }
}
