<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Query\JoinClause;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\PruneCoverage;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;

/**
 * Which records retention has pruned: absent seal members a valid prune record
 * covers, so the drain, replay and conflict path never store them again.
 *
 * An absent member no record covers is stored again, never relabelled as
 * pruned; reads use the writer, so a lagging replica hides no prune.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PruneTombstones
{
    /** @var int The most ids one statement names. */
    public const int CHUNK = 500;

    /** @var string A UUID in the one form every record id takes. */
    private const string ID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \SineMacula\Laravel\AuditLog\Contracts\PruneLedger  $ledger
     * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneCoverage  $coverage
     */
    public function __construct(

        /** The connections the storage connection is resolved from on every call. */
        private ConnectionResolverInterface $connections,

        /** The prune records of each seal, as verification reads them. */
        private PruneLedger $ledger,

        /** Which absent members a seal's records cover. */
        private PruneCoverage $coverage,
    ) {}

    /**
     * The ids among those given that retention has pruned, each once, in the
     * order given.
     *
     * @param  list<string>  $ids
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function prunedAmong(array $ids): array
    {
        $candidates = array_values(array_unique(array_filter($ids, static fn (string $id): bool => preg_match(self::ID_PATTERN, $id) === 1)));
        $pruned     = [];

        foreach (array_chunk($candidates, self::CHUNK) as $chunk) {
            foreach ($this->prunedIn($chunk) as $id) {
                $pruned[$id] = true;
            }
        }

        return array_values(array_filter($candidates, static fn (string $id): bool => isset($pruned[$id])));
    }

    /**
     * Whether retention has pruned the record with the id.
     *
     * @param  string  $id
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isPruned(string $id): bool
    {
        return $this->prunedAmong([$id]) !== [];
    }

    /**
     * The chunk's ids that are absent seal members a valid prune record covers.
     *
     * @param  list<string>  $chunk
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function prunedIn(array $chunk): array
    {
        $connection = $this->connections->connection(StorageConnection::name());

        assert($connection instanceof Connection);

        $absent = $connection->table(IntegrityTables::membersTable() . ' as m')
            ->leftJoin(EntrySettings::table() . ' as e', static function (JoinClause $join): void {
                $join->on('e.id', '=', 'm.entry_id');
            })
            ->whereIn('m.entry_id', $chunk)
            ->whereNull('e.id')
            ->useWritePdo()
            ->get(['m.entry_id', 'm.checkpoint_id'])
            ->all();

        $bySeal = [];

        foreach ($absent as $member) {
            $bySeal[(string) $member->checkpoint_id][] = (string) $member->entry_id;
        }

        $pruned = [];

        foreach ($bySeal as $sealId => $ids) {
            $pruned = [...$pruned, ...$this->coveredOf($connection, $sealId, $ids)];
        }

        return $pruned;
    }

    /**
     * The seal's absent members its valid prune records cover; none when the
     * seal or its records cannot be read.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $sealId
     * @param  list<string>  $absent
     * @return list<string>
     */
    private function coveredOf(Connection $connection, string $sealId, array $absent): array
    {
        try {
            $records = $this->ledger->recordsFor($sealId);
            $stored  = $records === [] ? null : $connection->table(IntegrityTables::checkpointsTable())->useWritePdo()->where('id', $sealId)->first();

            if ($stored === null) {
                return [];
            }

            $seal    = SealEnvelope::fromRow((array) $stored);
            $members = $connection->table(IntegrityTables::membersTable())->useWritePdo()->where('checkpoint_id', $sealId)->get(['entry_id', 'hmac'])->all();
            $pairs   = array_values(array_map(static fn (object $member): array => [(string) $member->entry_id, (string) $member->hmac], $members));
            $ids     = array_column($pairs, 0);

            usort($ids, strcmp(...));

            $authentic = count($pairs) === $seal->memberCount && hash_equals($seal->membersDigest, SealEnvelope::membersDigest($pairs));

            return $this->coverage->of($seal, $seal->digest(), $ids, $absent, [], $authentic, $records)->covered;
        } catch (\InvalidArgumentException|\UnexpectedValueException) {
            // A seal, a member or a record that cannot be read covers nothing
            return [];
        }
    }
}
