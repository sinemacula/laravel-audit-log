<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;

/**
 * Which of a seal's members its prune records account for, judged from what
 * verification read of the members and what the ledger gave for the seal.
 *
 * A record counts only when it binds exactly this seal, its log, its id, its
 * recomputed digest and its member count, and its signature verifies under the
 * key it names; one that does not is `prune_record` at the seal, one signed
 * under a key the ring does not hold `prune_key`, and either covers nothing.
 * Valid records whose bitmaps share a member are `prune_record` too, though
 * what they cover is still taken, since the verdict is `tampered` either way.
 *
 * A position is a member's place in the members sorted bytewise, and none is
 * assigned unless the membership was authenticated against the seal's members
 * digest, so a member row added, removed or moved never borrows a record's bit.
 * A missing member set in no valid record is `missing_entry`, at the first such
 * member in member order; a missing member set in one is covered; and a present
 * member set in one is to be read again, since a prune that committed after the
 * members were read is gone by then, and a member still there was restored or
 * inserted again. It reads nothing itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PruneCoverage
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSigner  $seals
     */
    public function __construct(

        /** The signer that verifies each prune record under the key it names. */
        private SealSigner $seals,
    ) {}

    /**
     * What the records give for the seal's members: the findings, the missing
     * members covered and the present members to read again.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  string  $digest
     * @param  list<string>  $sortedMemberIds
     * @param  list<string>  $missing
     * @param  list<string>  $present
     * @param  bool  $membershipAuthentic
     * @param  list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>  $records
     * @return \SineMacula\Laravel\AuditLog\Integrity\PruneCoverageResult
     */
    public function of(SealEnvelope $seal, string $digest, array $sortedMemberIds, array $missing, array $present, bool $membershipAuthentic, array $records): PruneCoverageResult
    {
        [$bitmaps, $findings] = $this->validBitmaps($seal, $digest, $records);
        [$union, $overlaps]   = self::union($bitmaps);

        if ($overlaps) {
            $findings[] = [Finding::PRUNE_RECORD, $seal->id];
        }

        $positions = $membershipAuthentic ? array_flip($sortedMemberIds) : [];
        $covered   = [];
        $uncovered = null;

        foreach ($missing as $id) {
            if (PruneBitmap::isSet($union, $positions[$id] ?? -1)) {
                $covered[] = $id;

                continue;
            }

            $uncovered = $uncovered === null || strcmp($id, $uncovered) < 0 ? $id : $uncovered;
        }

        if ($uncovered !== null) {
            $findings[] = [Finding::MISSING_ENTRY, $uncovered];
        }

        $recheck = array_values(array_filter($present, static fn (string $id): bool => PruneBitmap::isSet($union, $positions[$id] ?? -1)));

        return new PruneCoverageResult($findings, $covered, $recheck);
    }

    /**
     * The bitmaps of the records that bind the seal and verify, and the finding
     * of each record that does not, at the seal.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  string  $digest
     * @param  list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>  $records
     * @return array{0: list<string>, 1: list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>}
     */
    private function validBitmaps(SealEnvelope $seal, string $digest, array $records): array
    {
        $bitmaps  = [];
        $findings = [];

        foreach ($records as $record) {
            $finding = $this->findingOf($record, $seal, $digest);

            if ($finding !== null) {
                $findings[] = [$finding, $seal->id];

                continue;
            }

            $bitmaps[] = PruneBitmap::decode($record->pruned, $record->memberCount);
        }

        return [$bitmaps, $findings];
    }

    /**
     * The finding of one record, or `null` when it binds exactly this seal and
     * its signature verifies. What it binds is checked first, so a record of
     * another seal is forged even under a key the ring does not hold.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  string  $digest
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    private function findingOf(PruneRecord $record, SealEnvelope $seal, string $digest): ?Finding
    {
        $binds = $record->logId     === $seal->logId
            && $record->sealId      === $seal->id
            && $record->sealDigest  === $digest
            && $record->memberCount === $seal->memberCount;

        try {
            return $binds && $this->seals->verifiesPrune($record) ? null : Finding::PRUNE_RECORD;
        } catch (UnknownKeyException) {
            return Finding::PRUNE_KEY;
        } catch (\UnexpectedValueException) {
            return Finding::PRUNE_RECORD;
        }
    }

    /**
     * Every member the bitmaps set, as one bitmap over the members, none for no
     * bitmap, and whether any member is set in more than one of them. Every
     * bitmap is of the seal's member count, so all are of one length.
     *
     * @param  list<string>  $bitmaps
     * @return array{0: string, 1: bool}
     */
    private static function union(array $bitmaps): array
    {
        $union    = null;
        $overlaps = false;

        foreach ($bitmaps as $bitmap) {
            $overlaps = $overlaps || ($union !== null && trim($union & $bitmap, "\0") !== '');
            $union    = $union === null ? $bitmap : $union | $bitmap;
        }

        return [$union ?? '', $overlaps];
    }
}
