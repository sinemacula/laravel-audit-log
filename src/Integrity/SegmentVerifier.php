<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use Illuminate\Database\DatabaseManager;
use Illuminate\Support\LazyCollection;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Records\EnvelopeKeys;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;

/**
 * Verifies one segment of the log, the entries one stored seal covers, and
 * reports its integrity and its anchoring as two separate answers.
 *
 * The seal's place is checked first, on the raw column: a sequence other than
 * the one expected is a gap, so a deleted first seal is found. A seal of an
 * algorithm version or signer this release does not read, or that cannot be
 * read as a seal, stops the segment there. Otherwise every check runs: the log
 * it names, its stored digest against the digest recomputed from its fields,
 * its signature under the key it names, the genesis rule, and its link to the
 * seal before over that seal's recomputed digest, so a stored digest edited to
 * hide a change breaks the chain after it. A link to a seal before that cannot
 * be read is broken: versions only increase, so a seal this release reads never
 * follows one it cannot, and marking a seal unreadable never turns its deleted
 * segment into anything short of tampered. The members and their entries are
 * read in one statement on the writer, so a prune committing beside it is seen
 * whole or not at all, and streamed: each member's entry must exist, hold the
 * HMAC the seal recorded and verify under its own key, the rows must be as many
 * as the seal counts, and their entry ids and HMACs, sorted bytewise and never
 * in the order the database returned them, must give the members digest. Every
 * missing member is kept, and every present one that verified. A sealed
 * bundle's manifest is checked with its seal: each entry that verified and
 * signs a manifest has its artifact checked by the manifest verifier, in
 * batches, never one statement per entry. An entry pruned under a verified
 * prune record is missing, so it has no descriptor to check, and its artifact
 * goes with it. Every key an entry that verified names in an envelope must have
 * its key use, which is how an erasure finds the entry: the key uses of the
 * segment's entries are read together by one key-use check, none for a segment
 * with no envelope, and an entry short of one is `key_use_missing`.
 *
 * The prune ledger is asked for every segment, after its members and entries
 * were read, even when none is missing, so a seal whose pruned members were all
 * inserted again is found. The order is what tells a prune from a resurrection:
 * the members are read first, then the records, then each present member a
 * valid record covers is read again, by id, on the writer. One gone by then was
 * pruned by a transaction that committed between the reads, and its record
 * accounts for it; one still there was restored or inserted again, and is
 * `resurrected`. A missing member is pruned only when exactly one valid record
 * of exactly this seal, read after the member was, covers it, positions taken
 * from the authenticated members alone; anything else is reported. A ledger
 * that cannot read a stored record is a forged record of the seal.
 *
 * Anchoring comes from the anchor, never from the receipt kept beside the seal.
 * An anchor's head at this sequence with another digest is `contradicted`; no
 * anchor configured is `unanchored`; an anchor that failed earlier in the run,
 * and is not asked again, is `unavailable`. When the run's anchor head settles
 * anchoring, a seal up to it is `anchored` and one after it `unanchored`, with
 * no call. Otherwise the receipt is put to the anchor: no receipt, a receipt of
 * another anchor, or one the anchor does not confirm is `unanchored`, and an
 * anchor that fails is `unavailable`. A configured anchor's `unanchored` seal
 * whose signed `sealed_at` is within the grace, neither before its start nor
 * after the run's clock, awaits its first anchoring. Nothing here writes,
 * repairs or re-signs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SegmentVerifier
{
    /** @var int Most present members read again in one statement. */
    private const int RECHECK_BATCH = 500;

    /** @var string The key the present members that verified are kept under, beside the missing ones' finding: that of no finding. */
    private const string PRESENT = '';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSigner  $seals
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RecordSigner  $records
     * @param  \SineMacula\Laravel\AuditLog\Stores\RowCodec  $codec
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Contracts\PruneLedger  $prunes
     * @param  \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Integrity\ManifestVerifier  $manifests
     */
    public function __construct(

        /** The signer that verifies each seal and prune record under the key it names. */
        private SealSigner $seals,

        /** The signer that verifies each entry under the key it names. */
        private RecordSigner $records,

        /** The codec that decodes each stored entry for its verification. */
        private RowCodec $codec,

        /** The settings the log id is read from. */
        private SealSettings $settings,

        /** The ledger asked for the prune records of every segment. */
        private PruneLedger $prunes,

        /** The anchor asked whether it confirms each seal's receipt. */
        private CheckpointAnchor $anchor,

        /** The connections the storage connection is resolved from on every segment. */
        private DatabaseManager $database,

        /** The verifier of the manifests the segment's verified entries sign. */
        private ManifestVerifier $manifests,
    ) {}

    /**
     * The report of the stored seal's segment, expected at the sequence given,
     * after the report of the seal before it, if the run has one, under what
     * the run shares.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $seal
     * @param  int  $expected
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SegmentReport  $previous
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationContext  $context
     * @return \SineMacula\Laravel\AuditLog\Integrity\SegmentReport
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function verify(array $seal, int $expected, ?SegmentReport $previous, VerificationContext $context): SegmentReport
    {
        $sequence                       = SegmentRows::sequenceOf($seal);
        $gap                            = $sequence === $expected ? [] : [[Finding::SEQUENCE_GAP, SegmentRows::textOf($seal['id'] ?? null)]];
        [$envelope, $digest, $findings] = $this->own($seal);

        if ($envelope === null || $digest === null) {
            return $this->boundary($seal, $gap);
        }

        [$members, $memberFindings, $sorted, $missing, $present, $authentic] = $this->members($envelope);
        [$anchoring, $awaiting, $anchorFindings]                             = $this->anchoring($seal, $envelope, $digest, $context);

        [$pruneFindings, $pruned]           = $this->coverage($envelope, $digest, $sorted, $missing, $present, $authentic);
        $all                                = [...$gap, ...$findings, ...SegmentRows::chain($envelope, $previous), ...$memberFindings, ...$pruneFindings, ...$anchorFindings];
        [$integrity, $finding, $firstBadId] = SegmentReport::verdict($all, $pruned);

        return new SegmentReport($envelope->sequence, $envelope->id, $integrity, $anchoring, $members, $finding, $firstBadId, $digest, $awaiting);
    }

    /**
     * The report of the seal's own fields alone: its version and signer,
     * whether it can be read, its log, its stored digest, its signature and the
     * genesis rule, never its members or its anchoring. It is how the seal
     * before a ranged run's first, the run's first link, is checked, and how a
     * seal that cannot be read is reported, with the findings given beside its
     * own.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $seal
     * @param  list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>  $also
     * @return \SineMacula\Laravel\AuditLog\Integrity\SegmentReport
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function boundary(array $seal, array $also = []): SegmentReport
    {
        [, $digest, $findings]              = $this->own($seal);
        [$integrity, $finding, $firstBadId] = SegmentReport::verdict([...$also, ...$findings], false);
        $sealId                             = SegmentRows::textOf($seal['id'] ?? null) ?? '';

        return new SegmentReport(SegmentRows::sequenceOf($seal), $sealId, $integrity, AnchorStatus::UNANCHORED, 0, $finding, $firstBadId, $digest);
    }

    /**
     * The stored seal's envelope, its recomputed digest and the findings of its
     * own fields. A seal of a version or signer this release does not read, or
     * that cannot be read, has no envelope and no digest.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array<array-key, mixed>  $seal
     * @return array{0: ?\SineMacula\Laravel\AuditLog\Integrity\SealEnvelope, 1: ?string, 2: list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>}
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function own(array $seal): array
    {
        $sealId  = SegmentRows::textOf($seal['id'] ?? null);
        $version = IntegerSetting::parse($seal['algorithm_version'] ?? null);
        $signer  = $seal['signer'] ?? null;

        if (($version !== null && !in_array($version, SealEnvelope::SUPPORTED_ALGORITHM_VERSIONS, true)) || (is_string($signer) && $signer !== SealEnvelope::SIGNER)) {
            return [null, null, [[Finding::SEAL_VERSION, $sealId]]];
        }

        try {
            $envelope = SealEnvelope::fromRow($seal);
        } catch (\UnexpectedValueException) {
            return [null, null, [[Finding::SEAL_MALFORMED, $sealId]]];
        }

        $digest = $envelope->digest();
        $checks = [
            Finding::LOG_MISMATCH->value => $envelope->logId               !== $this->settings->logId(),
            Finding::SEAL_DIGEST->value  => ($seal['seal_digest'] ?? null) !== $digest,
            Finding::GENESIS->value      => SegmentRows::breaksGenesis($envelope),
        ];

        $failed = array_map(Finding::from(...), array_keys(array_filter($checks)));
        $signed = $this->signatureFinding($envelope, SegmentRows::textOf($seal['signature'] ?? null) ?? '');
        $found  = array_map(static fn (Finding $finding): array => [$finding, $envelope->id], $signed === null ? $failed : [...$failed, $signed]);

        return [$envelope, $digest, $found];
    }

    /**
     * The finding the seal's signature gives, or `null` when it is the seal's
     * under the key it names. A signature that is not 64 lower-case hex is
     * malformed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  string  $signature
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    private function signatureFinding(SealEnvelope $seal, string $signature): ?Finding
    {
        try {
            return $this->seals->verifies($seal, $signature) ? null : Finding::SEAL_SIGNATURE;
        } catch (UnknownKeyException) {
            return Finding::SEAL_KEY;
        } catch (\UnexpectedValueException) {
            return Finding::SEAL_MALFORMED;
        }
    }

    /**
     * How many member rows the seal has, the findings of its members, of the
     * manifests its verified entries sign and of the set of members, the member
     * entry ids sorted bytewise, every missing member's id, every present
     * member's that verified, and whether the membership is authentic: the rows
     * as many as the seal counts and giving its members digest. Only as many
     * member rows as the seal counts are kept, so a seal given extra member
     * rows costs no more memory than its own; such a seal is never authentic,
     * so nothing it leaves out could be found pruned.
     *
     * Only an entry that verified is trusted for its manifest descriptor and
     * the keys its envelopes name, the manifests are checked together, in
     * batches, never one statement per entry, and the key uses of the entries
     * that name a key are read together, in batches by entry; a segment with no
     * bundle and no envelope costs no statement more. A missing entry has no
     * descriptor to check and no envelope, so a pruned entry's artifact, which
     * goes with it, is never asked for.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @return array{0: int, 1: list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>, 2: list<string>, 3: list<string>, 4: list<string>, 5: bool}
     *
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function members(SealEnvelope $seal): array
    {
        $count     = 0;
        $pairs     = [];
        $first     = [];
        $manifests = [];
        $keys      = [];
        $kept      = [Finding::MISSING_ENTRY->value => [], self::PRESENT => []];

        foreach ($this->memberRows($seal->id) as $row) {
            $entry              = (array) $row;
            $member             = SegmentRows::textOf($entry['member_entry_id'] ?? null) ?? '';
            $hmac               = SegmentRows::textOf($entry['member_hmac'] ?? null)     ?? '';
            [$finding, $keyIds] = $this->memberFinding($entry, $hmac);

            if (++$count <= $seal->memberCount) {
                $pairs[]                           = [$member, $hmac];
                $kept[(string) $finding?->value][] = $member;
            }

            if ($finding === null) {
                $manifests[$member] = $this->manifests->descriptorOf($entry);
                $keys[$member]      = $keyIds;

                continue;
            }

            $first[$finding->value] = SegmentRows::earliest($first[$finding->value] ?? null, $member);
        }

        unset($first[Finding::MISSING_ENTRY->value]);

        $found      = array_map(static fn (string $finding, string $id): array => [Finding::from($finding), $id], array_keys($first), $first);
        $manifests  = $this->manifests->findings(array_filter($manifests, is_array(...)));
        $keyUses    = $this->keyUseFindings(array_filter($keys));
        $membership = SegmentRows::membership($seal, $count, $pairs);
        $sorted     = array_column($pairs, 0);

        usort($sorted, strcmp(...));

        return [$count, [...$found, ...$manifests, ...$keyUses, ...$membership], $sorted, $kept[Finding::MISSING_ENTRY->value], $kept[self::PRESENT], $membership === []];
    }

    /**
     * The seal's member rows, each with its entry's columns, or the entry's
     * columns all `null` when it is missing: one statement on the writer,
     * streamed, in whatever order the database returns them.
     *
     * @param  string  $sealId
     * @return \Illuminate\Support\LazyCollection<int, \stdClass>
     *
     * @throws \InvalidArgumentException
     */
    private function memberRows(string $sealId): LazyCollection
    {
        /** @var \Illuminate\Support\LazyCollection<int, \stdClass> */
        return $this->database->connection(StorageConnection::name())
            ->table(IntegrityTables::membersTable() . ' as m')
            ->leftJoin(EntrySettings::table() . ' as e', 'e.id', '=', 'm.entry_id')
            ->where('m.checkpoint_id', $sealId)
            ->select(['m.entry_id as member_entry_id', 'm.hmac as member_hmac', 'e.*'])
            ->useWritePdo()
            ->cursor();
    }

    /**
     * The finding of one member row and its entry, or `null` when the entry
     * exists, holds the HMAC the seal recorded and verifies under its own key,
     * with the keys its envelopes name when it does. A missing entry is
     * `missing_entry`, which the prune ledger may account for.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $entry
     * @param  string  $memberHmac
     * @return array{0: ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: list<string>}
     */
    private function memberFinding(#[\SensitiveParameter] array $entry, string $memberHmac): array
    {
        if (($entry['id'] ?? null) === null) {
            return [Finding::MISSING_ENTRY, []];
        }

        return ($entry['hmac'] ?? null) === $memberHmac ? $this->entryFinding($entry) : [Finding::MEMBER_HMAC, []];
    }

    /**
     * The finding of a present entry's own signature, or `null` when it
     * verifies under the key it names, with the keys its envelopes name when it
     * does: only an entry that verified says what it holds.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $entry
     * @return array{0: ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: list<string>}
     */
    private function entryFinding(#[\SensitiveParameter] array $entry): array
    {
        try {
            $decoded = $this->codec->decode($entry);
            $finding = $this->records->verifies($decoded) ? null : Finding::ENTRY_HMAC;
        } catch (UnknownKeyException) {
            $finding = Finding::ENTRY_KEY;
        } catch (\UnexpectedValueException) {
            $finding = Finding::ENTRY_MALFORMED;
        }

        if ($finding !== null) {
            return [$finding, []];
        }

        $ip = $decoded['ip'] ?? null;

        return [null, EnvelopeKeys::of($decoded['properties'] ?? null, $decoded['context'] ?? null, is_string($ip) ? $ip : null)];
    }

    /**
     * The `key_use_missing` finding at each verified entry one of whose keys
     * has no key use naming it, the entries' key uses read by one key-use check
     * for the segment, and none when no entry names a key.
     *
     * @param  array<string, list<string>>  $keys
     * @return list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>
     *
     * @throws \InvalidArgumentException
     */
    private function keyUseFindings(array $keys): array
    {
        if ($keys === []) {
            return [];
        }

        return array_map(static fn (string $entryId): array => [Finding::KEY_USE_MISSING, $entryId], (new KeyUseCheck($this->database))->missing($keys));
    }

    /**
     * The findings of the seal's prune records and of what they cover, and
     * whether the segment is pruned: at least one member missing, or gone when
     * read again, and every missing member covered. The ledger is asked once,
     * after the members were read; each present member a valid record covers is
     * then read again, so one gone by then was pruned meanwhile and one still
     * there is `resurrected`, at each such member.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  string  $digest
     * @param  list<string>  $sorted
     * @param  list<string>  $missing
     * @param  list<string>  $present
     * @param  bool  $authentic
     * @return array{0: list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>, 1: bool}
     *
     * @throws \InvalidArgumentException
     */
    private function coverage(SealEnvelope $seal, string $digest, array $sorted, array $missing, array $present, bool $authentic): array
    {
        try {
            $records    = $this->prunes->recordsFor($seal->id);
            $unreadable = [];
        } catch (\UnexpectedValueException) {
            $records    = [];
            $unreadable = [[Finding::PRUNE_RECORD, $seal->id]];
        }

        $result      = (new PruneCoverage($this->seals))->of($seal, $digest, $sorted, $missing, $present, $authentic, $records);
        $resurrected = array_map(static fn (string $id): array => [Finding::RESURRECTED, $id], $this->stillPresent($result->recheck));
        $findings    = [...$unreadable, ...$result->findings, ...$resurrected];

        // A member read again is either gone or `resurrected`, which outweighs
        // pruned, so one read again counts towards pruned as a missing one does
        return [$findings, ($missing !== [] || $result->recheck !== []) && count($result->covered) === count($missing)];
    }

    /**
     * Which of the ids are still entries: one statement on the writer for each
     * 500 of them, and none for no id.
     *
     * @param  list<string>  $ids
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function stillPresent(array $ids): array
    {
        $still = [];

        foreach (array_chunk($ids, self::RECHECK_BATCH) as $batch) {
            $found = $this->database->connection(StorageConnection::name())
                ->table(EntrySettings::table())
                ->whereIn('id', $batch)
                ->useWritePdo()
                ->pluck('id')
                ->all();

            array_push($still, ...array_values(array_filter($found, is_string(...))));
        }

        return $still;
    }

    /**
     * The seal's anchoring, whether it awaits its first anchoring, and the
     * finding when the anchor's head holds another digest at its sequence.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array<array-key, mixed>  $seal
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $envelope
     * @param  string  $digest
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationContext  $context
     * @return array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus, 1: bool, 2: list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function anchoring(array $seal, SealEnvelope $envelope, string $digest, VerificationContext $context): array
    {
        $remote = $context->remote;

        if ($remote !== null && $remote->sequence === $envelope->sequence && $remote->digest !== $digest) {
            return [AnchorStatus::CONTRADICTED, false, [[Finding::ANCHOR_CONTRADICTION, $envelope->id]]];
        }

        $status = match (true) {
            $this->anchor instanceof NullAnchor => AnchorStatus::UNANCHORED,
            !$context->askAnchor                => AnchorStatus::UNAVAILABLE,
            $context->byHead                    => $remote !== null && $envelope->sequence <= $remote->sequence ? AnchorStatus::ANCHORED : AnchorStatus::UNANCHORED,
            default                             => $this->ask($seal, $envelope, $digest),
        };

        $awaiting = $status === AnchorStatus::UNANCHORED
            && !$this->anchor instanceof NullAnchor
            && strcmp($envelope->sealedAt, $context->graceFrom) >= 0
            && strcmp($envelope->sealedAt, $context->graceTo) <= 0;

        return [$status, $awaiting, []];
    }

    /**
     * Ask the anchor whether it confirms the seal's receipt: no receipt, a
     * malformed one or one of another anchor is unanchored without asking for
     * the confirmation; a receipt the anchor confirms is anchored, one it does
     * not is unanchored, and an anchor that fails is unavailable.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $seal
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $envelope
     * @param  string  $digest
     * @return \SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus
     */
    private function ask(array $seal, SealEnvelope $envelope, string $digest): AnchorStatus
    {
        $receipt = SegmentRows::receiptOf($seal['anchor_receipt'] ?? null);

        try {
            $confirmed = $receipt !== null
                && ($seal['anchor'] ?? null) === $this->anchor->name()
                && $this->anchor->confirms(SealSummary::of($envelope, $digest), $receipt);
        } catch (\Throwable) {
            return AnchorStatus::UNAVAILABLE;
        }

        return $confirmed ? AnchorStatus::ANCHORED : AnchorStatus::UNANCHORED;
    }
}
