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
 * in the order the database returned them, must give the members digest.
 * Missing entries are pruned only under a prune record whose signature verifies
 * and which binds exactly this seal; anything else is reported. A sealed
 * bundle's manifest is checked with its seal: each entry that verified and
 * signs a manifest has its artifact checked by the manifest verifier, in
 * batches, never one statement per entry. An entry pruned under a verified
 * prune record is missing, so it has no descriptor to check, and its artifact
 * goes with it.
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

        /** The ledger asked for the prune record of a seal whose entries are missing. */
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
        $sequence                       = self::sequenceOf($seal);
        $gap                            = $sequence === $expected ? [] : [[Finding::SEQUENCE_GAP, self::textOf($seal['id'] ?? null)]];
        [$envelope, $digest, $findings] = $this->own($seal);

        if ($envelope === null || $digest === null) {
            return $this->boundary($seal, $gap);
        }

        [$members, $memberFindings, $firstMissing] = $this->members($envelope);
        [$anchoring, $awaiting, $anchorFindings]   = $this->anchoring($seal, $envelope, $digest, $context);

        $pruneFindings                      = $this->prune($envelope, $digest, $firstMissing);
        $pruned                             = $firstMissing !== null && $pruneFindings === [];
        $all                                = [...$gap, ...$findings, ...self::chain($envelope, $previous), ...$memberFindings, ...$pruneFindings, ...$anchorFindings];
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

        return new SegmentReport(self::sequenceOf($seal), self::textOf($seal['id'] ?? null) ?? '', $integrity, AnchorStatus::UNANCHORED, 0, $finding, $firstBadId, $digest);
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
        $sealId  = self::textOf($seal['id'] ?? null);
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
            Finding::GENESIS->value      => self::breaksGenesis($envelope),
        ];

        $failed = array_map(Finding::from(...), array_keys(array_filter($checks)));
        $signed = $this->signatureFinding($envelope, self::textOf($seal['signature'] ?? null) ?? '');
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
     * manifests its verified entries sign and of the set of members, and the
     * first missing entry's id in member order, if any entry is missing. Only
     * as many member pairs as the seal counts are kept, so a seal given extra
     * member rows costs no more memory than its own.
     *
     * Only an entry that verified is trusted for its manifest descriptor, and
     * the manifests are checked together, in batches, never one statement per
     * entry; a segment with no bundle costs no statement more. A missing entry
     * has no descriptor to check, so a pruned entry's artifact, which goes with
     * it, is never asked for.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @return array{0: int, 1: list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>, 2: ?string}
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

        foreach ($this->memberRows($seal->id) as $row) {
            $entry  = (array) $row;
            $member = self::textOf($entry['member_entry_id'] ?? null) ?? '';
            $hmac   = self::textOf($entry['member_hmac'] ?? null)     ?? '';

            $count++;

            if ($count <= $seal->memberCount) {
                $pairs[] = [$member, $hmac];
            }

            $finding = $this->memberFinding($entry, $hmac);

            if ($finding === null) {
                $manifests[$member] = $this->manifests->descriptorOf($entry);

                continue;
            }

            $first[$finding->value] = self::earliest($first[$finding->value] ?? null, $member);
        }

        $missing = $first[Finding::MISSING_ENTRY->value] ?? null;

        unset($first[Finding::MISSING_ENTRY->value]);

        $found     = array_map(static fn (string $finding, string $id): array => [Finding::from($finding), $id], array_keys($first), $first);
        $manifests = $this->manifests->findings(array_filter($manifests, is_array(...)));

        return [$count, [...$found, ...$manifests, ...self::membership($seal, $count, $pairs)], $missing];
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
     * exists, holds the HMAC the seal recorded and verifies under its own key.
     * A missing entry is `missing_entry`, which the prune ledger may account
     * for.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $entry
     * @param  string  $memberHmac
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    private function memberFinding(#[\SensitiveParameter] array $entry, string $memberHmac): ?Finding
    {
        if (($entry['id'] ?? null) === null) {
            return Finding::MISSING_ENTRY;
        }

        return ($entry['hmac'] ?? null) === $memberHmac ? $this->entryFinding($entry) : Finding::MEMBER_HMAC;
    }

    /**
     * The finding of a present entry's own signature, or `null` when it
     * verifies under the key it names.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $entry
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    private function entryFinding(#[\SensitiveParameter] array $entry): ?Finding
    {
        try {
            return $this->records->verifies($this->codec->decode($entry)) ? null : Finding::ENTRY_HMAC;
        } catch (UnknownKeyException) {
            return Finding::ENTRY_KEY;
        } catch (\UnexpectedValueException) {
            return Finding::ENTRY_MALFORMED;
        }
    }

    /**
     * The finding of the seal's missing entries, if any is missing and no valid
     * prune record that binds exactly this seal accounts for them: the first
     * missing entry with no record, or the seal when its record does not
     * account for them. Missing entries with no finding are pruned.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  string  $digest
     * @param  ?string  $firstMissing
     * @return list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>
     */
    private function prune(SealEnvelope $seal, string $digest, ?string $firstMissing): array
    {
        if ($firstMissing === null) {
            return [];
        }

        $record  = $this->prunes->recordFor($seal->id);
        $finding = $record === null ? Finding::MISSING_ENTRY : $this->pruneFinding($record, $seal, $digest);

        if ($finding === null) {
            return [];
        }

        return [[$finding, $finding === Finding::MISSING_ENTRY ? $firstMissing : $seal->id]];
    }

    /**
     * The finding of the seal's prune record, or `null` when it accounts for
     * the missing entries: it binds exactly this seal (its log, id, recomputed
     * digest and member count) and its signature verifies. One that does not
     * bind the seal or whose signature fails is forged; one signed under a key
     * the ring does not hold cannot be checked.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  string  $digest
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    private function pruneFinding(PruneRecord $record, SealEnvelope $seal, string $digest): ?Finding
    {
        $binds = $record->logId     === $seal->logId
            && $record->sealId      === $seal->id
            && $record->sealDigest  === $digest
            && $record->memberCount === $seal->memberCount;

        try {
            return $binds && $this->seals->verifiesPrune($record) ? null : Finding::PRUNE_RECORD;
        } catch (UnknownKeyException) {
            return Finding::PRUNE_KEY;
        }
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
        $receipt = self::receiptOf($seal['anchor_receipt'] ?? null);

        try {
            $confirmed = $receipt !== null
                && ($seal['anchor'] ?? null) === $this->anchor->name()
                && $this->anchor->confirms(SealSummary::of($envelope, $digest), $receipt);
        } catch (\Throwable) {
            return AnchorStatus::UNAVAILABLE;
        }

        return $confirmed ? AnchorStatus::ANCHORED : AnchorStatus::UNANCHORED;
    }

    /**
     * The findings of the set of members: the rows must be as many as the seal
     * counts, and their pairs must give the members digest. A seal with more or
     * fewer rows fails both, since a set of another size never gives the digest
     * the seal recorded.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  int  $count
     * @param  list<array{0: string, 1: string}>  $pairs
     * @return list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>
     */
    private static function membership(SealEnvelope $seal, int $count, array $pairs): array
    {
        if ($count !== $seal->memberCount) {
            return [[Finding::MEMBER_COUNT, $seal->id], [Finding::MEMBERS_DIGEST, $seal->id]];
        }

        try {
            $matches = SealEnvelope::membersDigest($pairs) === $seal->membersDigest;
        } catch (\InvalidArgumentException) {
            $matches = false;
        }

        return $matches ? [] : [[Finding::MEMBERS_DIGEST, $seal->id]];
    }

    /**
     * The finding of the seal's link to the seal before, when the run has one:
     * the link must name its id and its recomputed digest, so a link to a seal
     * that cannot be read, which has none, is broken.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SegmentReport  $previous
     * @return list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>
     */
    private static function chain(SealEnvelope $seal, ?SegmentReport $previous): array
    {
        if ($previous === null) {
            return [];
        }

        $broken = $seal->previousId !== $previous->sealId
            || $previous->digest === null
            || $seal->previousDigest !== $previous->digest;

        return $broken ? [[Finding::CHAIN_BROKEN, $seal->id]] : [];
    }

    /**
     * Whether the seal breaks the genesis rule: the first seal links to none,
     * and every later one links to the seal before by both its id and its
     * digest.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @return bool
     */
    private static function breaksGenesis(SealEnvelope $seal): bool
    {
        if ($seal->sequence === 1) {
            return $seal->previousId !== null || $seal->previousDigest !== null;
        }

        return $seal->previousId === null || $seal->previousDigest === null;
    }

    /**
     * The receipt kept beside the seal, or `null` when there is none or it is
     * not a JSON object of string keys and scalars or `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $stored
     * @return ?array<string, scalar|null>
     */
    private static function receiptOf(mixed $stored): ?array
    {
        $decoded = is_string($stored) ? json_decode($stored) : null;
        $fields  = $decoded instanceof \stdClass ? get_object_vars($decoded) : [];
        $receipt = array_filter($fields, static fn (mixed $value, int|string $key): bool => is_string($key) && ($value === null || is_scalar($value)), ARRAY_FILTER_USE_BOTH);

        /** @var array<string, scalar|null> $receipt */
        return $decoded instanceof \stdClass && count($receipt) === count($fields) ? $receipt : null;
    }

    /**
     * The stored seal's sequence, read from an integer or its decimal string,
     * or 0 when it is neither.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $seal
     * @return int
     */
    private static function sequenceOf(array $seal): int
    {
        return IntegerSetting::parse($seal['sequence'] ?? null) ?? 0;
    }

    /**
     * The earlier, bytewise, of the id kept so far and the id given.
     *
     * @param  ?string  $kept
     * @param  string  $id
     * @return string
     */
    private static function earliest(?string $kept, string $id): string
    {
        return $kept === null || strcmp($id, $kept) < 0 ? $id : $kept;
    }

    /**
     * The stored value when it is a string, and `null` otherwise.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return ?string
     */
    private static function textOf(mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }
}
