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
 * Verifies one segment, the entries one stored seal covers, and reports its
 * integrity and anchoring apart. It never writes, repairs or re-signs.
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

    /** @var string The key verified present members are kept under: no finding's. */
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
     * after the report of the seal before it, if the run has one.
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
     * The report of the seal's own fields alone: how a ranged run's first link
     * and an unreadable seal are checked.
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
     * The stored seal's envelope, recomputed digest and own findings; an
     * unreadable seal, or one of an unknown version, has neither.
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
     * under the key it names.
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
     * The seal's member count, findings, sorted ids, missing and verified ids,
     * and whether it is authentic; rows past its count are not kept.
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
     * The seal's member rows with their entries' columns, `null` for a missing
     * entry: one statement on the writer, streamed.
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
     * The finding of one member row and its entry, or `null` with the keys its
     * envelopes name when the entry verifies.
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
     * The finding of a present entry's signature, or `null` with the keys its
     * envelopes name: only a verified entry says what it holds.
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
     * The `key_use_missing` finding at each verified entry naming a key no key
     * use names, read by one check for the segment.
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
     * The prune records' findings and whether the segment is pruned; a covered
     * member still present is read again, and `resurrected` if there.
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

        // One read again is gone or `resurrected`, which outweighs pruned, so
        // it counts as missing
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
     * Ask the anchor whether it confirms the seal's receipt; without a
     * well-formed receipt of this anchor the seal is unanchored without asking.
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
