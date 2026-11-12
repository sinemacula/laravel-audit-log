<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;

/**
 * What verification established about one segment, its integrity and anchoring
 * apart. It names ids and counts, never an entry's value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SegmentReport
{
    /**
     * Constructor.
     *
     * @param  int  $sequence
     * @param  string  $sealId
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus  $integrity
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus  $anchoring
     * @param  int  $members
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @param  ?string  $firstBadId
     * @param  ?string  $digest
     * @param  bool  $awaitingAnchor
     */
    public function __construct(

        /** The seal's sequence, as stored. */
        public int $sequence,

        /** The seal's id, as stored, or empty when it is not a string. */
        public string $sealId,

        /** What the segment's checks established about its integrity. */
        public IntegrityStatus $integrity,

        /** What the anchor established about the seal, apart from its integrity. */
        public AnchorStatus $anchoring,

        /** How many member rows of the seal were found. */
        public int $members,

        /** The finding the segment reports, or `null` when no check failed. */
        public ?Finding $finding = null,

        /** The id of the seal or entry the finding was found at, or `null` when there is none to name. */
        public ?string $firstBadId = null,

        /** The digest recomputed from the seal's fields, or `null` when the seal could not be read. */
        public ?string $digest = null,

        /** Whether the seal is unanchored only because it was sealed within the anchoring grace. */
        public bool $awaitingAnchor = false,
    ) {}

    /**
     * The segment's status, finding and first id: the most severe status wins,
     * then the first finding in enum order, then the first id.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>  $findings
     * @param  bool  $pruned
     * @return array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus, 1: ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 2: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function verdict(array $findings, bool $pruned): array
    {
        $status  = $pruned ? IntegrityStatus::PRUNED : IntegrityStatus::VALID;
        $finding = null;

        foreach (Finding::cases() as $case) {
            if (self::idsOf($findings, $case) === [] || $case->status()->severity() <= $status->severity()) {
                continue;
            }

            $status  = $case->status();
            $finding = $case;
        }

        return [$status, $finding, self::firstIdOf($findings, $finding)];
    }

    /**
     * The report as its line of output.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{type: 'segment', sequence: int, seal_id: string, integrity: string, anchoring: string, awaiting_anchor: bool, members: int, finding: ?string, first_bad_id: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function toArray(): array
    {
        return [
            'type'            => 'segment',
            'sequence'        => $this->sequence,
            'seal_id'         => $this->sealId,
            'integrity'       => $this->integrity->value,
            'anchoring'       => $this->anchoring->value,
            'awaiting_anchor' => $this->awaitingAnchor,
            'members'         => $this->members,
            'finding'         => $this->finding?->value,
            'first_bad_id'    => $this->firstBadId,
        ];
    }

    /**
     * The ids the finding was found at, `null` for one found at no id.
     *
     * @param  list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>  $findings
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @return list<?string>
     */
    private static function idsOf(array $findings, Finding $finding): array
    {
        $ids = [];

        foreach ($findings as [$found, $id]) {
            if ($found !== $finding) {
                continue;
            }

            $ids[] = $id;
        }

        return $ids;
    }

    /**
     * The first id, bytewise, the finding was found at, or `null` when there is
     * no finding or it was found at no id.
     *
     * @param  list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>  $findings
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @return ?string
     */
    private static function firstIdOf(array $findings, ?Finding $finding): ?string
    {
        $ids = $finding === null ? [] : array_filter(self::idsOf($findings, $finding), is_string(...));

        usort($ids, strcmp(...));

        return $ids[0] ?? null;
    }
}
