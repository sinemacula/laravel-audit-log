<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\RunFinding;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\VerificationTally;

/**
 * Unit tests for the counts of one run: every status counted from zero in enum
 * order, the segments awaiting their first anchoring, the run's own findings
 * kept in order, the unsealed counts, and the first failure, the most severe
 * and then the earliest, of segments and run findings alike.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationTally::class)]
final class VerificationTallyTest extends TestCase
{
    /** @var string The first seal's id. */
    private const string FIRST = '01932b4e-9000-7000-8000-000000000001';

    /** @var string The second seal's id. */
    private const string SECOND = '01932b4e-9000-7000-8000-000000000002';

    /** @var string The third seal's id. */
    private const string THIRD = '01932b4e-9000-7000-8000-000000000003';

    /**
     * A new tally lists every status at zero, in enum order, with nothing
     * awaiting, found, pending or overdue, and no failure.
     *
     * @return void
     */
    public function testEveryStatusIsCountedFromZero(): void
    {
        $tally = new VerificationTally;

        self::assertSame(['valid' => 0, 'pruned' => 0, 'incomplete' => 0, 'unverifiable' => 0, 'tampered' => 0], $tally->integrity());
        self::assertSame(['anchored' => 0, 'unanchored' => 0, 'unavailable' => 0, 'contradicted' => 0], $tally->anchoring());
        self::assertSame(0, $tally->segments());
        self::assertSame(0, $tally->awaiting());
        self::assertSame([], $tally->findings());
        self::assertSame(0, $tally->pending());
        self::assertSame(0, $tally->overdue());
        self::assertNull($tally->firstFinding());
        self::assertNull($tally->firstBadId());
    }

    /**
     * Each report adds one to its integrity and its anchoring status, and the
     * order of the maps never changes.
     *
     * @return void
     */
    public function testCountsEachReportUnderBothStatuses(): void
    {
        $tally = new VerificationTally;

        $tally->add(self::report(1, IntegrityStatus::VALID, AnchorStatus::ANCHORED));
        $tally->add(self::report(2, IntegrityStatus::PRUNED, AnchorStatus::UNAVAILABLE));
        $tally->add(self::report(3, IntegrityStatus::VALID, AnchorStatus::ANCHORED));

        self::assertSame(['valid' => 2, 'pruned' => 1, 'incomplete' => 0, 'unverifiable' => 0, 'tampered' => 0], $tally->integrity());
        self::assertSame(['anchored' => 2, 'unanchored' => 0, 'unavailable' => 1, 'contradicted' => 0], $tally->anchoring());
        self::assertSame(3, $tally->segments());
        self::assertNull($tally->firstFinding());
    }

    /**
     * The first failure is the most severe given, and of equally severe ones
     * the earliest, with the id it was found at; a later failure of the same
     * status never replaces it, and a run finding competes with segments.
     *
     * @return void
     */
    public function testTheFirstFailureIsTheMostSevereThenTheEarliest(): void
    {
        $tally = new VerificationTally;

        $tally->add(self::report(1, IntegrityStatus::INCOMPLETE, AnchorStatus::UNANCHORED, Finding::MISSING_ENTRY, self::FIRST));

        self::assertSame(Finding::MISSING_ENTRY, $tally->firstFinding());
        self::assertSame(self::FIRST, $tally->firstBadId());

        $tally->add(self::report(2, IntegrityStatus::TAMPERED, AnchorStatus::UNANCHORED, Finding::ENTRY_HMAC, self::SECOND));
        $tally->add(self::report(3, IntegrityStatus::TAMPERED, AnchorStatus::UNANCHORED, Finding::SEAL_DIGEST, self::THIRD));
        $tally->addFinding(new RunFinding(Finding::ORPHAN_MEMBER, self::THIRD, 2));
        $tally->add(self::report(4, IntegrityStatus::UNVERIFIABLE, AnchorStatus::UNANCHORED, Finding::SEAL_KEY, self::THIRD));

        self::assertSame(Finding::ENTRY_HMAC, $tally->firstFinding());
        self::assertSame(self::SECOND, $tally->firstBadId());
    }

    /**
     * A run finding is the first failure when nothing as severe came before it,
     * and a later segment of a more severe status replaces it.
     *
     * @return void
     */
    public function testARunFindingCanBeTheFirstFailure(): void
    {
        $tally = new VerificationTally;

        $tally->addFinding(new RunFinding(Finding::OVERDUE_UNSEALED, self::FIRST, 4));

        self::assertSame(Finding::OVERDUE_UNSEALED, $tally->firstFinding());
        self::assertSame(self::FIRST, $tally->firstBadId());

        $tally->addFinding(new RunFinding(Finding::MISSING_TAIL));

        self::assertSame(Finding::MISSING_TAIL, $tally->firstFinding());
        self::assertNull($tally->firstBadId());
    }

    /**
     * A finding that does not fail, a valid or pruned report or one without a
     * finding, is never the first failure.
     *
     * @return void
     */
    public function testOnlyAFailureIsTheFirstFailure(): void
    {
        $tally = new VerificationTally;

        $tally->add(self::report(1, IntegrityStatus::PRUNED, AnchorStatus::UNANCHORED));
        $tally->add(self::report(2, IntegrityStatus::VALID, AnchorStatus::CONTRADICTED, Finding::ANCHOR_CONTRADICTION, self::SECOND));
        $tally->add(self::report(3, IntegrityStatus::TAMPERED, AnchorStatus::UNANCHORED));

        self::assertNull($tally->firstFinding());
        self::assertNull($tally->firstBadId());

        $tally->add(self::report(4, IntegrityStatus::INCOMPLETE, AnchorStatus::UNANCHORED, Finding::MISSING_ENTRY, self::THIRD));

        self::assertSame(Finding::MISSING_ENTRY, $tally->firstFinding());
        self::assertSame(self::THIRD, $tally->firstBadId());
    }

    /**
     * The run's own findings are kept in the order found, and are not counted
     * as segments.
     *
     * @return void
     */
    public function testRunFindingsAreKept(): void
    {
        $tally   = new VerificationTally;
        $orphans = new RunFinding(Finding::ORPHAN_MEMBER, self::FIRST, 2);
        $tail    = new RunFinding(Finding::MISSING_TAIL);

        $tally->addFinding($orphans);
        $tally->addFinding($tail);

        self::assertSame([$orphans, $tail], $tally->findings());
        self::assertSame(0, $tally->segments());
        self::assertSame(0, $tally->integrity()['tampered']);
    }

    /**
     * Only the segments that await their first anchoring are counted as
     * awaiting.
     *
     * @return void
     */
    public function testCountsTheSegmentsAwaitingAnchor(): void
    {
        $tally = new VerificationTally;

        $tally->add(self::report(1, IntegrityStatus::VALID, AnchorStatus::UNANCHORED));
        $tally->add(self::report(2, IntegrityStatus::VALID, AnchorStatus::UNANCHORED, awaiting: true));
        $tally->add(self::report(3, IntegrityStatus::VALID, AnchorStatus::UNANCHORED, awaiting: true));

        self::assertSame(2, $tally->awaiting());
        self::assertSame(3, $tally->anchoring()['unanchored']);
    }

    /**
     * The unsealed counts are kept as given, pending apart from overdue.
     *
     * @return void
     */
    public function testKeepsTheUnsealedCounts(): void
    {
        $tally = new VerificationTally;

        $tally->unsealed(5, 2);

        self::assertSame(5, $tally->pending());
        self::assertSame(2, $tally->overdue());
    }

    /**
     * A report of the sequence, in the statuses given, with the finding and id
     * given, awaiting its first anchoring when said to.
     *
     * @param  int  $sequence
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus  $integrity
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus  $anchoring
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @param  ?string  $firstBadId
     * @param  bool  $awaiting
     * @return \SineMacula\Laravel\AuditLog\Integrity\SegmentReport
     */
    private static function report(
        int $sequence,
        IntegrityStatus $integrity,
        AnchorStatus $anchoring,
        ?Finding $finding = null,
        ?string $firstBadId = null,
        bool $awaiting = false,
    ): SegmentReport {
        return new SegmentReport($sequence, self::FIRST, $integrity, $anchoring, 1, $finding, $firstBadId, null, $awaiting);
    }
}
