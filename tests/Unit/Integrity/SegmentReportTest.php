<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;

/**
 * Unit tests for one segment's report: what it keeps, its line of output, and
 * the verdict of several findings, the most severe status first, then the first
 * finding in enum order, then the first id bytewise, with a valid prune record
 * giving `pruned` only while nothing worse is found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SegmentReport::class)]
final class SegmentReportTest extends TestCase
{
    /** @var string A seal's id. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000001';

    /** @var string A seal's digest. */
    private const string DIGEST = '329162defc18f3f10f3a8a351a7faa0c0e5e1004d65ea3b432feb0b54d3282c6';

    /** @var string The first entry id, bytewise. */
    private const string FIRST = '01932b4e-8a40-7000-8000-000000000001';

    /** @var string The second entry id, bytewise. */
    private const string SECOND = '01932b4e-8a40-7000-8000-000000000002';

    /**
     * Raise every PHP warning as an exception, so each report is also built and
     * read quietly: inside a Laravel application a warning becomes an
     * exception, which would turn verifying the log into an error.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        set_error_handler(static function (int $level, string $message): never {
            throw new \ErrorException($message, 0, $level);
        });
    }

    /**
     * Restore the error handler after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        restore_error_handler();

        parent::tearDown();
    }

    /**
     * The line names the segment, both statuses, whether it awaits its first
     * anchoring, the member rows found, and the finding and first id, in that
     * order of keys, and nothing else.
     *
     * @return void
     */
    public function testTheLineIsPinned(): void
    {
        $report = new SegmentReport(3, self::SEAL_ID, IntegrityStatus::TAMPERED, AnchorStatus::UNANCHORED, 2, Finding::ENTRY_HMAC, self::FIRST, self::DIGEST, true);

        self::assertSame([
            'type'            => 'segment',
            'sequence'        => 3,
            'seal_id'         => self::SEAL_ID,
            'integrity'       => 'tampered',
            'anchoring'       => 'unanchored',
            'awaiting_anchor' => true,
            'members'         => 2,
            'finding'         => 'entry_hmac',
            'first_bad_id'    => self::FIRST,
        ], $report->toArray());
    }

    /**
     * A valid segment's line has no finding and no first id, and is not
     * awaiting unless told it is.
     *
     * @return void
     */
    public function testAValidLineHasNoFinding(): void
    {
        $line = (new SegmentReport(1, self::SEAL_ID, IntegrityStatus::VALID, AnchorStatus::ANCHORED, 4))->toArray();

        self::assertNull($line['finding']);
        self::assertNull($line['first_bad_id']);
        self::assertFalse($line['awaiting_anchor']);
        self::assertSame('anchored', $line['anchoring']);
    }

    /**
     * The report keeps the digest recomputed from the seal's fields, which the
     * next seal's link is checked against, and `null` for a seal that could not
     * be read; neither is in the line.
     *
     * @return void
     */
    public function testKeepsItsDigest(): void
    {
        $read   = new SegmentReport(1, self::SEAL_ID, IntegrityStatus::VALID, AnchorStatus::UNANCHORED, 1, null, null, self::DIGEST);
        $unread = new SegmentReport(1, self::SEAL_ID, IntegrityStatus::UNVERIFIABLE, AnchorStatus::UNANCHORED, 0, Finding::SEAL_MALFORMED, self::SEAL_ID);

        self::assertSame(self::DIGEST, $read->digest);
        self::assertNull($unread->digest);
        self::assertArrayNotHasKey('digest', $read->toArray());
        self::assertNotContains(self::DIGEST, $read->toArray());
    }

    /**
     * No finding is valid, with no finding and no first id.
     *
     * @return void
     */
    public function testNoFindingIsValid(): void
    {
        self::assertSame([IntegrityStatus::VALID, null, null], SegmentReport::verdict([], false));
    }

    /**
     * The most severe status wins whatever order the findings come in: a
     * tampered finding beats an unverifiable and an incomplete one, though it
     * comes last and is later in enum order.
     *
     * @return void
     */
    public function testTheMostSevereStatusWins(): void
    {
        $findings = [
            [Finding::MISSING_ENTRY, self::FIRST],
            [Finding::ENTRY_KEY, self::FIRST],
            [Finding::ENTRY_HMAC, self::SECOND],
        ];

        self::assertSame([IntegrityStatus::TAMPERED, Finding::ENTRY_HMAC, self::SECOND], SegmentReport::verdict($findings, false));
        self::assertSame([IntegrityStatus::UNVERIFIABLE, Finding::ENTRY_KEY, self::FIRST], SegmentReport::verdict(array_slice($findings, 0, 2), false));
    }

    /**
     * Within the most severe status, the first finding in enum order wins, not
     * the first given.
     *
     * @return void
     */
    public function testWithinAStatusTheFirstFindingInEnumOrderWins(): void
    {
        $findings = [
            [Finding::ENTRY_HMAC, self::FIRST],
            [Finding::CHAIN_BROKEN, self::SEAL_ID],
            [Finding::SEAL_DIGEST, self::SEAL_ID],
        ];

        self::assertSame([IntegrityStatus::TAMPERED, Finding::SEAL_DIGEST, self::SEAL_ID], SegmentReport::verdict($findings, false));
    }

    /**
     * Of the ids a finding was found at, the first bytewise is reported, not
     * the first given.
     *
     * @return void
     */
    public function testTheFirstIdIsTheFirstBytewise(): void
    {
        $findings = [
            [Finding::MEMBER_HMAC, self::SECOND],
            [Finding::MEMBER_HMAC, self::FIRST],
        ];

        self::assertSame([IntegrityStatus::TAMPERED, Finding::MEMBER_HMAC, self::FIRST], SegmentReport::verdict($findings, false));
    }

    /**
     * A finding found at no id reports no first id, and an id given with it
     * elsewhere is still reported.
     *
     * @return void
     */
    public function testAFindingAtNoIdHasNoFirstId(): void
    {
        self::assertSame([IntegrityStatus::TAMPERED, Finding::SEQUENCE_GAP, null], SegmentReport::verdict([[Finding::SEQUENCE_GAP, null]], false));
        $findings = [[Finding::SEQUENCE_GAP, null], [Finding::SEQUENCE_GAP, self::SEAL_ID]];

        self::assertSame([IntegrityStatus::TAMPERED, Finding::SEQUENCE_GAP, self::SEAL_ID], SegmentReport::verdict($findings, false));
    }

    /**
     * A valid prune record makes a segment `pruned` with no finding, but never
     * hides a finding of any failing status.
     *
     * @return void
     */
    public function testAPrunedSegmentIsPrunedOnlyWhileNothingWorseIsFound(): void
    {
        self::assertSame([IntegrityStatus::PRUNED, null, null], SegmentReport::verdict([], true));
        self::assertSame([IntegrityStatus::INCOMPLETE, Finding::MISSING_ENTRY, self::FIRST], SegmentReport::verdict([[Finding::MISSING_ENTRY, self::FIRST]], true));
        self::assertSame([IntegrityStatus::UNVERIFIABLE, Finding::ENTRY_KEY, self::FIRST], SegmentReport::verdict([[Finding::ENTRY_KEY, self::FIRST]], true));
        self::assertSame([IntegrityStatus::TAMPERED, Finding::SEAL_SIGNATURE, self::SEAL_ID], SegmentReport::verdict([[Finding::SEAL_SIGNATURE, self::SEAL_ID]], true));
    }
}
