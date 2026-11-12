<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity;

use Carbon\CarbonImmutable;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\DiskAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\CheckpointWriter;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalVerifier;
use SineMacula\Laravel\AuditLog\Integrity\KeyStoreVerifier;
use SineMacula\Laravel\AuditLog\Integrity\ManifestVerifier;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\RunFinding;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\VerificationSummary;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\RecordsStorageStatements;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\SeedsArtifacts;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Integrity\RecordingAnchor;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for the verification of the log, on whichever engine the suite
 * runs against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Verifier::class)]
final class VerifierTest extends TestCase
{
    use MakesSubjectKeys, RecordsStorageStatements, SealsEntries, SeedsArtifacts, WritesTheJournal;

    /** @var string When every seal of a test is made. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When a run begins, unless a test says otherwise: well past the grace of every seal, and within the allowed age of every entry stored by default. */
    private const string VERIFIED_AT = '2026-11-02 04:00:00';

    /** @var string The disk a disk anchor writes to. */
    private const string DISK = 'anchors';

    /** @var string A secret of the first key of an explicit ring. */
    private const string SECRET_2025 = 'audit-log verify test key 2025 0123456789';

    /** @var string A secret of the second key of an explicit ring. */
    private const string SECRET_2026 = 'audit-log verify test key 2026 0123456789';

    /** @var string A digest no seal has. */
    private const string OTHER_DIGEST = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /** @var string An id no seal has. */
    private const string OTHER_ID = '01932b4e-9000-7000-8000-00000000ffff';

    /** @var list<\SineMacula\Laravel\AuditLog\Integrity\SegmentReport> The reports the last run streamed, in order. */
    private array $streamed = [];

    /**
     * Seal entries at a fixed time for every test.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->sealAt(self::SEALED_AT);
    }

    /**
     * Put the storage connection's reader back, in case a test replaced it.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::connection(StorageConnection::name())->setReadPdo(null);

        parent::tearDown();
    }

    /**
     * A log with no seal and no entry is valid and the run complete: the empty
     * range from 1 to 0, no head, no segment and nothing pending.
     *
     * @return void
     */
    public function testAnEmptyLogIsValidAndComplete(): void
    {
        $pages   = $this->recordPages();
        $summary = $this->verifyLog();

        self::assertCount(0, $pages);

        self::assertSame([], $this->streamed);
        self::assertSame(1, $summary->from);
        self::assertSame(0, $summary->to);
        self::assertNull($summary->head);
        self::assertTrue($summary->complete);
        self::assertFalse($summary->fails(true));
        self::assertNull($summary->remote);
        self::assertSame(0, $summary->pending);
        self::assertSame([], $summary->findings);
    }

    /**
     * Every seal's report is streamed once, in sequence order, and counted, and
     * the run covers the range to the head it observed.
     *
     * @return void
     */
    public function testEverySegmentIsStreamedInOrder(): void
    {
        $this->storeSeals(3);

        $summary = $this->verifyLog();

        self::assertSame([1, 2, 3], $this->sequences());
        self::assertSame(array_column($this->seals(), 'id'), array_map(static fn (SegmentReport $report): string => $report->sealId, $this->streamed));
        self::assertSame([1, 3, 3], [$summary->from, $summary->to, $summary->head]);
        self::assertSame(3, $summary->integrity['valid']);
        self::assertSame(3, $summary->anchoring['unanchored']);
        self::assertFalse($summary->fails(false));
    }

    /**
     * A first seal deleted with its members and entries is still found: the
     * walk expects sequence 1 and finds 2, a gap.
     *
     * @return void
     */
    public function testADeletedGenesisSealIsTampered(): void
    {
        $this->storeSeals(2);
        $this->deleteSeal(1);

        $summary = $this->verifyLog();

        self::assertSame([2], $this->sequences());
        self::assertSame(Finding::SEQUENCE_GAP, $this->streamed[0]->finding);
        self::assertSame(IntegrityStatus::TAMPERED, $this->streamed[0]->integrity);
        self::assertSame(Finding::SEQUENCE_GAP, $summary->firstFinding);
        self::assertTrue($summary->fails(false));
    }

    /**
     * A ranged run whose boundary seal does not exist finds a gap of the run,
     * and walks from its first seal with no link to check.
     *
     * @return void
     */
    public function testAMissingBoundarySealIsAGap(): void
    {
        $this->storeSeals(3);
        $this->deleteSeal(1);

        $summary = $this->verifyLog(new VerificationRange(2));

        self::assertSame([2, 3], $this->sequences());
        self::assertNull($this->streamed[0]->finding);
        self::assertSame([Finding::SEQUENCE_GAP], self::findingsOf($summary));
        self::assertNull($summary->findings[0]->firstBadId);
        self::assertTrue($summary->fails(false));
    }

    /**
     * An anchor that fails when asked to confirm a receipt is asked once in a
     * run: every later segment is unavailable without a call.
     *
     * @return void
     */
    public function testAFailingAnchorIsAskedOnce(): void
    {
        $this->storeSeals(5);

        $anchor = new RecordingAnchor(false);

        $this->anchorAll($anchor);
        $anchor->failing();

        $calls   = count($anchor->calls());
        $summary = $this->verifyLog(anchor: $anchor);

        self::assertSame(['confirms'], array_slice($anchor->calls(), $calls));
        self::assertSame(5, $summary->anchoring['unavailable']);
        self::assertSame(5, $summary->integrity['valid']);
    }

    /**
     * An anchor that recovers is still not asked again in the run that saw it
     * fail, and is asked again by the next run.
     *
     * @return void
     */
    public function testAFailedAnchorIsAskedAgainByTheNextRun(): void
    {
        $this->storeSeals(2);

        $anchor = new RecordingAnchor(false);

        $this->anchorAll($anchor);
        $anchor->failing();

        $this->verifyLog(anchor: $anchor);
        $anchor->recovering();

        $calls = count($anchor->calls());

        $this->verifyLog(anchor: $anchor);

        self::assertSame(['confirms', 'confirms'], array_slice($anchor->calls(), $calls));
    }

    /**
     * An anchor that holds no seal agrees with a log that has none: the
     * anchor's head is anchored, and a strict run passes.
     *
     * @return void
     */
    public function testAnEmptyRemoteAndAnEmptyLogAgree(): void
    {
        $anchor  = new RecordingAnchor;
        $summary = $this->verifyLog(anchor: $anchor);

        self::assertSame(AnchorStatus::ANCHORED, $summary->remote);
        self::assertNull($summary->remoteHead);
        self::assertTrue($summary->anchorConfigured);
        self::assertTrue($summary->discovers);
        self::assertFalse($summary->fails(true));
        self::assertSame(['latest'], $anchor->calls());
    }

    /**
     * The grace is measured from the run's start, read once: seals 600 seconds
     * old await anchoring and pass strictly, 901 seconds old do not.
     *
     * @return void
     */
    public function testTheGraceIsMeasuredFromTheRunsStart(): void
    {
        $this->storeSeals(3);

        $clock = \Mockery::mock(Clock::class);

        $clock->shouldReceive('now')->once()->andReturn(new CarbonImmutable('2026-11-01 13:10:00', 'UTC'));

        $summary = $this->verifyLog(anchor: new RecordingAnchor, clock: $clock);

        self::assertSame(3, $summary->awaiting);
        self::assertSame([true, true, true], array_map(static fn (SegmentReport $report): bool => $report->awaitingAnchor, $this->streamed));
        self::assertSame(AnchorStatus::UNANCHORED, $summary->remote);
        self::assertFalse($summary->fails(true));

        $late = $this->verifyLog(anchor: new RecordingAnchor, clock: FrozenClock::at('2026-11-01 13:15:01'));

        self::assertSame(0, $late->awaiting);
        self::assertTrue($late->fails(true));
    }

    /**
     * Nothing is accumulated: the callback receives each report once, and the
     * summary holds counts and the run's findings, never a report.
     *
     * @return void
     */
    public function testNothingIsAccumulated(): void
    {
        $this->storeSeals(3);

        $summary = $this->verifyLog();
        $ids     = array_map(static fn (SegmentReport $report): string => $report->sealId, $this->streamed);

        self::assertCount(3, $ids);
        self::assertSame($ids, array_values(array_unique($ids)));

        foreach (get_object_vars($summary) as $name => $value) {
            $values = is_array($value) ? $value : [$value];

            self::assertSame([], array_filter($values, static fn (mixed $item): bool => $item instanceof SegmentReport), $name);
        }
    }

    /**
     * A ranged run covers only its range, and is not complete, however much of
     * the log it covers.
     *
     * @return void
     */
    public function testARangedRunIsNotComplete(): void
    {
        $this->storeSeals(3);

        $summary = $this->verifyLog(new VerificationRange(2, 3));

        self::assertSame([2, 3], $this->sequences());
        self::assertSame([2, 3, 3], [$summary->from, $summary->to, $summary->head]);
        self::assertFalse($summary->complete);
        self::assertFalse($this->verifyLog(new VerificationRange(1, 3))->complete);
    }

    /**
     * A ranged run checks its first seal's link: re-signed to link elsewhere it
     * is a broken chain, though the boundary seal is valid.
     *
     * @return void
     */
    public function testARangedRunChecksItsBoundaryLink(): void
    {
        $this->storeSeals(3);

        self::assertNull($this->verifyLog(new VerificationRange(2))->firstFinding);

        $this->resign(2, ['previous_digest' => self::OTHER_DIGEST]);

        $summary = $this->verifyLog(new VerificationRange(2));

        self::assertSame([2, 3], $this->sequences());
        self::assertSame(Finding::CHAIN_BROKEN, $this->streamed[0]->finding);
        self::assertTrue($summary->fails(false));
    }

    /**
     * A boundary seal that fails its checks is reported before the range, and
     * the link is checked against its recomputed digest.
     *
     * @return void
     */
    public function testABoundaryThatFailsIsReported(): void
    {
        $this->storeSeals(3);

        $this->checkpoints()->where('sequence', 1)->update(['seal_digest' => self::OTHER_DIGEST]);

        $summary = $this->verifyLog(new VerificationRange(2));

        self::assertSame([1, 2, 3], $this->sequences());
        self::assertSame(Finding::SEAL_DIGEST, $this->streamed[0]->finding);
        self::assertSame(0, $this->streamed[0]->members);
        self::assertNull($this->streamed[1]->finding);
        self::assertSame(1, $summary->integrity['tampered']);
        self::assertSame(2, $summary->integrity['valid']);
    }

    /**
     * A ranged run skips the whole log's checks for orphaned members and
     * overdue entries, which a complete run fails on.
     *
     * @return void
     */
    public function testARangedRunSkipsTheWholeLogChecks(): void
    {
        $this->storeSeals(2);
        $this->orphanMember('01932b4e-8a40-7000-8000-00000000aaaa');
        $this->storeEntryAt('2026-10-30 00:00:00');

        $ranged = $this->verifyLog(new VerificationRange(1, 2));

        self::assertSame([], $ranged->findings);
        self::assertSame(0, $ranged->pending);
        self::assertSame(0, $ranged->overdue);
        self::assertFalse($ranged->fails(false));

        $complete = $this->verifyLog();

        self::assertSame([Finding::ORPHAN_MEMBER, Finding::OVERDUE_UNSEALED], self::findingsOf($complete));
        self::assertTrue($complete->fails(false));
    }

    /**
     * A seal written while the run is under way, after it read the head, is
     * never read: the run ends at the head it observed.
     *
     * @return void
     */
    public function testSealsAfterTheStartHeadAreSkipped(): void
    {
        $this->storeSeals(2);

        $sealed  = false;
        $summary = $this->verifier()->verify(VerificationRange::whole(), function (SegmentReport $report) use (&$sealed): void {
            $this->streamed[] = $report;

            if ($sealed) {
                return;
            }

            $this->storeEntries(1, '2026-11-01 12:50:00');
            $this->sealAll();

            $sealed = true;
        });

        self::assertCount(3, $this->seals());
        self::assertSame([1, 2], $this->sequences());
        self::assertSame([1, 2, 2], [$summary->from, $summary->to, $summary->head]);
        self::assertFalse($summary->fails(false));
    }

    /**
     * A member row whose seal is missing is tampering, a finding of the run
     * that counts every such row and names the first by seal and entry id.
     *
     * @return void
     */
    public function testAnOrphanedMemberIsTampered(): void
    {
        $this->storeSeals(1);
        $this->orphanMember('01932b4e-8a40-7000-8000-00000000bbbb', self::OTHER_ID);
        $this->orphanMember('01932b4e-8a40-7000-8000-00000000cccc', '01932b4e-9000-7000-8000-00000000eeee');
        $this->orphanMember('01932b4e-8a40-7000-8000-00000000aaaa', self::OTHER_ID);

        $summary = $this->verifyLog();

        self::assertSame([Finding::ORPHAN_MEMBER], self::findingsOf($summary));
        self::assertSame(3, $summary->findings[0]->count);
        self::assertSame('01932b4e-8a40-7000-8000-00000000cccc', $summary->findings[0]->firstBadId);
        self::assertSame(IntegrityStatus::TAMPERED, $summary->findings[0]->status());
        self::assertSame(Finding::ORPHAN_MEMBER, $summary->firstFinding);
        self::assertTrue($summary->fails(false));
    }

    /**
     * Unsealed entries older than the allowed age are overdue, making the run
     * incomplete at the first; younger ones are counted as pending.
     *
     * @return void
     */
    public function testAnOverdueUnsealedRowIsIncomplete(): void
    {
        $this->storeSeals(1);

        $later   = $this->storeEntryAt('2026-10-31 02:00:00');
        $earlier = $this->storeEntryAt('2026-10-31 01:00:00');

        $this->storeEntryAt('2026-11-02 03:00:00');

        $summary = $this->verifyLog();

        self::assertSame([Finding::OVERDUE_UNSEALED], self::findingsOf($summary));
        self::assertSame(2, $summary->findings[0]->count);
        self::assertSame($earlier, $summary->findings[0]->firstBadId);
        self::assertNotSame($later, $summary->firstBadId);
        self::assertSame(2, $summary->overdue);
        self::assertSame(1, $summary->pending);
        self::assertSame(IntegrityStatus::INCOMPLETE, $summary->findings[0]->status());
        self::assertTrue($summary->fails(false));
    }

    /**
     * An entry no seal holds that is younger than the allowed age, up to the
     * very limit, is pending and never bad.
     *
     * @return void
     */
    public function testAYoungUnsealedRowIsPendingNeverBad(): void
    {
        $this->storeSeals(1);
        $this->storeEntryAt('2026-11-02 03:59:00');
        $this->storeEntryAt('2026-11-01 03:00:00');

        $summary = $this->verifyLog();

        self::assertSame(2, $summary->pending);
        self::assertSame(0, $summary->overdue);
        self::assertSame([], $summary->findings);
        self::assertFalse($summary->fails(true));
    }

    /**
     * An anchor's head matching the local seal at its sequence is anchored, and
     * is reported with its sequence.
     *
     * @return void
     */
    public function testTheRemoteHeadMatchingIsAnchored(): void
    {
        $this->storeSeals(2);

        $anchor = new RecordingAnchor;

        $this->anchorAll($anchor);

        $summary = $this->verifyLog(anchor: $anchor);

        self::assertSame(AnchorStatus::ANCHORED, $summary->remote);
        self::assertSame(2, $summary->remoteHead);
        self::assertSame([], $summary->findings);
    }

    /**
     * An anchor's head that is not the local head, but matches the local seal
     * at its sequence, is anchored: the anchor may lag the log.
     *
     * @return void
     */
    public function testARemoteHeadBehindTheTailIsAnchored(): void
    {
        $this->storeSeals(3);

        $anchor = new RecordingAnchor;

        $this->anchorAll($anchor, 2);

        $summary = $this->verifyLog(anchor: $anchor);

        self::assertSame(AnchorStatus::ANCHORED, $summary->remote);
        self::assertSame(2, $summary->remoteHead);
        self::assertFalse($summary->fails(false));
    }

    /**
     * An anchor's head beyond the local tail is a missing tail, which is
     * tampering, and contradicts the local log.
     *
     * @return void
     */
    public function testARemoteHeadBeyondTheTailIsTampered(): void
    {
        $this->storeSeals(2);

        $summary = $this->verifyLog(anchor: (new RecordingAnchor)->holdInstead(3, self::OTHER_DIGEST));

        self::assertSame(AnchorStatus::CONTRADICTED, $summary->remote);
        self::assertSame(3, $summary->remoteHead);
        self::assertSame([Finding::MISSING_TAIL], self::findingsOf($summary));
        self::assertSame(Finding::MISSING_TAIL, $summary->firstFinding);
        self::assertTrue($summary->fails(false));
    }

    /**
     * An anchor's head with no local log at all is a missing tail.
     *
     * @return void
     */
    public function testAnEmptyLocalLogWithARemoteHeadIsTampered(): void
    {
        $summary = $this->verifyLog(anchor: (new RecordingAnchor)->holdInstead(1, self::OTHER_DIGEST));

        self::assertNull($summary->head);
        self::assertSame(AnchorStatus::CONTRADICTED, $summary->remote);
        self::assertSame([Finding::MISSING_TAIL], self::findingsOf($summary));
        self::assertTrue($summary->fails(false));
    }

    /**
     * An anchor holding no seal leaves a local log unanchored: a plain run
     * passes, and a strict one fails on seals past the grace.
     *
     * @return void
     */
    public function testAnEmptyRemoteWithALocalLogIsUnanchored(): void
    {
        $this->storeSeals(2);

        $summary = $this->verifyLog(anchor: new RecordingAnchor);

        self::assertSame(AnchorStatus::UNANCHORED, $summary->remote);
        self::assertNull($summary->remoteHead);
        self::assertSame([], $summary->findings);
        self::assertFalse($summary->fails(false));
        self::assertTrue($summary->fails(true));
    }

    /**
     * An anchor's head with another digest than the local seal at its sequence
     * contradicts that segment alone, and settles no anchoring.
     *
     * @return void
     */
    public function testARemoteDigestDifferingAtItsSequenceIsContradicted(): void
    {
        $this->storeSeals(2);

        $summary = $this->verifyLog(anchor: (new RecordingAnchor)->holdInstead(2, self::OTHER_DIGEST));

        self::assertSame(AnchorStatus::CONTRADICTED, $this->streamed[1]->anchoring);
        self::assertSame(Finding::ANCHOR_CONTRADICTION, $this->streamed[1]->finding);
        self::assertSame(AnchorStatus::UNANCHORED, $this->streamed[0]->anchoring);
        self::assertSame(AnchorStatus::CONTRADICTED, $summary->remote);
        self::assertSame([], $summary->findings);
        self::assertSame(1, $summary->anchoring['contradicted']);
        self::assertTrue($summary->fails(false));
    }

    /**
     * An anchor's head the walk meets is compared by the walk alone: the
     * segment carries the contradiction, and the run adds none.
     *
     * @return void
     */
    public function testARemoteHeadTheWalkMeetsIsComparedByTheWalk(): void
    {
        $this->storeSeals(3);

        $whole  = $this->verifyLog(anchor: (new RecordingAnchor)->holdInstead(2, self::OTHER_DIGEST));
        $ranged = $this->verifyLog(new VerificationRange(2), (new RecordingAnchor)->holdInstead(2, self::OTHER_DIGEST));

        foreach ([$whole, $ranged] as $summary) {
            self::assertSame(AnchorStatus::CONTRADICTED, $summary->remote);
            self::assertSame([], $summary->findings);
            self::assertSame(1, $summary->anchoring['contradicted']);
        }
    }

    /**
     * An anchor whose head conflicts is still asked to confirm each receipt,
     * since only a failure stops it being asked.
     *
     * @return void
     */
    public function testAConflictedHeadStillAsksForReceipts(): void
    {
        $this->storeSeals(2);
        $this->checkpoints()->update(['anchor' => 'mock', 'anchor_receipt' => '{"proof":"held"}']);

        $anchor = \Mockery::mock(CheckpointAnchor::class);

        $anchor->shouldReceive('supportsDiscovery')->andReturnTrue();
        $anchor->shouldReceive('name')->andReturn('mock');
        $anchor->shouldReceive('latest')->once()->andThrow(AnchorConflictException::forSequence(2));
        $anchor->shouldReceive('confirms')->twice()->andReturnTrue();

        $summary = $this->verifyLog(anchor: $anchor);

        self::assertSame(2, $summary->anchoring['anchored']);
        self::assertSame(AnchorStatus::CONTRADICTED, $summary->remote);
        self::assertSame([Finding::ANCHOR_CONFLICT], self::findingsOf($summary));
    }

    /**
     * An anchor's head outside a ranged run is read on its own: a matching
     * digest is anchored, another contradicts the run at that seal.
     *
     * @return void
     */
    public function testARemoteHeadOutsideTheRangeIsReadOnItsOwn(): void
    {
        $this->storeSeals(2);

        $anchor = new RecordingAnchor;

        $this->anchorAll($anchor);

        self::assertSame(AnchorStatus::ANCHORED, $this->verifyLog(new VerificationRange(1, 1), $anchor)->remote);

        $summary = $this->verifyLog(new VerificationRange(1, 1), (new RecordingAnchor)->holdInstead(2, self::OTHER_DIGEST));

        self::assertSame([1], $this->sequences());
        self::assertSame(AnchorStatus::CONTRADICTED, $summary->remote);
        self::assertSame([Finding::ANCHOR_CONTRADICTION], self::findingsOf($summary));
        self::assertSame($this->seals()[1]['id'], $summary->findings[0]->firstBadId);
        self::assertTrue($summary->fails(false));
    }

    /**
     * An anchor's head at a sequence the local log no longer holds, between
     * seals it does, is a contradiction of the run, with no seal to name.
     *
     * @return void
     */
    public function testARemoteHeadAtASealMissingLocallyIsContradicted(): void
    {
        $this->storeSeals(3);

        $anchor = new RecordingAnchor;

        $this->anchorAll($anchor, 2);
        $this->deleteSeal(2);

        $summary = $this->verifyLog(anchor: $anchor);

        self::assertSame(AnchorStatus::CONTRADICTED, $summary->remote);
        self::assertSame([Finding::ANCHOR_CONTRADICTION], self::findingsOf($summary));
        self::assertNull($summary->findings[0]->firstBadId);
        self::assertSame(Finding::SEQUENCE_GAP, $this->streamed[1]->finding);
    }

    /**
     * An anchor's head at a local seal that cannot be read is unanchored, while
     * the seal is unverifiable.
     *
     * @return void
     */
    public function testARemoteHeadAtAMalformedSealIsUnanchored(): void
    {
        $this->storeSeals(2);

        $anchor = new RecordingAnchor;

        $this->anchorAll($anchor);
        $this->checkpoints()->where('sequence', 2)->update(['members_digest' => 'not a digest']);

        $summary = $this->verifyLog(anchor: $anchor);

        self::assertSame(AnchorStatus::UNANCHORED, $summary->remote);
        self::assertSame([], $summary->findings);
        self::assertSame(Finding::SEAL_MALFORMED, $this->streamed[1]->finding);

        self::assertSame(AnchorStatus::UNANCHORED, $this->verifyLog(new VerificationRange(1, 1), $anchor)->remote);
    }

    /**
     * An anchor that holds two digests for its head conflicts: a finding of the
     * run, which is tampering, and the anchor's head is contradicted.
     *
     * @return void
     */
    public function testARemoteConflictIsTampered(): void
    {
        $this->storeSeals(1);

        $summary = $this->verifyLog(anchor: (new RecordingAnchor)->failing(AnchorConflictException::forSequence(1)));

        self::assertSame(AnchorStatus::CONTRADICTED, $summary->remote);
        self::assertNull($summary->remoteHead);
        self::assertSame([Finding::ANCHOR_CONFLICT], self::findingsOf($summary));
        self::assertSame(Finding::ANCHOR_CONFLICT, $summary->firstFinding);
        self::assertTrue($summary->fails(false));
    }

    /**
     * An anchor that fails when asked for its head is unavailable and not asked
     * again, so every segment is unavailable without a call.
     *
     * @return void
     */
    public function testAnUnavailableRemoteIsUnavailable(): void
    {
        $this->storeSeals(2);

        $anchor = new RecordingAnchor;

        $this->anchorAll($anchor);
        $anchor->failing();

        $calls   = count($anchor->calls());
        $summary = $this->verifyLog(anchor: $anchor);

        self::assertSame(['latest'], array_slice($anchor->calls(), $calls));
        self::assertSame(AnchorStatus::UNAVAILABLE, $summary->remote);
        self::assertNull($summary->remoteHead);
        self::assertSame(2, $summary->anchoring['unavailable']);
        self::assertSame([], $summary->findings);
        self::assertFalse($summary->fails(false));
        self::assertTrue($summary->fails(true));
    }

    /**
     * An anchor that cannot discover is never asked for its head, so the head
     * is unanchored and a strict run fails.
     *
     * @return void
     */
    public function testAnAnchorWithoutDiscoveryIsNeverAsked(): void
    {
        $this->storeSeals(1);

        $anchor  = new RecordingAnchor(false);
        $summary = $this->verifyLog(anchor: $anchor);

        self::assertNotContains('latest', $anchor->calls());
        self::assertFalse($summary->discovers);
        self::assertTrue($summary->anchorConfigured);
        self::assertSame(AnchorStatus::UNANCHORED, $summary->remote);
        self::assertFalse($summary->fails(false));
        self::assertTrue($summary->fails(true));
    }

    /**
     * With the null anchor, no anchor is configured: the run has no anchor's
     * head and no discovery, and every segment is unanchored.
     *
     * @return void
     */
    public function testTheNullAnchorMeansNoAnchorIsConfigured(): void
    {
        $this->storeSeals(1);

        $summary = $this->verifyLog(anchor: new NullAnchor);

        self::assertNull($summary->remote);
        self::assertNull($summary->remoteHead);
        self::assertFalse($summary->anchorConfigured);
        self::assertFalse($summary->discovers);
        self::assertSame(1, $summary->anchoring['unanchored']);
        self::assertFalse($summary->fails(true));
    }

    /**
     * A truncated tail is found with every local receipt cleared: the anchor's
     * head, asked for independently of them, is beyond the local log.
     *
     * @return void
     */
    public function testTailTruncationIsFoundWithLocalReceiptsCleared(): void
    {
        $this->storeSeals(3);

        $anchor = new RecordingAnchor;

        $this->anchorAll($anchor);
        $this->deleteSeal(3);
        $this->checkpoints()->update(['anchor' => null, 'anchor_receipt' => null, 'anchored_at' => null]);

        $summary = $this->verifyLog(anchor: $anchor);

        self::assertSame([1, 2], $this->sequences());
        self::assertSame(2, $summary->head);
        self::assertSame(3, $summary->remoteHead);
        self::assertSame([Finding::MISSING_TAIL], self::findingsOf($summary));
        self::assertTrue($summary->fails(false));
    }

    /**
     * The anchor's head is asked for before the local head, so a seal anchored
     * meanwhile is never a missing tail.
     *
     * @return void
     */
    public function testTheRemoteIsAskedBeforeTheLocalHead(): void
    {
        $this->storeSeals(2);

        $anchor = \Mockery::mock(CheckpointAnchor::class);

        $anchor->shouldReceive('supportsDiscovery')->andReturnTrue();
        $anchor->shouldReceive('name')->andReturn('mock');
        $anchor->shouldReceive('latest')->once()->andReturnUsing(function (): AnchoredHead {
            $this->storeEntries(1, '2026-11-01 12:50:00');
            $this->sealAll();

            return new AnchoredHead(3, (string) $this->seals()[2]['seal_digest']);
        });

        $summary = $this->verifyLog(anchor: $anchor);

        self::assertSame(3, $summary->head);
        self::assertSame(AnchorStatus::ANCHORED, $summary->remote);
        self::assertSame([], $summary->findings);
    }

    /**
     * A log whose every seal the anchor confirms, under an anchor whose head
     * matches, passes a strict run.
     *
     * @return void
     */
    public function testAFullyAnchoredLogPassesStrict(): void
    {
        $this->storeSeals(2);

        $anchor = new DiskAnchor(Storage::fake(self::DISK), self::DISK, 'audit-log-anchors', app(SealSettings::class)->logId());

        $this->anchorAll($anchor);

        $summary = $this->verifyLog(anchor: $anchor);

        self::assertSame(2, $summary->anchoring['anchored']);
        self::assertSame(AnchorStatus::ANCHORED, $summary->remote);
        self::assertFalse($summary->fails(true));
    }

    /**
     * A run of the whole log records when it ran, the head it observed, its
     * strictness and whether it passed at it.
     *
     * @return void
     */
    public function testAFullRunRecordsItsCompletion(): void
    {
        $this->storeSeals(2);
        $this->verifyLog(anchor: new RecordingAnchor);

        self::assertSame(['at' => '2026-11-02T04:00:00.000000Z', 'head' => 2, 'passed' => true, 'strict' => false], $this->lastFull());

        $this->checkpoints()->where('sequence', 2)->update(['signature' => self::OTHER_DIGEST]);
        $this->verifyLog();

        self::assertSame(['at' => '2026-11-02T04:00:00.000000Z', 'head' => 2, 'passed' => false, 'strict' => false], $this->lastFull());
    }

    /**
     * A strict run records whether it passed strictly, so unanchored seals past
     * the grace are never recorded as a pass.
     *
     * @return void
     */
    public function testAStrictRunRecordsWhetherItPassedStrictly(): void
    {
        $this->storeSeals(2);

        $this->verifier(new RecordingAnchor)->verify(VerificationRange::whole(), static function (): void {}, true);

        self::assertSame(['at' => '2026-11-02T04:00:00.000000Z', 'head' => 2, 'passed' => false, 'strict' => true], $this->lastFull());
    }

    /**
     * A run of an empty log records its completion with no head.
     *
     * @return void
     */
    public function testAFullRunOfAnEmptyLogRecordsNoHead(): void
    {
        $this->verifyLog();

        self::assertSame(['at' => '2026-11-02T04:00:00.000000Z', 'head' => null, 'passed' => true, 'strict' => false], $this->lastFull());
    }

    /**
     * A ranged run whose last seals are missing is a gap, since the walk must
     * reach the range's last sequence.
     *
     * @return void
     */
    public function testAMissingLastSealOfARangeIsAGap(): void
    {
        $this->storeSeals(5);
        $this->deleteSeal(3);

        $summary = $this->verifyLog(new VerificationRange(2, 3));

        self::assertSame([2], $this->sequences());
        self::assertSame([Finding::SEQUENCE_GAP], self::findingsOf($summary));
        self::assertTrue($summary->fails(false));
    }

    /**
     * A range of which no seal is left is a gap, never an empty pass.
     *
     * @return void
     */
    public function testARangeWithNoSealIsAGap(): void
    {
        $this->storeSeals(5);
        $this->deleteSeal(3);
        $this->deleteSeal(4);

        $summary = $this->verifyLog(new VerificationRange(3, 4));

        self::assertSame([], $this->sequences());
        self::assertSame([Finding::SEQUENCE_GAP], self::findingsOf($summary));
        self::assertTrue($summary->fails(false));
    }

    /**
     * A seal below sequence 1 is outside the chain: a whole-log run finds it as
     * a gap with an orphaned member, and it is never the head.
     *
     * @return void
     */
    public function testASealOutsideTheChainIsFound(): void
    {
        $this->storeSeals(2);

        $phantom = ['id' => self::OTHER_ID, 'sequence' => 0] + $this->seals()[0];
        $entry   = $this->storeEntries(1, '2026-11-01 12:30:00')[0];

        $this->checkpoints()->insert($phantom);
        $this->orphanMember($entry);

        $summary = $this->verifyLog();

        self::assertSame(2, $summary->head);
        self::assertSame([1, 2], $this->sequences());
        self::assertSame([Finding::SEQUENCE_GAP, Finding::ORPHAN_MEMBER], self::findingsOf($summary));
        self::assertSame(self::OTHER_ID, $summary->findings[0]->firstBadId);
        self::assertSame(0, $summary->pending);
        self::assertTrue($summary->fails(false));
    }

    /**
     * A log whose only seal is outside the chain has no head, and the run still
     * finds the seal.
     *
     * @return void
     */
    public function testALogOfOnlyASealOutsideTheChainHasNoHead(): void
    {
        $this->storeSeals(1);
        $this->checkpoints()->update(['sequence' => 0]);

        $summary = $this->verifyLog();

        self::assertNull($summary->head);
        self::assertSame([Finding::SEQUENCE_GAP], array_slice(self::findingsOf($summary), 0, 1));
        self::assertTrue($summary->fails(false));
    }

    /**
     * A greatest stored sequence that cannot be read as an integer is refused,
     * never taken for an empty log.
     *
     * @return void
     */
    public function testAMalformedGreatestSequenceIsRefused(): void
    {
        if (DB::connection(StorageConnection::name())->getDriverName() !== 'sqlite') {
            self::markTestSkipped('Only SQLite stores text in an integer column.');
        }

        $this->storeSeals(1);
        $this->checkpoints()->update(['sequence' => 'first']);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('The greatest stored seal sequence is malformed.');

        $this->verifyLog();
    }

    /**
     * An unsealed entry further ahead of the clock than the lookback is a
     * finding, never pending; one within it is still pending.
     *
     * @return void
     */
    public function testAnUnsealedEntryFarAheadOfTheClockIsAFinding(): void
    {
        $this->storeSeals(1);

        $far  = $this->storeEntryAt('2099-01-01 00:00:00');
        $near = $this->storeEntryAt('2026-11-02 04:59:59');

        $summary = $this->verifyLog();

        self::assertSame([Finding::FUTURE_UNSEALED], self::findingsOf($summary));
        self::assertSame($far, $summary->findings[0]->firstBadId);
        self::assertSame(1, $summary->findings[0]->count);
        self::assertSame(1, $summary->pending);
        self::assertSame(0, $summary->overdue);
        self::assertSame(IntegrityStatus::INCOMPLETE, $summary->findings[0]->status());
        self::assertTrue($summary->fails(false));
        self::assertNotSame($near, $far);
    }

    /**
     * An unreadable seal at the anchor's head is compared by its stored digest:
     * another is a contradiction, the same leaves it unanchored.
     *
     * @return void
     */
    public function testAnUnreadableSealAtTheAnchorsHeadIsComparedByItsStoredDigest(): void
    {
        $this->storeSeals(2);

        $anchor = new DiskAnchor(Storage::fake(self::DISK), self::DISK, 'audit-log-anchors', app(SealSettings::class)->logId());

        $this->anchorAll($anchor);
        $this->checkpoints()->where('sequence', 2)->update(['algorithm_version' => 2]);

        $same = $this->verifyLog(anchor: $anchor);

        self::assertSame(AnchorStatus::UNANCHORED, $same->remote);
        self::assertSame([], self::findingsOf($same));

        $this->checkpoints()->where('sequence', 2)->update(['seal_digest' => self::OTHER_DIGEST]);

        $other = $this->verifyLog(anchor: $anchor);

        self::assertSame(AnchorStatus::CONTRADICTED, $other->remote);
        self::assertSame([Finding::ANCHOR_CONTRADICTION], self::findingsOf($other));
        self::assertSame(1, $other->integrity['unverifiable']);
        self::assertTrue($other->fails(false));
    }

    /**
     * When the walk reaches the anchor's head, the head settles every seal's
     * anchoring in one call, whatever the receipts hold.
     *
     * @return void
     */
    public function testTheAnchorsHeadSettlesAnchoringWithOneCall(): void
    {
        $this->storeSeals(3);

        $anchor = new RecordingAnchor;

        $this->anchorAll($anchor);
        $this->checkpoints()->update(['anchor' => null, 'anchor_receipt' => null, 'anchored_at' => null]);

        $before  = count($anchor->calls());
        $summary = $this->verifyLog(anchor: $anchor);

        self::assertSame(['latest'], array_slice($anchor->calls(), $before));
        self::assertSame(3, $summary->anchoring['anchored']);
        self::assertFalse($summary->fails(true));
    }

    /**
     * An anchor that holds no seal settles every seal unanchored with no call,
     * whatever receipts are kept beside the seals.
     *
     * @return void
     */
    public function testAnEmptyAnchorSettlesEverySealUnanchoredWithNoCall(): void
    {
        $this->storeSeals(2);

        $anchor = new RecordingAnchor;

        $this->checkpoints()->update(['anchor' => RecordingAnchor::NAME, 'anchor_receipt' => '{"sequence":1}', 'anchored_at' => '2026-11-01 13:05:00.000000']);

        $summary = $this->verifyLog(anchor: $anchor);

        self::assertSame(['latest'], $anchor->calls());
        self::assertSame(2, $summary->anchoring['unanchored']);
    }

    /**
     * A ranged run ending before the anchor's head cannot settle anchoring by
     * it, so each seal's receipt is put to the anchor.
     *
     * @return void
     */
    public function testARangeEndingBeforeTheAnchorsHeadAsksPerSeal(): void
    {
        $this->storeSeals(3);

        $anchor = new RecordingAnchor;

        $this->anchorAll($anchor);

        $before  = count($anchor->calls());
        $summary = $this->verifyLog(new VerificationRange(1, 2), $anchor);

        self::assertSame(['latest', 'confirms', 'confirms'], array_slice($anchor->calls(), $before));
        self::assertSame(2, array_sum($summary->anchoring));
    }

    /**
     * A ranged run records nothing, since it does not establish the whole log.
     *
     * @return void
     */
    public function testARangedRunRecordsNothing(): void
    {
        $this->storeSeals(2);
        $this->verifyLog(new VerificationRange(1, 2));

        self::assertNull(app(IntegrityProgress::class)->get(IntegrityProgress::VERIFY_LAST_FULL));
    }

    /**
     * A refused range verifies nothing, streams nothing and records nothing.
     *
     * @return void
     */
    public function testARefusedRangeVerifiesNothing(): void
    {
        $this->storeSeals(2);

        try {
            $this->verifyLog(new VerificationRange(1, 3));

            self::fail('Expected the range to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('--to is beyond the head of the log, seal 2.', $exception->getMessage());
        }

        self::assertSame([], $this->streamed);
        self::assertNull(app(IntegrityProgress::class)->get(IntegrityProgress::VERIFY_LAST_FULL));
    }

    /**
     * Seals under keys rotated between them verify, each under the key it
     * names, while both keys stay in the ring.
     *
     * @return void
     */
    public function testKeyRotationBetweenSealsVerifies(): void
    {
        $this->useRing(['k2025' => self::SECRET_2025], 'k2025');
        $this->storeEntries(2);
        $this->sealAll();
        $this->useRing(['k2025' => self::SECRET_2025, 'k2026' => self::SECRET_2026], 'k2026');
        $this->storeEntries(2, '2026-11-01 12:30:00');
        $this->sealAll();

        $summary = $this->verifyLog();

        self::assertSame(['k2025', 'k2026'], array_column($this->seals(), 'key_id'));
        self::assertSame(2, $summary->integrity['valid']);
        self::assertFalse($summary->fails(false));
    }

    /**
     * One seal holding entries signed under two keys verifies, each entry under
     * the key it names.
     *
     * @return void
     */
    public function testAMixedKeySegmentVerifies(): void
    {
        $this->useRing(['k2025' => self::SECRET_2025, 'k2026' => self::SECRET_2026], 'k2025');
        $this->storeEntries(2);
        $this->useRing(['k2025' => self::SECRET_2025, 'k2026' => self::SECRET_2026], 'k2026');
        $this->storeEntries(2, '2026-11-01 12:30:00');
        $this->sealAll();

        $summary = $this->verifyLog();

        self::assertSame(['k2025', 'k2026'], DB::connection(StorageConnection::name())->table(EntrySettings::table())->distinct()->orderBy('key_id')->pluck('key_id')->all());
        self::assertSame(4, $this->streamed[0]->members);
        self::assertSame(1, $summary->integrity['valid']);
    }

    /**
     * The walk reads the seals in pages of a hundred, in order across page
     * boundaries, each page after the seals before it verify.
     *
     * @return void
     */
    public function testTheWalkReadsEverySealAcrossPages(): void
    {
        $this->storeSealsQuickly(Verifier::SEAL_PAGE + 1);

        $pages   = $this->recordPages();
        $summary = $this->verifyLog();

        self::assertSame(range(1, Verifier::SEAL_PAGE + 1), $this->sequences());
        self::assertSame(Verifier::SEAL_PAGE + 1, $summary->integrity['valid']);
        self::assertCount(2, $pages);
        self::assertSame(100, Verifier::SEAL_PAGE);
    }

    /**
     * A full page with a seal missing ends after its last seal, so no seal is
     * read twice and the gap is found once.
     *
     * @return void
     */
    public function testAPageWithAGapResumesAfterItsLastSeal(): void
    {
        $this->storeSealsQuickly(Verifier::SEAL_PAGE + 2);
        $this->deleteSeal(50);

        $summary = $this->verifyLog();

        self::assertSame([...range(1, 49), ...range(51, Verifier::SEAL_PAGE + 2)], $this->sequences());
        self::assertSame(1, $summary->integrity['tampered']);
        self::assertSame(Finding::SEQUENCE_GAP, $this->streamed[49]->finding);
    }

    /**
     * Every run verifies the whole lifecycle journal and each seal's commitment
     * to it, a ranged run included, and summarises what it read.
     *
     * @return void
     */
    public function testEveryRunVerifiesTheJournal(): void
    {
        $this->storeSeals(1);
        $this->journalHold('01932b4e-d000-7000-8000-000000000001');
        $this->storeSeals(1);
        $this->journalHold('01932b4e-d000-7000-8000-000000000002');

        foreach (['the whole log' => VerificationRange::whole(), 'a range' => new VerificationRange(2, 2)] as $what => $range) {
            $summary = $this->verifyLog($range);

            self::assertSame(['rows' => 2, 'head' => 2, 'committed' => 1], $summary->journal?->toArray(), $what);
            self::assertSame([], $summary->findings, $what);
            self::assertFalse($summary->fails(false), $what);
        }
    }

    /**
     * A journal finding is a finding of the run and fails it, ranged or whole,
     * whatever the seals' own integrity, and is the run's first failure.
     *
     * @return void
     */
    public function testAJournalFindingFailsTheRun(): void
    {
        $this->storeSeals(2);

        $release = $this->journalRow(JournalKind::RELEASE, ['hold_id' => '01932b4e-d000-7000-8000-000000000001'], '01932b4e-d000-7000-8000-000000000001');

        foreach (['the whole log' => VerificationRange::whole(), 'a range' => new VerificationRange(1, 1)] as $what => $range) {
            $summary = $this->verifyLog($range);

            self::assertEquals([new RunFinding(Finding::JOURNAL_TRANSITION, $release->id)], $summary->findings, $what);
            self::assertSame(0, $summary->integrity['tampered'], $what);
            self::assertTrue($summary->fails(false), $what);
            self::assertSame(Finding::JOURNAL_TRANSITION, $summary->firstFinding, $what);
            self::assertSame($release->id, $summary->firstBadId, $what);
        }
    }

    /**
     * A run of the whole log verifies the key store after the journal, its
     * counts and findings the run's.
     *
     * @return void
     */
    public function testACompleteRunVerifiesTheKeyStore(): void
    {
        $owner = Reference::of('App\Models\User', '42');

        $this->storeSeals(1);
        $this->makeSubjectKey($owner);
        $this->makeSubjectKey(Reference::of('App\Models\User', '43'));
        $this->eraseByHand($owner);

        $summary = $this->verifyLog();

        self::assertSame(['keys' => 2, 'erased' => 1, 'findings' => 0, 'skipped' => false, 'encrypter' => null], $summary->keys?->toArray());
        self::assertSame([], $summary->findings);
        self::assertFalse($summary->fails(false));
    }

    /**
     * A ranged run leaves the key store: it reads no key or key use, and its
     * summary holds no key store section.
     *
     * @return void
     */
    public function testARangedRunLeavesTheKeyStore(): void
    {
        $this->storeSeals(2);
        $this->keyConnection()->table(KeyTables::keyUsesTable())->insert(['key_id' => self::OTHER_ID, 'entry_id' => self::OTHER_ID]);

        $statements = $this->recordExecutedStatements();
        $summary    = $this->verifyLog(new VerificationRange(1, 2));

        self::assertNull($summary->keys);
        self::assertSame([], $summary->findings);
        $tables   = [KeyTables::keyUsesTable(), KeyTables::subjectKeysTable()];
        $keyStore = array_filter($statements->getArrayCopy(), static fn (string $sql): bool => str_contains($sql, $tables[0]) || str_contains($sql, $tables[1]));

        self::assertSame([], array_values($keyStore));
    }

    /**
     * A key finding is a finding of the run and fails it, whatever the seals'
     * own integrity, and is the run's first failure, at the key.
     *
     * @return void
     */
    public function testAKeyFindingFailsTheRun(): void
    {
        $this->storeSeals(1);

        [$key] = $this->makeSubjectKey(Reference::of('App\Models\User', '42'));

        $this->keyConnection()->table(KeyTables::subjectKeysTable())->where('id', $key->id)->update(['generation' => 9]);

        $summary = $this->verifyLog();

        self::assertEquals([new RunFinding(Finding::KEY_SUBSTITUTED, $key->id)], $summary->findings);
        self::assertSame(1, $summary->integrity['valid']);
        self::assertTrue($summary->fails(false));
        self::assertSame(Finding::KEY_SUBSTITUTED, $summary->firstFinding);
        self::assertSame($key->id, $summary->firstBadId);
        self::assertSame(1, $summary->keys?->findings);
        self::assertFalse(app(IntegrityProgress::class)->get(IntegrityProgress::VERIFY_LAST_FULL)['passed'] ?? true);
    }

    /**
     * With a custom field encrypter bound, the key store section is skipped,
     * naming the encrypter, and a key use with no key is not found.
     *
     * @return void
     */
    public function testACustomEncrypterSkipsTheKeyStore(): void
    {
        $this->storeSeals(1);
        $this->keyConnection()->table(KeyTables::keyUsesTable())->insert(['key_id' => self::OTHER_ID, 'entry_id' => self::OTHER_ID]);

        $summary = $this->verifier(encrypter: new RecordingFieldEncrypter)->verify(VerificationRange::whole(), static function (): void {});

        self::assertSame(['keys' => 0, 'erased' => 0, 'findings' => 0, 'skipped' => true, 'encrypter' => RecordingFieldEncrypter::class], $summary->keys?->toArray());
        self::assertSame([], $summary->findings);
        self::assertFalse($summary->fails(false));
    }

    /**
     * Every statement of a run reads the writer, so a replica's lag never reads
     * as a missing row.
     *
     * @return void
     */
    public function testEveryQueryReadsTheWriter(): void
    {
        $this->storeSeals(2);
        $this->storeEntryAt('2026-11-02 03:00:00');

        $anchor = new DiskAnchor(Storage::fake(self::DISK), self::DISK, 'audit-log-anchors', app(SealSettings::class)->logId());

        $this->anchorAll($anchor);

        DB::connection(StorageConnection::name())->setReadPdo(static function (): never {
            throw new \LogicException('Verification read the replica.');
        });

        $summary = $this->verifyLog(new VerificationRange, $anchor);

        self::assertSame(2, $summary->anchoring['anchored']);
        self::assertSame(1, $summary->pending);
        self::assertFalse($summary->fails(true));
        self::assertNotNull(app(IntegrityProgress::class)->get(IntegrityProgress::VERIFY_LAST_FULL));
    }

    /**
     * A bundle's artifact digest changed after sealing fails the run as a
     * tampered mismatch at its entry; an intact bundle's seal stays valid.
     *
     * @return void
     */
    public function testARunWithATamperedArtifactFails(): void
    {
        $this->seedBundle();
        $this->sealAll();

        $entryId = $this->seedBundle(2);

        $this->sealAll();
        $this->tamperWithArtifact($entryId, ['digest' => self::OTHER_DIGEST]);

        $summary = $this->verifyLog();

        self::assertSame(1, $summary->integrity['valid']);
        self::assertSame(1, $summary->integrity['tampered']);
        self::assertSame(Finding::MANIFEST_MISMATCH, $this->streamed[1]->finding);
        self::assertSame($entryId, $this->streamed[1]->firstBadId);
        self::assertSame(Finding::MANIFEST_MISMATCH, $summary->firstFinding);
        self::assertTrue($summary->fails(false));
    }

    /**
     * A bundle's members replaced after sealing by another canonical list fail
     * the run as `manifest_tampered`, at the bundle's entry.
     *
     * @return void
     */
    public function testARunWithTamperedMembersFails(): void
    {
        $entryId = $this->seedBundle(2);
        $members = Manifest::encode([[RecordFactory::MEMBER_TYPE, '1'], [RecordFactory::MEMBER_TYPE, '3']]);

        $this->sealAll();
        $this->tamperWithArtifact($entryId, ['members' => RecordFactory::encrypter()->encryptString($members)]);

        $summary = $this->verifyLog();

        self::assertSame(1, $summary->integrity['tampered']);
        self::assertSame(Finding::MANIFEST_TAMPERED, $this->streamed[0]->finding);
        self::assertSame($entryId, $this->streamed[0]->firstBadId);
        self::assertSame(Finding::MANIFEST_TAMPERED, $summary->firstFinding);
        self::assertTrue($summary->fails(false));
    }

    /**
     * Run a verification of the range, the whole log by default, under the
     * anchor and on the clock given, keeping every report it streams.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\VerificationRange  $range
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @return \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary
     *
     * @throws \InvalidArgumentException
     */
    private function verifyLog(?VerificationRange $range = null, ?CheckpointAnchor $anchor = null, ?Clock $clock = null): VerificationSummary
    {
        $this->streamed = [];

        return $this->verifier($anchor, $clock)->verify($range ?? VerificationRange::whole(), function (SegmentReport $report): void {
            $this->streamed[] = $report;
        });
    }

    /**
     * A verifier from the container's collaborators with nothing pruned, by
     * default with no anchor or encrypter and a clock stopped at the run.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @param  ?\SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $encrypter
     * @return \SineMacula\Laravel\AuditLog\Integrity\Verifier
     */
    private function verifier(?CheckpointAnchor $anchor = null, ?Clock $clock = null, ?FieldEncrypter $encrypter = null): Verifier
    {
        $this->keyWrapper();

        $anchor ??= new NullAnchor;
        $database = app(DatabaseManager::class);
        $settings = app(SealSettings::class);
        $manifest = app(ManifestVerifier::class);
        $segments = new SegmentVerifier(app(SealSigner::class), app(RecordSigner::class), app(RowCodec::class), $settings, new NullPruneLedger, $anchor, $database, $manifest);

        $keys = app(KeyStoreVerifier::class);
        $clock ??= FrozenClock::at(self::VERIFIED_AT);

        $encrypter ??= new NoFieldEncrypter;

        return new Verifier($segments, $anchor, $settings, app(IntegrityProgress::class), $clock, $database, app(JournalVerifier::class), $keys, $encrypter);
    }

    /**
     * Store and seal the number of seals, two entries each, recorded a minute
     * apart.
     *
     * @param  int  $count
     * @return void
     */
    private function storeSeals(int $count): void
    {
        $first = new CarbonImmutable(self::ENTRIES_RECORDED_AT, 'UTC');

        for ($seal = 0; $seal < $count; $seal++) {
            $this->storeEntries(2, $first->addMinutes($seal)->format('Y-m-d H:i:s.u'));
            $this->sealAll();
        }
    }

    /**
     * Store and seal the number of seals, one entry each, through the writer
     * alone, which is quicker than a sweep per seal.
     *
     * @param  int  $count
     * @return void
     */
    private function storeSealsQuickly(int $count): void
    {
        $writer = new CheckpointWriter(app(DatabaseManager::class), app(SealSigner::class), app(SealSettings::class), FrozenClock::at(self::SEALED_AT));

        $this->storeEntries($count);

        for ($seal = 0; $seal < $count; $seal++) {
            $writer->write(null, '2026-11-01T13:00:00.000000Z', 1);
        }
    }

    /**
     * Record every statement that reads a page of seals, as it runs.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordPages(): \ArrayObject
    {
        $pages = new \ArrayObject;

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use ($pages): void {
            if (!str_contains($query->sql, IntegrityTables::checkpointsTable()) || !str_contains(strtolower($query->sql), 'limit')) {
                return;
            }

            $pages->append($query->sql);
        });

        return $pages;
    }

    /**
     * Anchor the stored seals up to the sequence given, or every one, and keep
     * each receipt beside its seal, as anchoring does.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @param  int  $upTo
     * @return void
     */
    private function anchorAll(CheckpointAnchor $anchor, int $upTo = PHP_INT_MAX): void
    {
        foreach ($this->seals() as $seal) {
            if ((int) $seal['sequence'] > $upTo) {
                continue;
            }

            $receipt = $anchor->anchor(SealSummary::of(SealEnvelope::fromRow($seal), (string) $seal['seal_digest']));

            $this->checkpoints()->where('id', $seal['id'])->update([
                'anchor'         => $anchor->name(),
                'anchor_receipt' => json_encode($receipt, JSON_THROW_ON_ERROR),
                'anchored_at'    => '2026-11-01 13:05:00.000000',
            ]);
        }
    }

    /**
     * Delete the stored seal at the sequence, with its members and their
     * entries.
     *
     * @param  int  $sequence
     * @return void
     */
    private function deleteSeal(int $sequence): void
    {
        $stored  = $this->checkpoints()->where('sequence', $sequence)->value('id');
        $id      = is_string($stored) ? $stored : '';
        $members = $this->membersOf($id);

        DB::connection(StorageConnection::name())->table(EntrySettings::table())->whereIn('id', $members)->delete();
        DB::connection(StorageConnection::name())->table(IntegrityTables::membersTable())->where('checkpoint_id', $id)->delete();
        $this->checkpoints()->where('id', $id)->delete();
    }

    /**
     * Rewrite the stored seal at the sequence with the changes, and store the
     * digest and signature of the result, as someone holding the key would.
     *
     * @param  int  $sequence
     * @param  array<string, scalar|null>  $changes
     * @return void
     */
    private function resign(int $sequence, array $changes): void
    {
        $this->checkpoints()->where('sequence', $sequence)->update($changes);

        $envelope = SealEnvelope::fromRow((array) $this->checkpoints()->where('sequence', $sequence)->first());

        $this->checkpoints()->where('sequence', $sequence)->update(['seal_digest' => $envelope->digest(), 'signature' => app(SealSigner::class)->sign($envelope)]);
    }

    /**
     * Insert a member row for the entry under the seal id given, which no
     * stored seal has.
     *
     * @param  string  $entryId
     * @param  string  $sealId
     * @return void
     */
    private function orphanMember(string $entryId, string $sealId = self::OTHER_ID): void
    {
        $member = ['checkpoint_id' => $sealId, 'entry_id' => $entryId, 'hmac' => self::OTHER_DIGEST];

        DB::connection(StorageConnection::name())->table(IntegrityTables::membersTable())->insert($member);
    }

    /**
     * The progress the last complete run recorded.
     *
     * @return ?array<string, scalar|null>
     */
    private function lastFull(): ?array
    {
        return app(IntegrityProgress::class)->get(IntegrityProgress::VERIFY_LAST_FULL);
    }

    /**
     * The sequences of the reports the last run streamed, in order.
     *
     * @return list<int>
     */
    private function sequences(): array
    {
        return array_map(static fn (SegmentReport $report): int => $report->sequence, $this->streamed);
    }

    /**
     * A query of the seals table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function checkpoints(): Builder
    {
        return DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable());
    }

    /**
     * The findings of the run as a whole, in the order found.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary  $summary
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding>
     */
    private static function findingsOf(VerificationSummary $summary): array
    {
        return array_map(static fn (RunFinding $finding): Finding => $finding->finding, $summary->findings);
    }
}
