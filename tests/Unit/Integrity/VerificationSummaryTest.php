<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\JournalSummary;
use SineMacula\Laravel\AuditLog\Integrity\KeyStoreSummary;
use SineMacula\Laravel\AuditLog\Integrity\RunFinding;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\VerificationSummary;
use SineMacula\Laravel\AuditLog\Integrity\VerificationTally;

/**
 * Unit tests for what one verification run established: when it fails, with and
 * without `strict`, with and without an anchor configured, the anchoring grace
 * and the empty remote it excuses, its summary line with the journal's and the
 * key store's parts, their findings failing it, and the event it gives
 * listeners.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationSummary::class)]
final class VerificationSummaryTest extends TestCase
{
    /** @var string A seal's id. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000001';

    /** @var string An entry's id. */
    private const string ENTRY_ID = '01932b4e-8a40-7000-8000-000000000001';

    /**
     * Raise every PHP warning as an exception, so each summary is also built
     * and read quietly: inside a Laravel application a warning becomes an
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
     * A run whose every segment is valid and anchored, under an anchor whose
     * head matches, passes with and without `strict`.
     *
     * @return void
     */
    public function testAValidRunPasses(): void
    {
        $summary = self::summary([self::report(IntegrityStatus::VALID, AnchorStatus::ANCHORED)], AnchorStatus::ANCHORED);

        self::assertFalse($summary->fails(false));
        self::assertFalse($summary->fails(true));
        self::assertTrue($summary->anchorConfigured);
        self::assertTrue($summary->discovers);
    }

    /**
     * A pruned segment passes: its missing entries are accounted for.
     *
     * @return void
     */
    public function testAPrunedSegmentPasses(): void
    {
        $summary = self::summary([self::report(IntegrityStatus::PRUNED, AnchorStatus::ANCHORED)], AnchorStatus::ANCHORED);

        self::assertFalse($summary->fails(true));
    }

    /**
     * Rows of `[status, finding]`: the integrity statuses that fail, each with
     * a finding of a run that gives it.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus, 1: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding}>
     */
    public static function provideFailingStatuses(): iterable
    {
        yield from [
            'incomplete'   => [IntegrityStatus::INCOMPLETE, Finding::OVERDUE_UNSEALED],
            'unverifiable' => [IntegrityStatus::UNVERIFIABLE, Finding::SEAL_KEY],
            'tampered'     => [IntegrityStatus::TAMPERED, Finding::ORPHAN_MEMBER],
        ];
    }

    /**
     * A segment or a run finding of a failing status fails the run, with or
     * without `strict` and whatever the anchor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus  $status
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @return void
     */
    #[DataProvider('provideFailingStatuses')]
    public function testEachFailingStatusFails(IntegrityStatus $status, Finding $finding): void
    {
        $segment = self::summary([self::report(IntegrityStatus::VALID, AnchorStatus::UNANCHORED), self::report($status, AnchorStatus::UNANCHORED)], null);
        $run     = self::summary([self::report(IntegrityStatus::VALID, AnchorStatus::ANCHORED)], AnchorStatus::ANCHORED, [new RunFinding($finding)]);

        self::assertTrue($segment->fails(false));
        self::assertTrue($segment->fails(true));
        self::assertTrue($run->fails(false));
        self::assertTrue($run->fails(true));
    }

    /**
     * With no anchor configured, an unanchored segment is informational:
     * neither a plain nor a strict run fails on it.
     *
     * @return void
     */
    public function testUnanchoredIsInformationalWithoutAnAnchor(): void
    {
        $summary = self::summary([self::report(IntegrityStatus::VALID, AnchorStatus::UNANCHORED)], null, discovers: false);

        self::assertFalse($summary->anchorConfigured);
        self::assertFalse($summary->fails(false));
        self::assertFalse($summary->fails(true));
    }

    /**
     * Rows of `[anchoring]`: the anchoring statuses short of `anchored`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus}>
     */
    public static function provideStatusesShortOfAnchored(): iterable
    {
        yield from [
            'unanchored'   => [AnchorStatus::UNANCHORED],
            'unavailable'  => [AnchorStatus::UNAVAILABLE],
            'contradicted' => [AnchorStatus::CONTRADICTED],
        ];
    }

    /**
     * With an anchor configured, a strict run fails on any one segment short of
     * `anchored`, and a plain run does not.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus  $anchoring
     * @return void
     */
    #[DataProvider('provideStatusesShortOfAnchored')]
    public function testStrictFailsOnAnySegmentShortOfAnchored(AnchorStatus $anchoring): void
    {
        $summary = self::summary([self::report(IntegrityStatus::VALID, AnchorStatus::ANCHORED), self::report(IntegrityStatus::VALID, $anchoring)], AnchorStatus::ANCHORED);

        self::assertFalse($summary->fails(false));
        self::assertTrue($summary->fails(true));
    }

    /**
     * A strict run excuses an unanchored segment that awaits its first
     * anchoring, but never one that is unavailable or contradicted, even if it
     * was sealed as recently, and never one unanchored past the grace.
     *
     * @return void
     */
    public function testStrictExcusesOnlyASealWithinTheGrace(): void
    {
        $anchored    = self::report(IntegrityStatus::VALID, AnchorStatus::ANCHORED);
        $within      = self::report(IntegrityStatus::VALID, AnchorStatus::UNANCHORED, true);
        $awaiting    = self::summary([$anchored, $within], AnchorStatus::ANCHORED);
        $unavailable = self::summary([self::report(IntegrityStatus::VALID, AnchorStatus::UNAVAILABLE, true)], AnchorStatus::ANCHORED);
        $past        = self::summary([$within, self::report(IntegrityStatus::VALID, AnchorStatus::UNANCHORED)], AnchorStatus::ANCHORED);

        self::assertSame(1, $awaiting->awaiting);
        self::assertFalse($awaiting->fails(true));
        self::assertTrue($unavailable->fails(true));
        self::assertTrue($past->fails(true));
    }

    /**
     * A strict run fails on an anchor that was unavailable or contradicted when
     * its head was asked for, and on an anchor that holds no seal while the
     * local log has one past the grace.
     *
     * @return void
     */
    public function testStrictFailsOnAnUnavailableOrEmptyRemote(): void
    {
        $segments = [self::report(IntegrityStatus::VALID, AnchorStatus::ANCHORED)];

        self::assertTrue(self::summary($segments, AnchorStatus::UNAVAILABLE, remoteHead: null)->fails(true));
        self::assertTrue(self::summary($segments, AnchorStatus::CONTRADICTED)->fails(true));
        self::assertTrue(self::summary([self::report(IntegrityStatus::VALID, AnchorStatus::UNANCHORED)], AnchorStatus::UNANCHORED, remoteHead: null)->fails(true));
        self::assertFalse(self::summary($segments, AnchorStatus::UNAVAILABLE, remoteHead: null)->fails(false));
    }

    /**
     * An anchor that holds no seal is excused while every seal from the first
     * awaits its first anchoring, and not once one does not, nor for a ranged
     * run that starts after the first seal, nor for an anchor's head that is
     * merely unanchored.
     *
     * @return void
     */
    public function testAnEmptyRemoteIsExcusedOnlyWhileEverySegmentAwaits(): void
    {
        $awaiting = [self::report(IntegrityStatus::VALID, AnchorStatus::UNANCHORED, true), self::report(IntegrityStatus::VALID, AnchorStatus::UNANCHORED, true)];

        self::assertFalse(self::summary($awaiting, AnchorStatus::UNANCHORED, remoteHead: null)->fails(true));
        self::assertTrue(self::summary([...$awaiting, self::report(IntegrityStatus::VALID, AnchorStatus::ANCHORED)], AnchorStatus::UNANCHORED, remoteHead: null)->fails(true));
        self::assertTrue(self::summary($awaiting, AnchorStatus::UNANCHORED, remoteHead: null, from: 2)->fails(true));
        self::assertTrue(self::summary($awaiting, AnchorStatus::UNANCHORED, remoteHead: 2)->fails(true));
    }

    /**
     * An anchor that holds no seal is never excused when the run checked no
     * segment, which a log with seals and a range left nothing to check would
     * be.
     *
     * @return void
     */
    public function testAnEmptyRemoteIsNotExcusedWithNoSegment(): void
    {
        self::assertTrue(self::summary([], AnchorStatus::UNANCHORED, remoteHead: null)->fails(true));
    }

    /**
     * A strict run fails on an anchor that cannot report its head, since a
     * truncated tail could not then be found.
     *
     * @return void
     */
    public function testStrictFailsWithoutDiscovery(): void
    {
        $summary = self::summary([self::report(IntegrityStatus::VALID, AnchorStatus::ANCHORED)], AnchorStatus::ANCHORED, discovers: false);

        self::assertFalse($summary->fails(false));
        self::assertTrue($summary->fails(true));
    }

    /**
     * With the null anchor, `strict` changes nothing: every segment unanchored,
     * no head and no discovery still pass.
     *
     * @return void
     */
    public function testStrictChangesNothingWithTheNullAnchor(): void
    {
        $reports = [self::report(IntegrityStatus::VALID, AnchorStatus::UNANCHORED), self::report(IntegrityStatus::PRUNED, AnchorStatus::UNANCHORED)];
        $summary = self::summary($reports, null, remoteHead: null, discovers: false);

        self::assertSame($summary->fails(false), $summary->fails(true));
        self::assertFalse($summary->fails(true));
        self::assertNull($summary->remote);
    }

    /**
     * The summary line names the range, both heads, how the anchor compared,
     * whether the run was complete and strict, every count, what was read of
     * the journal and the key store, the first failure and whether it passed,
     * in that order of keys.
     *
     * @return void
     */
    public function testTheSummaryLineIsPinned(): void
    {
        $tally = new VerificationTally;

        $tally->add(self::report(IntegrityStatus::VALID, AnchorStatus::UNANCHORED, true));
        $tally->add(self::report(IntegrityStatus::TAMPERED, AnchorStatus::ANCHORED, false, Finding::ENTRY_HMAC, self::ENTRY_ID));
        $tally->unsealed(3, 1);

        $summary = VerificationSummary::of([2, 4], 5, 4, AnchorStatus::ANCHORED, false, true, $tally)
            ->withJournal(new JournalSummary(3, 3, 2))
            ->withKeys(new KeyStoreSummary(4, 1, 0));

        self::assertSame([
            'type'            => 'summary',
            'from'            => 2,
            'to'              => 4,
            'head'            => 5,
            'remote_head'     => 4,
            'remote'          => 'anchored',
            'complete'        => false,
            'strict'          => true,
            'integrity'       => ['valid' => 1, 'pruned' => 0, 'incomplete' => 0, 'unverifiable' => 0, 'tampered' => 1],
            'anchoring'       => ['anchored' => 1, 'unanchored' => 1, 'unavailable' => 0, 'contradicted' => 0],
            'awaiting_anchor' => 1,
            'pending'         => 3,
            'overdue'         => 1,
            'journal'         => ['rows' => 3, 'head' => 3, 'committed' => 2],
            'keys'            => ['keys' => 4, 'erased' => 1, 'findings' => 0, 'skipped' => false, 'encrypter' => null],
            'first_finding'   => 'entry_hmac',
            'first_bad_id'    => self::ENTRY_ID,
            'passed'          => false,
        ], $summary->toArray(true));
    }

    /**
     * A summary built with no journal summary names none, and one given the
     * journal's keeps it with everything else as it was.
     *
     * @return void
     */
    public function testTheJournalIsKeptWhenGiven(): void
    {
        $tally = new VerificationTally;

        $tally->add(self::report(IntegrityStatus::VALID, AnchorStatus::UNANCHORED, true));
        $tally->unsealed(2, 0);

        $journal = new JournalSummary(0, null, null);
        $none    = VerificationSummary::of([3, 3], 4, 3, AnchorStatus::ANCHORED, false, true, $tally);
        $kept    = $none->withJournal($journal);

        self::assertNull($none->journal);
        self::assertNull($none->toArray(false)['journal']);
        self::assertSame($journal, $kept->journal);
        self::assertSame(['rows' => 0, 'head' => null, 'committed' => null], $kept->toArray(false)['journal']);
        self::assertSame([...$none->toArray(true), 'journal' => $journal->toArray()], $kept->toArray(true));
        self::assertSame($none->anchorConfigured, $kept->anchorConfigured);
        self::assertSame($none->discovers, $kept->discovers);
        self::assertSame($none->firstFinding, $kept->firstFinding);
        self::assertSame($none->fails(true), $kept->fails(true));
    }

    /**
     * The key store's section is in each form: none until it is given, as for a
     * ranged run; kept once given, through the journal's and with everything
     * else as it was; in the line as its own array; and a key finding the tally
     * holds is the event's first finding and fails the run, though no segment
     * failed.
     *
     * @return void
     */
    public function testTheKeysSectionIsInEachForm(): void
    {
        $tally = new VerificationTally;

        $tally->add(self::report(IntegrityStatus::VALID, AnchorStatus::UNANCHORED));
        $tally->addFinding(new RunFinding(Finding::KEY_RESTORED, self::ENTRY_ID, 2));

        $keys    = new KeyStoreSummary(3, 1, 2);
        $none    = VerificationSummary::of([1, 1], 1, null, null, true, false, $tally);
        $kept    = $none->withKeys($keys)->withJournal(new JournalSummary(1, 1, 1));
        $skipped = $none->withKeys(KeyStoreSummary::skipped()->naming('App\Privacy\VaultEncrypter'));

        self::assertNull($none->keys);
        self::assertNull($none->toArray(false)['keys']);
        self::assertSame($keys, $kept->keys);
        self::assertSame(['keys' => 3, 'erased' => 1, 'findings' => 2, 'skipped' => false, 'encrypter' => null], $kept->toArray(false)['keys']);
        self::assertSame([...$none->toArray(false), 'journal' => ['rows' => 1, 'head' => 1, 'committed' => 1], 'keys' => $keys->toArray()], $kept->toArray(false));
        self::assertSame(['keys' => 0, 'erased' => 0, 'findings' => 0, 'skipped' => true, 'encrypter' => 'App\Privacy\VaultEncrypter'], $skipped->toArray(false)['keys']);
        self::assertNull($kept->withKeys(null)->keys);
        self::assertTrue($kept->fails(false));
        self::assertSame(Finding::KEY_RESTORED, $kept->firstFinding);
        self::assertSame('key_restored', $kept->toEvent('verify')->finding);
        self::assertSame(self::ENTRY_ID, $kept->toEvent('verify')->firstBadId);
    }

    /**
     * A journal finding is a finding of the run, so it fails the run under
     * either strictness, and is the event's first finding.
     *
     * @return void
     */
    public function testAJournalFindingFailsTheRun(): void
    {
        $tally = new VerificationTally;

        $tally->addFinding(new RunFinding(Finding::JOURNAL_GAP, self::ENTRY_ID));

        $summary = VerificationSummary::of([1, 0], null, null, null, true, false, $tally)->withJournal(new JournalSummary(2, 1, null));

        self::assertTrue($summary->fails(false));
        self::assertFalse($summary->toArray(false)['passed']);
        self::assertSame('journal_gap', $summary->toEvent('verify')->finding);
    }

    /**
     * The line says whether the run passed under the strictness it ran with,
     * and names no anchor's status with none configured.
     *
     * @return void
     */
    public function testTheLinePassesUnderItsStrictness(): void
    {
        $anchored = self::summary([self::report(IntegrityStatus::VALID, AnchorStatus::UNANCHORED)], AnchorStatus::ANCHORED);
        $none     = self::summary([], null, remoteHead: null, discovers: false);

        self::assertTrue($anchored->toArray(false)['passed']);
        self::assertFalse($anchored->toArray(true)['passed']);
        self::assertFalse($anchored->toArray(false)['strict']);
        self::assertNull($none->toArray(true)['remote']);
        self::assertNull($none->toArray(true)['remote_head']);
        self::assertTrue($none->toArray(true)['passed']);
    }

    /**
     * The event names the command and carries every count, the first finding
     * and its id, both heads and whether the run was complete.
     *
     * @return void
     */
    public function testTheEventCarriesTheCountsAndTheFirstFinding(): void
    {
        $tally = new VerificationTally;

        $tally->add(self::report(IntegrityStatus::VALID, AnchorStatus::ANCHORED));
        $tally->addFinding(new RunFinding(Finding::ORPHAN_MEMBER, self::ENTRY_ID, 2));

        $event = VerificationSummary::of([1, 3], 3, 3, AnchorStatus::ANCHORED, true, true, $tally)->toEvent('verify');

        self::assertInstanceOf(IntegrityCheckFailed::class, $event);
        self::assertSame('verify', $event->command);
        self::assertSame(['valid' => 1, 'pruned' => 0, 'incomplete' => 0, 'unverifiable' => 0, 'tampered' => 0], $event->integrity);
        self::assertSame(['anchored' => 1, 'unanchored' => 0, 'unavailable' => 0, 'contradicted' => 0], $event->anchoring);
        self::assertSame('orphan_member', $event->finding);
        self::assertSame(self::ENTRY_ID, $event->firstBadId);
        self::assertSame(3, $event->head);
        self::assertSame(3, $event->remoteHead);
        self::assertTrue($event->complete);
    }

    /**
     * The event of a run with no failure, which fails only under `strict`, has
     * no finding to name.
     *
     * @return void
     */
    public function testTheEventOfAStrictFailureHasNoFinding(): void
    {
        $event = self::summary([self::report(IntegrityStatus::VALID, AnchorStatus::UNANCHORED)], AnchorStatus::ANCHORED, remoteHead: null, complete: false)->toEvent('verify');

        self::assertNull($event->finding);
        self::assertNull($event->firstBadId);
        self::assertNull($event->remoteHead);
        self::assertFalse($event->complete);
        self::assertSame(1, $event->anchoring['unanchored']);
    }

    /**
     * The summary keeps the range, the heads, the run's findings and the
     * tally's counts as given.
     *
     * @return void
     */
    public function testKeepsTheRunsCounts(): void
    {
        $tally   = new VerificationTally;
        $finding = new RunFinding(Finding::OVERDUE_UNSEALED, self::ENTRY_ID, 2);

        $tally->addFinding($finding);
        $tally->unsealed(4, 2);

        $summary = VerificationSummary::of([1, 0], null, null, null, true, false, $tally);

        self::assertSame(1, $summary->from);
        self::assertSame(0, $summary->to);
        self::assertNull($summary->head);
        self::assertSame([$finding], $summary->findings);
        self::assertSame(4, $summary->pending);
        self::assertSame(2, $summary->overdue);
        self::assertSame(Finding::OVERDUE_UNSEALED, $summary->firstFinding);
        self::assertTrue($summary->complete);
        self::assertTrue($summary->fails(false));
    }

    /**
     * The summary of the reports and run findings given, from the first seal
     * given, under an anchor whose head compared as given, or no anchor when it
     * is `null`.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Integrity\SegmentReport>  $reports
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus  $remote
     * @param  list<\SineMacula\Laravel\AuditLog\Integrity\RunFinding>  $findings
     * @param  ?int  $remoteHead
     * @param  bool  $discovers
     * @param  int  $from
     * @param  bool  $complete
     * @return \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary
     */
    private static function summary(
        array $reports,
        ?AnchorStatus $remote,
        array $findings = [],
        ?int $remoteHead = 1,
        bool $discovers = true,
        int $from = 1,
        bool $complete = true,
    ): VerificationSummary {
        $tally = new VerificationTally;

        foreach ($reports as $report) {
            $tally->add($report);
        }

        foreach ($findings as $finding) {
            $tally->addFinding($finding);
        }

        return VerificationSummary::of([$from, $from + count($reports) - 1], $from + count($reports) - 1, $remoteHead, $remote, $complete, $discovers, $tally);
    }

    /**
     * A report in the statuses given, awaiting its first anchoring when said
     * to, with the finding and id given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus  $integrity
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus  $anchoring
     * @param  bool  $awaiting
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @param  ?string  $firstBadId
     * @return \SineMacula\Laravel\AuditLog\Integrity\SegmentReport
     */
    private static function report(IntegrityStatus $integrity, AnchorStatus $anchoring, bool $awaiting = false, ?Finding $finding = null, ?string $firstBadId = null): SegmentReport
    {
        $finding ??= $integrity->isFailure() ? Finding::SEAL_DIGEST : null;

        return new SegmentReport(1, self::SEAL_ID, $integrity, $anchoring, 1, $finding, $firstBadId, null, $awaiting);
    }
}
