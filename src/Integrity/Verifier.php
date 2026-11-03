<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\JoinClause;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Verifies the log, or a range of its seals, and streams one report per segment
 * as it goes, holding counts and never the reports.
 *
 * The run's clock is read once, so the anchoring grace is measured back from
 * when the run began, and never past it. The anchor's head is asked for first,
 * independently of every receipt kept beside the seals, and the local head
 * after it, so a remote head the local log does not reach can never be a seal
 * committed meanwhile; seals written after the local head was read are never
 * read. The local head is the greatest sequence from 1, so a row at a sequence
 * below 1 is never taken for it. A range is validated against that head before
 * anything is verified. A ranged run checks its first seal's link to the seal
 * before it, and a missing one is a gap.
 *
 * The walk reads the seals in pages by sequence and expects the range's first
 * sequence first, then each next one, through the range's last, so a deleted
 * first seal, a seal missing between two and seals missing at the end of the
 * range are each a gap, and the coverage reported is never more than was read.
 * When discovery gave the anchor's head, the walk reaches it and the local seal
 * there has its digest, that head settles every seal's anchoring with no
 * further call: the head's digest commits to the chain before it, which the
 * walk checks link by link, so a seal up to it is anchored in any run that
 * passes, and a seal after it is not held. Otherwise, a head the local log
 * contradicts among them, each seal's receipt is put to the anchor. An anchor
 * that fails, in discovery or when asked to confirm a receipt, is not asked
 * again in the run. The anchor's head is compared with the local seal at its
 * sequence on every run: a head beyond the local tail, or with no local log, is
 * a missing tail; another digest at its sequence, no local seal there, or a
 * seal there that cannot be read whose stored digest is another is a
 * contradiction.
 *
 * Only a run of the whole log checks for seals outside the chain (a sequence
 * below 1), for member rows of no seal in the chain, and for unsealed entries:
 * those older than the allowed age are overdue, and those recorded further
 * ahead of the run's clock than the lookback are never sealed and are a
 * finding, never pending. It records its completion, with whether it passed at
 * the strictness it ran at. Every statement reads the writer, so a replica's
 * lag never reads as a missing row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Verifier
{
    /** @var int Seals read by one statement of the walk. */
    public const int SEAL_PAGE = 100;

    /** @var int How long after it is sealed a seal may wait for its first anchoring before a strict run fails on it, in seconds: one sealing lock period. */
    public const int ANCHOR_GRACE_SECONDS = 900;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier  $segments
     * @param  \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Database\IntegrityProgress  $progress
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** The verifier of each segment. */
        private SegmentVerifier $segments,

        /** The anchor whose head is compared with the local log. */
        private CheckpointAnchor $anchor,

        /** The settings the allowed age of an unsealed entry is read from. */
        private SealSettings $settings,

        /** The progress a run of the whole log records its completion in. */
        private IntegrityProgress $progress,

        /** The clock the run reads once, when it begins. */
        private Clock $clock,

        /** The connections the storage connection is resolved from on every run. */
        private DatabaseManager $database,
    ) {}

    /**
     * Verify the range, giving each segment's report to the callback as it is
     * made, and summarise the run; a run of the whole log records whether it
     * passed at the strictness given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationRange  $range
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Integrity\SegmentReport): void  $each
     * @param  bool  $strict
     * @return \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \JsonException
     */
    public function verify(VerificationRange $range, \Closure $each, bool $strict = false): VerificationSummary
    {
        $now                         = $this->clock->now();
        $tally                       = new VerificationTally;
        [$remote, $settled, $asking] = $this->discover($tally);
        $head                        = $this->head();
        $bounds                      = $range->bounds($head);
        $byHead                      = $settled === null && $this->discovers() && $this->isSettledByHead($remote, $bounds);
        $grace                       = [StoredTime::format($now->subSeconds(self::ANCHOR_GRACE_SECONDS)), StoredTime::format($now)];
        $context                     = new VerificationContext($remote, $asking, $grace[0], $grace[1], $byHead);
        $atRemote                    = $this->walk($bounds, $context, $each, $tally);
        $status                      = $settled ?? $this->reconcile($remote, $head, $bounds, $atRemote, $tally);

        if ($range->isComplete()) {
            $this->checkOutsideTheChain($tally);
            $this->checkOrphans($tally);
            $this->checkUnsealed($now, $tally);
        }

        $summary = VerificationSummary::of($bounds, $head, $remote?->sequence, $status, $range->isComplete(), $this->discovers(), $tally);

        if ($range->isComplete()) {
            $last = ['at' => StoredTime::format($now), 'head' => $head, 'passed' => !$summary->fails($strict), 'strict' => $strict];

            $this->progress->put(IntegrityProgress::VERIFY_LAST_FULL, $last, $now);
        }

        return $summary;
    }

    /**
     * Ask the anchor for its head: the head, the anchor's status when asking
     * settles it, and whether the anchor may still be asked to confirm. With no
     * anchor, or one that cannot discover, it is not asked; a conflict is a
     * finding of the run, and any other failure makes the anchor unavailable
     * for the rest of the run.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @return array{0: ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead, 1: ?\SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus, 2: bool}
     */
    private function discover(VerificationTally $tally): array
    {
        if (!$this->discovers()) {
            $configured = !$this->anchor instanceof NullAnchor;

            return [null, $configured ? AnchorStatus::UNANCHORED : null, $configured];
        }

        try {
            $discovered = [$this->anchor->latest(), null, true];
        } catch (AnchorConflictException) {
            $tally->addFinding(new RunFinding(Finding::ANCHOR_CONFLICT));

            $discovered = [null, AnchorStatus::CONTRADICTED, true];
        } catch (\Throwable) {
            $discovered = [null, AnchorStatus::UNAVAILABLE, false];
        }

        return $discovered;
    }

    /**
     * Whether the anchor's head settles every seal's anchoring with no call per
     * seal, once discovery answered: the anchor holds none, or the walk reaches
     * its head and the local seal there has the head's digest, so the chain the
     * walk checks commits every seal up to it. A head the local log contradicts
     * settles nothing, and each seal's receipt is put to the anchor.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead  $remote
     * @param  array{0: int, 1: int}  $bounds
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function isSettledByHead(?AnchoredHead $remote, array $bounds): bool
    {
        if ($remote === null) {
            return true;
        }

        return $bounds[1] >= $remote->sequence && $this->boundaryAt($remote->sequence)?->digest === $remote->digest;
    }

    /**
     * Whether an anchor is configured that can report its head.
     *
     * @return bool
     */
    private function discovers(): bool
    {
        return !$this->anchor instanceof NullAnchor && $this->anchor->supportsDiscovery();
    }

    /**
     * The sequence of the local head, the greatest from 1, or `null` when the
     * log has no seal in the chain; a greatest sequence that cannot be read as
     * an integer is refused, never taken for an empty log.
     *
     * @return ?int
     *
     * @throws \UnexpectedValueException
     */
    private function head(): ?int
    {
        $greatest = $this->checkpoints()->where('sequence', '>=', 1)->max('sequence');

        if ($greatest === null) {
            return null;
        }

        return IntegerSetting::parse($greatest) ?? throw new \UnexpectedValueException('The greatest stored seal sequence is malformed.');
    }

    /**
     * Walk the seals of the range, giving each report to the callback and
     * counting it, and return the report of the seal at the anchor's head, if
     * the walk met it. A walk that ends before the range's last sequence, or
     * reads no seal at all, is a gap.
     *
     * @param  array{0: int, 1: int}  $bounds
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationContext  $context
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Integrity\SegmentReport): void  $each
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\SegmentReport
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function walk(array $bounds, VerificationContext $context, \Closure $each, VerificationTally $tally): ?SegmentReport
    {
        [$from, $to] = $bounds;

        if ($from > $to) {
            return null;
        }

        $previous = $this->boundary($from, $each, $tally);
        $expected = $from;
        $atRemote = null;

        foreach ($this->seals($from, $to) as $seal) {
            $report = $this->segments->verify($seal, $expected, $previous, $context);

            $each($report);
            $tally->add($report);

            // An anchor asked and found unavailable failed when asked, so it is
            // not asked again in this run
            $context  = $report->anchoring === AnchorStatus::UNAVAILABLE && $context->askAnchor ? $context->withoutAnchor() : $context;
            $atRemote = $report->sequence  === $context->remote?->sequence ? $report : $atRemote;
            $previous = $report;
            $expected = $report->sequence + 1;
        }

        if ($expected <= $to) {
            $tally->addFinding(new RunFinding(Finding::SEQUENCE_GAP));
        }

        return $atRemote;
    }

    /**
     * The stored seals from the first sequence to the last, as raw rows, read
     * in pages by sequence as they are needed, so a page is read only once the
     * seals before it have been verified. Each page starts after the sequence
     * the last seal of the page before holds, as it is stored.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  int  $from
     * @param  int  $to
     * @return \Generator<int, array<string, mixed>>
     *
     * @throws \InvalidArgumentException
     */
    private function seals(int $from, int $to): \Generator
    {
        $after = $from - 1;

        do {
            $page = $this->checkpoints()->where('sequence', '>', $after)->where('sequence', '<=', $to)->orderBy('sequence')->limit(self::SEAL_PAGE)->get()->all();

            foreach ($page as $stored) {
                $seal  = (array) $stored;
                $after = $seal['sequence'] ?? $after;

                yield $seal;
            }
        } while (count($page) === self::SEAL_PAGE);
    }

    /**
     * The first link of a ranged run: the report of the seal before its first,
     * given to the callback and counted only when it fails. A boundary seal
     * that does not exist is a gap, and the walk then starts with no link.
     *
     * @param  int  $from
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Integrity\SegmentReport): void  $each
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\SegmentReport
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function boundary(int $from, \Closure $each, VerificationTally $tally): ?SegmentReport
    {
        if ($from === 1) {
            return null;
        }

        $report = $this->boundaryAt($from - 1);

        if ($report === null) {
            $tally->addFinding(new RunFinding(Finding::SEQUENCE_GAP));

            return null;
        }

        if ($report->integrity->isFailure()) {
            $each($report);
            $tally->add($report);
        }

        return $report;
    }

    /**
     * How the anchor's head compares with the local log, once discovery gave a
     * head or none: an empty anchor agrees with an empty log and leaves a local
     * log unanchored, and a head is compared with the local seal at its
     * sequence.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead  $remote
     * @param  ?int  $head
     * @param  array{0: int, 1: int}  $bounds
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SegmentReport  $atRemote
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function reconcile(?AnchoredHead $remote, ?int $head, array $bounds, ?SegmentReport $atRemote, VerificationTally $tally): ?AnchorStatus
    {
        if (!$this->discovers()) {
            return null;
        }

        if ($remote === null) {
            return $head === null ? AnchorStatus::ANCHORED : AnchorStatus::UNANCHORED;
        }

        return $this->compare($remote, $head, $bounds, $atRemote, $tally);
    }

    /**
     * How the anchor's head compares with the local seal at its sequence: a
     * head beyond the local tail, or with no local log, is a missing tail; no
     * local seal at its sequence, or another digest there, is a contradiction;
     * the same digest is anchored. A local seal there that cannot be read has
     * no digest to recompute, so its stored digest is compared instead: another
     * is a contradiction, and the same leaves it unanchored. The walk's report
     * is used when the walk met that seal, and the seal is read on its own when
     * the range left it out.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\AnchoredHead  $remote
     * @param  ?int  $head
     * @param  array{0: int, 1: int}  $bounds
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SegmentReport  $atRemote
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @return \SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function compare(AnchoredHead $remote, ?int $head, array $bounds, ?SegmentReport $atRemote, VerificationTally $tally): AnchorStatus
    {
        if ($head === null || $remote->sequence > $head) {
            $tally->addFinding(new RunFinding(Finding::MISSING_TAIL));

            return AnchorStatus::CONTRADICTED;
        }

        $walked = $remote->sequence >= $bounds[0] && $remote->sequence <= $bounds[1];
        $local  = $walked ? $atRemote : $this->boundaryAt($remote->sequence);
        $status = $this->statusAgainst($remote, $local);

        // A readable seal the walk met and found contradicted carries the
        // finding already; one read on its own, one that cannot be read, or one
        // missing, is a finding of the run
        if ($status === AnchorStatus::CONTRADICTED && ($local?->digest === null || !$walked)) {
            $tally->addFinding(new RunFinding(Finding::ANCHOR_CONTRADICTION, $local?->sealId));
        }

        return $status;
    }

    /**
     * The report of the seal at the sequence, its own fields alone checked, or
     * `null` when there is no seal there.
     *
     * @param  int  $sequence
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\SegmentReport
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function boundaryAt(int $sequence): ?SegmentReport
    {
        $seal = $this->checkpoints()->where('sequence', $sequence)->first();

        return $seal === null ? null : $this->segments->boundary((array) $seal);
    }

    /**
     * How the local seal at the anchor's head compares with it: none there, or
     * another digest, is a contradiction, and the same digest is anchored. A
     * seal that cannot be read is compared by its stored digest: another is a
     * contradiction, and the same leaves it unanchored.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\AnchoredHead  $remote
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\SegmentReport  $local
     * @return \SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus
     *
     * @throws \InvalidArgumentException
     */
    private function statusAgainst(AnchoredHead $remote, ?SegmentReport $local): AnchorStatus
    {
        if ($local?->digest === null) {
            return $local !== null && $this->storedDigestAt($remote->sequence) === $remote->digest ? AnchorStatus::UNANCHORED : AnchorStatus::CONTRADICTED;
        }

        return $local->digest === $remote->digest ? AnchorStatus::ANCHORED : AnchorStatus::CONTRADICTED;
    }

    /**
     * The digest stored on the seal at the sequence, as the column holds it, or
     * `null` when it is not a string.
     *
     * @param  int  $sequence
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function storedDigestAt(int $sequence): ?string
    {
        $digest = $this->checkpoints()->where('sequence', $sequence)->value('seal_digest');

        return is_string($digest) ? $digest : null;
    }

    /**
     * Count the seals stored at a sequence below 1, which the chain never holds
     * and so no walk reads: a gap of the run when there are any, with the first
     * by sequence and id, since entries tied to one would otherwise be neither
     * unsealed nor orphaned.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function checkOutsideTheChain(VerificationTally $tally): void
    {
        $checkpoints = $this->checkpoints(...);
        $outside     = static fn (): Builder => $checkpoints()->where('sequence', '<', 1);
        $count       = $outside()->count();

        if ($count === 0) {
            return;
        }

        $first = $outside()->orderBy('sequence')->orderBy('id')->value('id');

        $tally->addFinding(new RunFinding(Finding::SEQUENCE_GAP, is_string($first) ? $first : null, $count));
    }

    /**
     * Count the member rows of no seal in the chain, whose seal is missing or
     * stored at a sequence below 1, a finding of the run when there are any,
     * with the first by seal and entry id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function checkOrphans(VerificationTally $tally): void
    {
        $connection = $this->connection();
        $orphans    = static fn (): Builder => $connection->table(IntegrityTables::membersTable() . ' as m')
            ->leftJoin(IntegrityTables::checkpointsTable() . ' as c', static function (JoinClause $join): void {
                $join->on('c.id', '=', 'm.checkpoint_id')->where('c.sequence', '>=', 1);
            })
            ->whereNull('c.id')
            ->useWritePdo();

        $count = $orphans()->count();

        if ($count === 0) {
            return;
        }

        $first = $orphans()->orderBy('m.checkpoint_id')->orderBy('m.entry_id')->value('m.entry_id');

        $tally->addFinding(new RunFinding(Finding::ORPHAN_MEMBER, is_string($first) ? $first : null, $count));
    }

    /**
     * Count the entries no seal holds: those older than the allowed age are
     * overdue, and those recorded further ahead of the run's clock than the
     * lookback are never sealed, each a finding of the run with the first by
     * time and id; the rest are pending, never bad.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function checkUnsealed(CarbonImmutable $now, VerificationTally $tally): void
    {
        $connection = $this->connection();
        $cutoff     = StoredTime::toStorage(StoredTime::format($now->subSeconds($this->settings->maxUnsealedAgeSeconds())));
        $ahead      = StoredTime::toStorage(StoredTime::format($now->addSeconds($this->settings->lookbackSeconds())));
        $unsealed   = static fn (): Builder => $connection->table(EntrySettings::table() . ' as e')
            ->leftJoin(IntegrityTables::membersTable() . ' as m', 'm.entry_id', '=', 'e.id')
            ->whereNull('m.entry_id')
            ->useWritePdo();

        $overdue = self::countUnsealed($unsealed()->where('e.recorded_at', '<', $cutoff), Finding::OVERDUE_UNSEALED, $tally);

        self::countUnsealed($unsealed()->where('e.recorded_at', '>', $ahead), Finding::FUTURE_UNSEALED, $tally);

        $tally->unsealed($unsealed()->whereBetween('e.recorded_at', [$cutoff, $ahead])->count(), $overdue);
    }

    /**
     * A query of the seals table on the storage connection's writer.
     *
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    private function checkpoints(): Builder
    {
        return $this->connection()->table(IntegrityTables::checkpointsTable())->useWritePdo();
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     *
     * @throws \InvalidArgumentException
     */
    private function connection(): Connection
    {
        return $this->database->connection(StorageConnection::name());
    }

    /**
     * Count the unsealed entries the query selects, a finding of the run when
     * there are any, with the first by time and id, and return how many.
     *
     * @param  \Illuminate\Database\Query\Builder  $entries
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @return int
     */
    private static function countUnsealed(Builder $entries, Finding $finding, VerificationTally $tally): int
    {
        $count = $entries->count();

        if ($count === 0) {
            return 0;
        }

        $first = $entries->orderBy('e.recorded_at')->orderBy('e.id')->value('e.id');

        $tally->addFinding(new RunFinding($finding, is_string($first) ? $first : null, $count));

        return $count;
    }
}
