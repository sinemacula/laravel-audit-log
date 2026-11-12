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
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Privacy\KeyStoreUse;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Verifies the log or a range of its seals, streaming one report per segment.
 * It reads only the writer, so replica lag never reads as a missing row.
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
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalVerifier  $journal
     * @param  \SineMacula\Laravel\AuditLog\Integrity\KeyStoreVerifier  $keys
     * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $encrypter
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

        /** The verifier of the lifecycle journal and the seals' commitments to it. */
        private JournalVerifier $journal,

        /** The verifier of the owners' key store, on a run of the whole log. */
        private KeyStoreVerifier $keys,

        /** The bound field encrypter, which says whether the package's key store is in use. */
        private FieldEncrypter $encrypter,
    ) {}

    /**
     * Verify the range, the journal and, for the whole log, the key store. The
     * anchor's head is read first, so it is never a seal made meanwhile.
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

        $journal = $this->journal->verify($tally);
        $keys    = $range->isComplete() ? $this->keys->verify($tally, KeyStoreUse::covers($this->encrypter))->naming(KeyStoreUse::describe($this->encrypter)) : null;
        $summary = VerificationSummary::of($bounds, $head, $remote?->sequence, $status, $range->isComplete(), $this->discovers(), $tally)->withJournal($journal)->withKeys($keys);

        if ($range->isComplete()) {
            $last = ['at' => StoredTime::format($now), 'head' => $head, 'passed' => !$summary->fails($strict), 'strict' => $strict];

            $this->progress->put(IntegrityProgress::VERIFY_LAST_FULL, $last, $now);
        }

        return $summary;
    }

    /**
     * Ask the anchor for its head; a conflict is a finding of the run, and any
     * other failure makes the anchor unavailable for the rest of it.
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
     * seal: it holds none, or the walk reaches its head with the same digest.
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
     * The sequence of the local head, or `null` with no seal in the chain; an
     * unreadable greatest sequence is refused, never read as empty.
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
     * Walk the range, giving each report to the callback, and return the report
     * at the anchor's head if met; ending short of the range is a gap.
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

            // An anchor that failed when asked is not asked again in this run
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
     * The stored seals in the range, read a page at a time as needed.
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
     * The first link of a ranged run: the seal before its first, reported only
     * when it fails; a missing one is a gap.
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
     * How the anchor's head compares with the local log; an empty anchor agrees
     * only with an empty log.
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
     * How the anchor's head compares with the local seal at its sequence, read
     * on its own when the range left it out.
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

        // The walk reported a readable seal it met; others are the run's
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
     * How the local seal at the anchor's head compares with it; an unreadable
     * seal is compared by its stored digest.
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
     * Count the seals below sequence 1, which no walk reads, as a gap: entries
     * tied to one would otherwise be neither unsealed nor orphaned.
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
     * Count the member rows of no seal in the chain as a finding of the run.
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
     * Count the unsealed entries: overdue and far-future ones are findings of
     * the run, and the rest pending.
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
     * Count the unsealed entries the query selects as a finding of the run, and
     * return how many.
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
