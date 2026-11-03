<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;

/**
 * The tally of one replay: the records replayed, those a dry run would replay,
 * those the store or a destination did not take, those another drain has in
 * hand, and the lines skipped, counted apart by why, since an altered record is
 * never to be confused with one whose key was removed.
 *
 * It also holds a bounded list of what happened, one event per outcome, saying
 * where, what and which record. An event holds a record's id only when that id
 * is a lower-case UUID, and the class of a failure, and nothing else, so a
 * console never reaches what a record held and hostile bytes never reach a
 * console.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReplayResult
{
    /** @var int The most events listed; the rest are only counted. */
    public const int MAX_EVENTS = 1000;

    /** @var string A UUID in the one form every record id takes. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var int Records the store has, or every destination has, because of this replay. */
    private int $replayed = 0;

    /** @var int Records a dry run found it would replay. */
    private int $wouldReplay = 0;

    /** @var int Records the store refused, or a drain could not deliver this time. */
    private int $failed = 0;

    /** @var int Rows another drain has in hand. */
    private int $deferred = 0;

    /** @var array<string, int> Lines skipped, by the value of the failure that refused each. */
    private array $skipped = [];

    /** @var list<string> What happened, oldest first, up to the bound. */
    private array $events = [];

    /** @var int Events past the bound, which are only counted. */
    private int $omitted = 0;

    /**
     * Count a record replayed.
     *
     * @param  string  $where
     * @param  string  $id
     * @return void
     */
    public function addReplayed(string $where, string $id): void
    {
        $this->replayed++;

        $this->listEvent($where, 'replayed', $id);
    }

    /**
     * Count a record a dry run would replay.
     *
     * @param  string  $where
     * @param  string  $id
     * @return void
     */
    public function addWouldReplay(string $where, string $id): void
    {
        $this->wouldReplay++;

        $this->listEvent($where, 'would_replay', $id);
    }

    /**
     * Count a record the store refused, by its id and the class of the failure.
     *
     * @param  string  $where
     * @param  string  $id
     * @param  string  $class
     * @return void
     */
    public function addFailed(string $where, string $id, string $class): void
    {
        $this->failed++;

        $this->listEvent($where, 'failed', $id, $class);
    }

    /**
     * Count a line skipped, under the failure that refused it, with its id when
     * it has one.
     *
     * @param  string  $where
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure  $failure
     * @param  ?string  $id
     * @return void
     */
    public function addSkipped(string $where, EnvelopeFailure $failure, ?string $id = null): void
    {
        $this->skipped[$failure->value] = ($this->skipped[$failure->value] ?? 0) + 1;

        $this->listEvent($where, $failure->value, $id);
    }

    /**
     * Map a drain's tally across: a row delivered is replayed; a row failed, or
     * released for a later attempt because a destination failed again, is one
     * this replay did not deliver; and a row another drain took over or claimed
     * first is that drain's. A drain does not say which row ended how, so it
     * lists no event.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $drain
     * @return void
     */
    public function addDrain(DrainResult $drain): void
    {
        $this->replayed += $drain->delivered();
        $this->failed   += $drain->failed() + $drain->retried();
        $this->deferred += $drain->stale()  + $drain->missed();
    }

    /**
     * The records replayed.
     *
     * @return int
     */
    public function replayed(): int
    {
        return $this->replayed;
    }

    /**
     * The records a dry run would replay.
     *
     * @return int
     */
    public function wouldReplay(): int
    {
        return $this->wouldReplay;
    }

    /**
     * The records the store refused, or a drain could not deliver this time.
     *
     * @return int
     */
    public function failed(): int
    {
        return $this->failed;
    }

    /**
     * The rows another drain has in hand.
     *
     * @return int
     */
    public function deferred(): int
    {
        return $this->deferred;
    }

    /**
     * The lines skipped, by the value of the failure that refused each, in the
     * order each failure was first met.
     *
     * @return array<string, int>
     */
    public function skipped(): array
    {
        return $this->skipped;
    }

    /**
     * What happened, oldest first, up to the bound: where, then the outcome,
     * then the record's id when it has a printable one, then the class of a
     * failure.
     *
     * @return list<string>
     */
    public function events(): array
    {
        return $this->events;
    }

    /**
     * The events past the bound, which are counted and not listed.
     *
     * @return int
     */
    public function omittedEvents(): int
    {
        return $this->omitted;
    }

    /**
     * Whether any line was skipped or any record failed, which is what makes a
     * replay unsuccessful: a dry run counts the lines it would skip too, and a
     * row another drain has in hand is still to come.
     *
     * @return bool
     */
    public function hasSkippedOrFailed(): bool
    {
        return $this->failed > 0 || $this->skipped !== [];
    }

    /**
     * List an event, or count it once the list is at its bound.
     *
     * @param  string  $where
     * @param  string  $outcome
     * @param  ?string  $id
     * @param  ?string  $class
     * @return void
     */
    private function listEvent(string $where, string $outcome, ?string $id, ?string $class = null): void
    {
        if (count($this->events) >= self::MAX_EVENTS) {
            $this->omitted++;

            return;
        }

        $event = $where . ': ' . $outcome;

        if ($id !== null && preg_match(self::UUID_PATTERN, $id) === 1) {
            $event .= ' ' . $id;
        }

        $this->events[] = $class === null ? $event : $event . ' (' . $class . ')';
    }
}
