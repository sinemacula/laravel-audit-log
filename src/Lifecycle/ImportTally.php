<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;

/**
 * The counts of one import as it goes: the lines read, imported, found to be
 * duplicates, in conflict or rejected, each rejection by its reason, the first
 * hundred conflicting source record ids in file order, the values removed as
 * envelope-shaped or as descriptors, and the lines already past their retention
 * when they arrived, unless that count was given up.
 *
 * Every line read is counted once, and ends imported, a duplicate, a conflict
 * or rejected, so those four sum to the lines read once the import has ended.
 * Every count only grows. The conflicting ids listed stop at a hundred, or
 * sooner once their canonical list would pass 60,000 bytes, so it always fits
 * the batch row's `text` column, MySQL's 65,535 bytes included. The count of
 * lines past retention is best effort: once the policy fails to answer it is
 * given up for the import, and reads as `null`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ImportTally
{
    /** @var int The most conflicting source record ids listed: the first, in file order. */
    public const int MAX_CONFLICT_IDS = 100;

    /** @var int The most bytes the canonical list of conflicting ids may take: under MySQL's 65,535 for a `text` column. */
    public const int MAX_CONFLICT_ID_BYTES = 60000;

    /** @var int The lines read, blank lines aside. */
    private int $linesRead = 0;

    /** @var int The lines imported as new rows. */
    private int $imported = 0;

    /** @var int The lines that repeat a record imported already. */
    private int $duplicates = 0;

    /** @var int The lines that conflict with a record imported already. */
    private int $conflicts = 0;

    /** @var int The lines rejected. */
    private int $rejected = 0;

    /** @var array<string, int> How many lines were rejected for each reason, by its value, in the order each reason was first met. */
    private array $rejections = [];

    /** @var list<string> The first hundred conflicting source record ids, in file order. */
    private array $conflictIds = [];

    /** @var int The bytes the canonical list of the conflicting ids takes. */
    private int $conflictIdBytes = 2;

    /** @var bool Whether the conflicting ids listed stopped short of a hundred, for want of room. */
    private bool $conflictIdsFull = false;

    /** @var int The envelope-shaped values and descriptors removed from the lines. */
    private int $dropped = 0;

    /** @var ?int The lines whose records were already past their retention when they arrived; `null` once the count was given up. */
    private ?int $pastRetention = 0;

    /**
     * Count a line read.
     *
     * @return void
     */
    public function countRead(): void
    {
        $this->linesRead++;
    }

    /**
     * Count a line rejected, under its reason.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection  $reason
     * @return void
     */
    public function countRejected(ImportRejection $reason): void
    {
        $this->rejected++;
        $this->rejections[$reason->value] = ($this->rejections[$reason->value] ?? 0) + 1;
    }

    /**
     * Count the values removed from a line.
     *
     * @param  int  $count
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function countDropped(int $count): void
    {
        if ($count < 0) {
            throw new \InvalidArgumentException('The values removed from a line cannot be fewer than none.');
        }

        $this->dropped += $count;
    }

    /**
     * Count a line whose record was already past its retention when it arrived.
     *
     * @return void
     */
    public function countPastRetention(): void
    {
        if ($this->pastRetention === null) {
            return;
        }

        $this->pastRetention++;
    }

    /**
     * Give up the count of lines past retention for the rest of the import: the
     * policy failed to answer.
     *
     * @return void
     */
    public function givePastRetentionUp(): void
    {
        $this->pastRetention = null;
    }

    /**
     * Whether the lines past retention are still counted.
     *
     * @return bool
     */
    public function countsPastRetention(): bool
    {
        return $this->pastRetention !== null;
    }

    /**
     * Count a chunk's plan: its new lines imported, its duplicates, and its
     * conflicts, listing their ids while the list has room.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportPlan  $plan
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    public function countPlan(ImportPlan $plan): void
    {
        $this->imported   += count($plan->lines);
        $this->duplicates += $plan->duplicates;
        $this->conflicts  += $plan->conflicts();

        foreach ($plan->conflictIds() as $id) {
            if (!$this->hasRoomFor($id)) {
                return;
            }

            $this->conflictIdBytes += strlen(CanonicalEncoder::encode([$id])) - ($this->conflictIds === [] ? 2 : 1);
            $this->conflictIds[] = $id;
        }
    }

    /**
     * A copy of the tally with a chunk's plan counted, leaving this one as it
     * is: what a chunk's transaction writes before it commits.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportPlan  $plan
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public function with(ImportPlan $plan): self
    {
        $next = clone $this;

        $next->countPlan($plan);

        return $next;
    }

    /**
     * The lines read, blank lines aside.
     *
     * @return int
     */
    public function linesRead(): int
    {
        return $this->linesRead;
    }

    /**
     * The lines imported as new rows.
     *
     * @return int
     */
    public function imported(): int
    {
        return $this->imported;
    }

    /**
     * The lines that repeat a record imported already.
     *
     * @return int
     */
    public function duplicates(): int
    {
        return $this->duplicates;
    }

    /**
     * The lines that conflict with a record imported already.
     *
     * @return int
     */
    public function conflicts(): int
    {
        return $this->conflicts;
    }

    /**
     * The lines rejected.
     *
     * @return int
     */
    public function rejected(): int
    {
        return $this->rejected;
    }

    /**
     * How many lines were rejected for each reason, by its value, in the order
     * each reason was first met.
     *
     * @return array<string, int>
     */
    public function rejections(): array
    {
        return $this->rejections;
    }

    /**
     * The first hundred conflicting source record ids, in file order.
     *
     * @return list<string>
     */
    public function conflictIds(): array
    {
        return $this->conflictIds;
    }

    /**
     * The envelope-shaped values and descriptors removed from the lines.
     *
     * @return int
     */
    public function dropped(): int
    {
        return $this->dropped;
    }

    /**
     * The lines whose records were already past their retention when they
     * arrived, or `null` when the count was given up.
     *
     * @return ?int
     */
    public function pastRetention(): ?int
    {
        return $this->pastRetention;
    }

    /**
     * Whether nothing read was rejected and nothing conflicted, so every line
     * was imported or was a duplicate.
     *
     * @return bool
     */
    public function isComplete(): bool
    {
        return $this->rejected === 0 && $this->conflicts === 0;
    }

    /**
     * The counts as the batch row holds them, the conflicting ids as a
     * canonical JSON list, or `null` when none conflicted.
     *
     * @return array{lines_read: int, imported: int, duplicates: int, conflicts: int, rejected: int, conflict_ids: ?string}
     *
     * @throws \UnexpectedValueException
     */
    public function toBatch(): array
    {
        return [
            'lines_read'   => $this->linesRead,
            'imported'     => $this->imported,
            'duplicates'   => $this->duplicates,
            'conflicts'    => $this->conflicts,
            'rejected'     => $this->rejected,
            'conflict_ids' => $this->conflictIds === [] ? null : CanonicalEncoder::encode($this->conflictIds),
        ];
    }

    /**
     * Whether the conflicting id still fits the list: fewer than a hundred are
     * listed, and its canonical list would stay within its bytes. Once one does
     * not fit, none later is listed, so the list keeps file order.
     *
     * @param  string  $id
     * @return bool
     *
     * @throws \UnexpectedValueException
     */
    private function hasRoomFor(string $id): bool
    {
        $bytes = $this->conflictIdBytes + strlen(CanonicalEncoder::encode([$id])) - ($this->conflictIds === [] ? 2 : 1);

        $this->conflictIdsFull = $this->conflictIdsFull || count($this->conflictIds) >= self::MAX_CONFLICT_IDS || $bytes > self::MAX_CONFLICT_ID_BYTES;

        return !$this->conflictIdsFull;
    }
}
