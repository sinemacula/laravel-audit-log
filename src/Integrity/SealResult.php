<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * The tally of one seal run.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SealResult
{
    /** @var int Seals written. */
    private int $seals = 0;

    /** @var int Entries the seals written hold. */
    private int $entries = 0;

    /** @var int Attempts rolled back and made again after losing to a concurrent writer. */
    private int $retries = 0;

    /** @var int Entries left unsealed because their id, HMAC or time is malformed. */
    private int $skipped = 0;

    /** @var ?int The sequence of the first seal written, or `null` before any. */
    private ?int $firstSequence = null;

    /** @var ?int The sequence of the last seal written, or `null` before any. */
    private ?int $lastSequence = null;

    /** @var bool Whether a sweep read the table to its end. */
    private bool $sweepCompleted = false;

    /**
     * Count a seal written, with the entries it holds.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @return void
     */
    public function added(SealEnvelope $seal): void
    {
        $this->seals++;
        $this->entries += $seal->memberCount;
        $this->firstSequence ??= $seal->sequence;
        $this->lastSequence = $seal->sequence;
    }

    /**
     * Count an attempt rolled back to be made again.
     *
     * @return void
     */
    public function retried(): void
    {
        $this->retries++;
    }

    /**
     * Count entries left unsealed because they cannot be sealed.
     *
     * @param  int  $count
     * @return void
     */
    public function skipped(int $count): void
    {
        $this->skipped += $count;
    }

    /**
     * Mark the sweep as having read the table to its end.
     *
     * @return void
     */
    public function completedSweep(): void
    {
        $this->sweepCompleted = true;
    }

    /**
     * The seals written.
     *
     * @return int
     */
    public function seals(): int
    {
        return $this->seals;
    }

    /**
     * The entries the seals written hold.
     *
     * @return int
     */
    public function entries(): int
    {
        return $this->entries;
    }

    /**
     * The attempts rolled back and made again.
     *
     * @return int
     */
    public function retries(): int
    {
        return $this->retries;
    }

    /**
     * The entries left unsealed because they cannot be sealed.
     *
     * @return int
     */
    public function skippedEntries(): int
    {
        return $this->skipped;
    }

    /**
     * The sequence of the first seal written, or `null` when none was.
     *
     * @return ?int
     */
    public function firstSequence(): ?int
    {
        return $this->firstSequence;
    }

    /**
     * The sequence of the last seal written, or `null` when none was.
     *
     * @return ?int
     */
    public function lastSequence(): ?int
    {
        return $this->lastSequence;
    }

    /**
     * Whether a sweep read the table to its end.
     *
     * @return bool
     */
    public function isSweepComplete(): bool
    {
        return $this->sweepCompleted;
    }
}
