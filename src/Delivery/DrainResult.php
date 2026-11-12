<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

/**
 * The tally of one drain, by how each row ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DrainResult
{
    /** @var int Rows every destination received, then deleted. */
    private int $delivered = 0;

    /** @var int Rows deleted undelivered because retention has already pruned their record. */
    private int $pruned = 0;

    /** @var int Rows released for a later attempt after a destination failed. */
    private int $retried = 0;

    /** @var int Rows failed and kept for a replay, or that could not be worked at all. */
    private int $failed = 0;

    /** @var int Rows another drain took over while this one worked them. */
    private int $stale = 0;

    /** @var int Rows another drain claimed between being listed and being claimed. */
    private int $missed = 0;

    /**
     * Count a row delivered and deleted.
     *
     * @return void
     */
    public function addDelivered(): void
    {
        $this->delivered++;
    }

    /**
     * Count a row deleted undelivered because its record was pruned.
     *
     * @return void
     */
    public function addPruned(): void
    {
        $this->pruned++;
    }

    /**
     * Count a row released for a later attempt.
     *
     * @return void
     */
    public function addRetried(): void
    {
        $this->retried++;
    }

    /**
     * Count a row failed, or one that could not be worked.
     *
     * @return void
     */
    public function addFailed(): void
    {
        $this->failed++;
    }

    /**
     * Count a row another drain took over.
     *
     * @return void
     */
    public function addStale(): void
    {
        $this->stale++;
    }

    /**
     * Count a row another drain claimed first.
     *
     * @return void
     */
    public function addMissed(): void
    {
        $this->missed++;
    }

    /**
     * The rows delivered and deleted.
     *
     * @return int
     */
    public function delivered(): int
    {
        return $this->delivered;
    }

    /**
     * The rows deleted undelivered because their record was pruned.
     *
     * @return int
     */
    public function pruned(): int
    {
        return $this->pruned;
    }

    /**
     * The rows released for a later attempt.
     *
     * @return int
     */
    public function retried(): int
    {
        return $this->retried;
    }

    /**
     * The rows failed, or that could not be worked.
     *
     * @return int
     */
    public function failed(): int
    {
        return $this->failed;
    }

    /**
     * The rows another drain took over.
     *
     * @return int
     */
    public function stale(): int
    {
        return $this->stale;
    }

    /**
     * The rows another drain claimed first.
     *
     * @return int
     */
    public function missed(): int
    {
        return $this->missed;
    }

    /**
     * Whether any row failed; a retry, a takeover and a miss are still to come,
     * and a pruned row is complete.
     *
     * @return bool
     */
    public function hasFailures(): bool
    {
        return $this->failed > 0;
    }
}
