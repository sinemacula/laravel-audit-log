<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;

/**
 * The tally of one anchoring pass, which stops at its first unavailable anchor,
 * conflict or refused seal and keeps only that one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AnchorResult
{
    /** @var int Seals anchored. */
    private int $anchored = 0;

    /** @var ?int The sequence of the last seal anchored, or `null` before any. */
    private ?int $lastAnchored = null;

    /** @var ?string The class of the failure that made the anchor unavailable, or `null`. */
    private ?string $unavailableClass = null;

    /** @var ?int The sequence of the first seal waiting to be anchored, or `null` when none or unknown. */
    private ?int $waitingFrom = null;

    /** @var ?array{sequence: int, sealId: string} The seal the anchor holds another digest for, or `null`. */
    private ?array $conflict = null;

    /** @var ?array{sequence: int, sealId: ?string, finding: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding} The seal refused, or `null`. */
    private ?array $refusal = null;

    /**
     * Constructor.
     *
     * @param  bool  $configured
     */
    public function __construct(

        /** Whether an anchor is configured, so the pass was made at all. */
        private readonly bool $configured = true,
    ) {}

    /**
     * Count a seal anchored.
     *
     * @param  int  $sequence
     * @return void
     */
    public function anchored(int $sequence): void
    {
        $this->anchored++;
        $this->lastAnchored = $sequence;
    }

    /**
     * Record the anchor unavailable from the sequence on, or before any seal
     * was read when it is `null`; only the first is kept.
     *
     * @param  ?int  $sequence
     * @param  string  $class
     * @return void
     */
    public function unavailable(?int $sequence, string $class): void
    {
        if ($this->unavailableClass !== null) {
            return;
        }

        $this->unavailableClass = $class;
        $this->waitingFrom      = $sequence;
    }

    /**
     * Record that the anchor holds another digest for the seal; only the first
     * is kept.
     *
     * @param  int  $sequence
     * @param  string  $sealId
     * @return void
     */
    public function conflicted(int $sequence, string $sealId): void
    {
        $this->conflict ??= ['sequence' => $sequence, 'sealId' => $sealId];
    }

    /**
     * Record the seal refused for the finding, its id `null` when malformed;
     * only the first is kept.
     *
     * @param  int  $sequence
     * @param  ?string  $sealId
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @return void
     */
    public function refused(int $sequence, ?string $sealId, Finding $finding): void
    {
        $this->refusal ??= ['sequence' => $sequence, 'sealId' => $sealId, 'finding' => $finding];
    }

    /**
     * Whether an anchor is configured, so the pass was made at all.
     *
     * @return bool
     */
    public function isConfigured(): bool
    {
        return $this->configured;
    }

    /**
     * The seals anchored.
     *
     * @return int
     */
    public function anchoredCount(): int
    {
        return $this->anchored;
    }

    /**
     * The sequence of the last seal anchored, or `null` when none was.
     *
     * @return ?int
     */
    public function lastAnchored(): ?int
    {
        return $this->lastAnchored;
    }

    /**
     * The class of the failure that made the anchor unavailable, or `null` when
     * it was not.
     *
     * @return ?string
     */
    public function unavailableClass(): ?string
    {
        return $this->unavailableClass;
    }

    /**
     * The sequence of the first seal that waits to be anchored, or `null` when
     * the anchor was not unavailable or failed before any seal was read.
     *
     * @return ?int
     */
    public function waitingFrom(): ?int
    {
        return $this->waitingFrom;
    }

    /**
     * The seal the anchor holds another digest for, or `null` when there was no
     * conflict.
     *
     * @return ?array{sequence: int, sealId: string}
     */
    public function conflict(): ?array
    {
        return $this->conflict;
    }

    /**
     * The seal refused and the finding it was refused for, or `null` when none
     * was.
     *
     * @return ?array{sequence: int, sealId: ?string, finding: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding}
     */
    public function refusal(): ?array
    {
        return $this->refusal;
    }

    /**
     * Whether the pass found a conflict or a refused seal; an unavailable
     * anchor is no alarm, since a later run tries again.
     *
     * @return bool
     */
    public function isAlarm(): bool
    {
        return $this->conflict !== null || $this->refusal !== null;
    }

    /**
     * Whether the pass stopped before its batch was done.
     *
     * @return bool
     */
    public function isStopped(): bool
    {
        return $this->unavailableClass !== null || $this->isAlarm();
    }
}
