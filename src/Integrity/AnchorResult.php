<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;

/**
 * The tally of one anchoring pass: whether an anchor is configured at all, the
 * seals anchored and the last of them, and what stopped the pass, if anything:
 * an anchor that was unavailable, by the class of its failure and the seal from
 * which seals wait to be anchored, a conflict the anchor raised for a seal, or
 * a seal refused because it does not verify.
 *
 * A pass stops at the first of these, so the first one recorded is the one
 * kept. A conflict and a refusal are alarms, since each is evidence of
 * tampering or of a seal that cannot be trusted; an unavailable anchor is not,
 * because a later run tries again. The tally holds sequences, ids, classes and
 * findings, never a value of an entry.
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

    /** @var ?string The class of the failure that made the anchor unavailable, or `null` while it is not. */
    private ?string $unavailableClass = null;

    /** @var ?int The sequence of the first seal that waits to be anchored, or `null` when none or unknown. */
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
     * Record that the anchor was unavailable with a failure of the class, from
     * the seal of the sequence on, or before any seal was read when the
     * sequence is `null`. Only the first is kept.
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
     * Record that the anchor holds another digest for the seal. Only the first
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
     * Record that the seal was refused because it does not verify, for the
     * finding; its id is `null` when the id itself is malformed. Only the first
     * is kept.
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
     * Whether the pass found something to alarm on: a conflict or a refused
     * seal. An unavailable anchor is not one, since a later run tries again.
     *
     * @return bool
     */
    public function isAlarm(): bool
    {
        return $this->conflict !== null || $this->refusal !== null;
    }

    /**
     * Whether the pass stopped before its batch was done: the anchor was
     * unavailable, raised a conflict, or a seal was refused.
     *
     * @return bool
     */
    public function isStopped(): bool
    {
        return $this->unavailableClass !== null || $this->isAlarm();
    }
}
