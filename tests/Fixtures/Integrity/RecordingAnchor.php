<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Integrity;

use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;

/**
 * An anchor that holds digests in memory by sequence and records each call
 * reaching it, so sealing and verifying in one test share it.
 *
 * It anchors idempotently, refusing another digest for a held sequence; a test
 * can make it fail, recover, disagree at a sequence or refuse discovery.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingAnchor implements CheckpointAnchor
{
    /** @var string The anchor's name. */
    public const string NAME = 'recording';

    /** @var array<int, string> The digest held at each sequence. */
    private array $held = [];

    /** @var list<string> The calls that reached the anchor, by method name, in order. */
    private array $calls = [];

    /** @var ?\Throwable What every call that reaches the anchor throws, while it is failing. */
    private ?\Throwable $failure = null;

    /**
     * Constructor.
     *
     * @param  bool  $discovery
     */
    public function __construct(

        /** Whether the anchor can report its head. */
        private readonly bool $discovery = true,
    ) {}

    /**
     * Make every call that reaches the anchor throw the failure, or an
     * unavailable anchor's `RuntimeException` when none is given.
     *
     * @param  ?\Throwable  $with
     * @return self
     */
    public function failing(#[\SensitiveParameter] ?\Throwable $with = null): self
    {
        $this->failure = $with ?? new \RuntimeException('The anchor is unavailable.');

        return $this;
    }

    /**
     * Make the anchor answer again after it was failing.
     *
     * @return self
     */
    public function recovering(): self
    {
        $this->failure = null;

        return $this;
    }

    /**
     * Hold the digest at the sequence instead of whatever was anchored there,
     * as a remote that disagrees with the local log would.
     *
     * @param  int  $sequence
     * @param  string  $digest
     * @return self
     */
    public function holdInstead(int $sequence, string $digest): self
    {
        $this->held[$sequence] = $digest;

        return $this;
    }

    /**
     * The digest held at each sequence, in sequence order.
     *
     * @return array<int, string>
     */
    public function held(): array
    {
        $held = $this->held;

        ksort($held);

        return $held;
    }

    /**
     * The calls that reached the anchor, by method name, in order.
     *
     * @return list<string>
     */
    public function calls(): array
    {
        return $this->calls;
    }

    /**
     * The anchor's name.
     *
     * @return string
     */
    #[\Override]
    public function name(): string
    {
        return self::NAME;
    }

    /**
     * Hold the summary's digest at its sequence and return the sequence and
     * digest; anchoring the same digest again changes nothing.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @return array{sequence: int, digest: string}
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException
     * @throws \Throwable
     */
    #[\Override]
    public function anchor(SealSummary $seal): array
    {
        $this->reach('anchor');
        $this->hold($seal);

        return ['sequence' => $seal->sequence, 'digest' => $seal->sealDigest];
    }

    /**
     * Whether the receipt is exactly the one the summary was given, and the
     * anchor still holds the summary's digest at its sequence.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @param  array<string, scalar|null>  $receipt
     * @return bool
     *
     * @throws \Throwable
     */
    #[\Override]
    public function confirms(SealSummary $seal, array $receipt): bool
    {
        $this->reach('confirms');

        $expected = ['sequence' => $seal->sequence, 'digest' => $seal->sealDigest];

        return $receipt === $expected && ($this->held[$seal->sequence] ?? null) === $seal->sealDigest;
    }

    /**
     * Whether the anchor can report its head, as the test constructed it.
     *
     * @return bool
     */
    #[\Override]
    public function supportsDiscovery(): bool
    {
        return $this->discovery;
    }

    /**
     * The highest sequence held and its digest, or `null` when nothing is
     * held; an anchor made unable to discover refuses to be asked.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    #[\Override]
    public function latest(): ?AnchoredHead
    {
        $this->reach('latest');

        return $this->head();
    }

    /**
     * Hold the summary's digest at its sequence, refusing another digest for a
     * sequence already held.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSummary  $seal
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException
     */
    private function hold(SealSummary $seal): void
    {
        if (($this->held[$seal->sequence] ?? $seal->sealDigest) !== $seal->sealDigest) {
            throw AnchorConflictException::forSequence($seal->sequence);
        }

        $this->held[$seal->sequence] = $seal->sealDigest;
    }

    /**
     * The highest sequence held and its digest, or `null` when nothing is
     * held; an anchor made unable to discover refuses to be asked.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
     *
     * @throws \LogicException
     */
    private function head(): ?AnchoredHead
    {
        if (!$this->discovery) {
            throw new \LogicException('This anchor cannot discover its head, so it must never be asked for it.');
        }

        if ($this->held === []) {
            return null;
        }

        $sequence = max(array_keys($this->held));

        return new AnchoredHead($sequence, $this->held[$sequence]);
    }

    /**
     * Record that the call reached the anchor, then throw the failure while the
     * anchor is failing.
     *
     * @param  string  $call
     * @return void
     *
     * @throws \Throwable
     */
    private function reach(string $call): void
    {
        $this->calls[] = $call;

        if ($this->failure !== null) {
            throw $this->failure;
        }
    }
}
