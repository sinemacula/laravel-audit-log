<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * What every segment of one verification run shares: the head the anchor
 * reported, whether the anchor may still be asked to confirm a receipt, the
 * instants the anchoring grace runs between, fixed when the run begins, and
 * whether the anchor's head settles each seal's anchoring.
 *
 * The grace ends at the run's clock, so a seal dated after the run began, by a
 * sealing server's clock running ahead or by a forger, is never excused. When
 * discovery gave the anchor's head and the walk reaches it, that head settles
 * anchoring with no call per seal: a seal up to it is anchored, since the
 * head's digest commits to the chain the walk checks, and a seal after it is
 * not held.
 *
 * An anchor that fails once in a run is not asked again in it, so an outage
 * costs one failure rather than one per seal: the run carries on with a context
 * that no longer asks, and every later segment's anchoring is `unavailable`
 * without a call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class VerificationContext
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead  $remote
     * @param  bool  $askAnchor
     * @param  string  $graceFrom
     * @param  string  $graceTo
     * @param  bool  $byHead
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The newest seal the anchor holds, or `null` when it holds none or was not asked. */
        public ?AnchoredHead $remote,

        /** Whether an anchor is configured and has not failed in this run, so it may be asked. */
        public bool $askAnchor,

        /** The instant, ISO-8601 UTC with microseconds, the anchoring grace before the run's clock. */
        public string $graceFrom,

        /** The instant, ISO-8601 UTC with microseconds, the anchoring grace ends at: the run's clock. */
        public string $graceTo,

        /** Whether the anchor's head settles each seal's anchoring, with no call per seal. */
        public bool $byHead = false,
    ) {
        if (!StoredTime::isInstant($graceFrom) || !StoredTime::isInstant($graceTo) || strcmp($graceFrom, $graceTo) > 0) {
            throw new \InvalidArgumentException('A verification\'s grace must run between two ISO-8601 UTC instants with microseconds, the first not after the second.');
        }
    }

    /**
     * The same context, with the anchor no longer asked, after it failed.
     *
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withoutAnchor(): self
    {
        return new self($this->remote, false, $this->graceFrom, $this->graceTo, $this->byHead);
    }
}
