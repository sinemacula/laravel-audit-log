<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * What every segment of one verification run shares, fixed when the run begins.
 * An anchor that fails once is not asked again, so an outage costs one failure.
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

        /** The instant the anchoring grace ends at, the run's clock, so a seal dated later is never excused. */
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
