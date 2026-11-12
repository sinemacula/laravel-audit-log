<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Support;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\AuditLog\Contracts\Clock;

/**
 * A clock stopped at one instant, given in UTC, so a test chooses when the
 * records it finalises are recorded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FrozenClock implements Clock
{
    /**
     * Constructor.
     *
     * @param  \Carbon\CarbonImmutable  $instant
     */
    private function __construct(

        /** The instant the clock is stopped at, in UTC. */
        private CarbonImmutable $instant,
    ) {}

    /**
     * A clock stopped at the instant, in any form Carbon reads; a time without
     * a zone is read in UTC.
     *
     * @param  string  $instant
     * @return self
     */
    public static function at(string $instant): self
    {
        return new self((new CarbonImmutable($instant, 'UTC'))->setTimezone('UTC'));
    }

    /**
     * The instant the clock is stopped at, in UTC.
     *
     * @return \Carbon\CarbonImmutable
     */
    #[\Override]
    public function now(): CarbonImmutable
    {
        return $this->instant;
    }
}
