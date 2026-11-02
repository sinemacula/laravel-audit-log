<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Support;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\AuditLog\Contracts\Clock;

/**
 * The system's clock, in UTC: the current instant as Carbon reads it, so a test
 * that freezes `CarbonImmutable::setTestNow()`, in any time zone, freezes it
 * too, and the instant is always given in UTC whatever the application's or the
 * runtime's time zone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SystemClock implements Clock
{
    /**
     * The current instant, in UTC, its microseconds kept.
     *
     * @return \Carbon\CarbonImmutable
     */
    #[\Override]
    public function now(): CarbonImmutable
    {
        return CarbonImmutable::now()->setTimezone('UTC');
    }
}
