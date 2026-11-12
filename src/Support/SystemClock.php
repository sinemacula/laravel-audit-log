<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Support;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\AuditLog\Contracts\Clock;

/**
 * The system clock in UTC, read through Carbon so
 * `CarbonImmutable::setTestNow()` freezes it.
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
