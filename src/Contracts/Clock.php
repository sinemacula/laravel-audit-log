<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use Carbon\CarbonImmutable;

/**
 * Clock contract: the time the package stamps on records.
 *
 * The package binds `Support\SystemClock`, which reads the system time and
 * honours a frozen `CarbonImmutable::setTestNow()`; an application or a test
 * rebinds the contract, a frozen clock say, to choose the time itself. An
 * implementation must keep no state between calls beyond a fixed instant.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Clock
{
    /**
     * The current instant, in UTC.
     *
     * @return \Carbon\CarbonImmutable
     */
    public function now(): CarbonImmutable;
}
