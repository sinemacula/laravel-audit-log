<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

use Carbon\CarbonImmutable;

/**
 * Clock contract: the time the package stamps on records. An implementation
 * keeps no state beyond a fixed instant.
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
