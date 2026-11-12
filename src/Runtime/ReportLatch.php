<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

/**
 * Stops a report from reporting itself again when its handler dispatches
 * something that fails the same way. Scoped per request or job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReportLatch
{
    /** @var bool Whether a report is running. */
    private bool $reporting = false;

    /**
     * Run the report unless one is already running, releasing the latch however
     * it ends.
     *
     * @param  \Closure(): void  $report
     * @return void
     */
    public function once(\Closure $report): void
    {
        if ($this->reporting) {
            return;
        }

        $this->reporting = true;

        try {
            $report();
        } finally {
            $this->reporting = false;
        }
    }
}
