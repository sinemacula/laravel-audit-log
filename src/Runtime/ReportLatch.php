<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Runtime;

/**
 * Stops a report from causing another report of itself: a handler that queues
 * something while it reports a failed dispatch dispatches again, which fails
 * the same way, and without this would report again, and so on until the
 * process ran out of memory.
 *
 * It is scoped, so it holds nothing from one request or job to the next.
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
     * Run the report, unless one is already running further up the stack, and
     * let go of the latch whatever the report does.
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
