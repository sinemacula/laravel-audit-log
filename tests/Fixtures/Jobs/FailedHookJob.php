<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Jobs;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

/**
 * A queued job that throws and records one activity from its `failed()` hook,
 * which shows the frame the hook runs in: the caller's on the sync queue, the
 * job's own in a worker.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailedHookJob implements ShouldQueue
{
    use Queueable;

    /** @var string The code the `failed()` hook records. */
    public const string CODE = 'job.failed_hook';

    /** @var string The message of what it throws. */
    public const string MESSAGE = 'The job failed.';

    /**
     * Throw.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function handle(): void
    {
        throw new \RuntimeException(self::MESSAGE);
    }

    /**
     * Record the activity, which is the job failing.
     *
     * @param  ?\Throwable  $exception
     * @return void
     */
    public function failed(?\Throwable $exception = null): void
    {
        AuditLog::record(self::CODE);
    }
}
