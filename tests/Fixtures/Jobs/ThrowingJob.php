<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Jobs;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

/**
 * A queued job that records one activity and then throws, with no `failed()`
 * hook.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ThrowingJob implements ShouldQueue
{
    use Queueable;

    /** @var string The code the job records before it throws. */
    public const string CODE = 'job.throwing';

    /** @var string The message of what it throws. */
    public const string MESSAGE = 'The job failed.';

    /**
     * Record the activity, then throw.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function handle(): void
    {
        AuditLog::record(self::CODE);

        throw new \RuntimeException(self::MESSAGE);
    }
}
