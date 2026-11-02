<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane\Fixtures;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

/**
 * A queued job a request dispatches onto the sync queue, which records an
 * activity and then fails, so the exception reaches the request that dispatched
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ThrowingSyncJob implements ShouldQueue
{
    use Queueable;

    /** @var string The code the job records before it fails. */
    public const string CODE = 'report.abandoned';

    /** @var string The message the job fails with. */
    public const string MESSAGE = 'The report could not be generated.';

    /**
     * Record the activity, then fail.
     *
     * @return never
     *
     * @throws \RuntimeException
     */
    public function handle(): never
    {
        AuditLog::record(self::CODE);

        throw new \RuntimeException(self::MESSAGE);
    }
}
