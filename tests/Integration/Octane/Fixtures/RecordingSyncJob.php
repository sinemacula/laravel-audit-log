<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane\Fixtures;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\Auth;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

/**
 * A sync-queued job that records an activity; it can forget the guards first,
 * so its record has only the actor it carried.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingSyncJob implements ShouldQueue
{
    use Queueable;

    /** @var string The code the job records. */
    public const string CODE = 'report.generated';

    /**
     * Constructor.
     *
     * @param  bool  $forgetsTheGuards
     */
    public function __construct(

        /** Whether the job forgets the guards before it records. */
        public readonly bool $forgetsTheGuards = false,
    ) {}

    /**
     * Record the activity.
     *
     * @return void
     */
    public function handle(): void
    {
        if ($this->forgetsTheGuards) {
            Auth::forgetGuards();
        }

        AuditLog::record(self::CODE);
    }
}
