<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Jobs;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Bus;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * A queued job that records, runs another job on the sync queue, and records
 * again, so the second record shows the frame it got back; it can sign someone
 * in for the inner job alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DispatchingJob implements ShouldQueue
{
    use Queueable;

    /** @var string The code the job records before the inner job. */
    public const string BEFORE = 'job.before_inner';

    /** @var string The code the job records after the inner job. */
    public const string AFTER = 'job.after_inner';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Queue\ShouldQueue  $inner
     * @param  ?int  $signsInAs
     * @param  ?\Illuminate\Contracts\Queue\ShouldQueue  $then
     */
    public function __construct(

        /** The job to run on the sync queue. */
        public readonly ShouldQueue $inner,

        /** The id of the user signed in for the inner job alone, if any. */
        public readonly ?int $signsInAs = null,

        /** The job to run on the sync queue after the inner job, if any. */
        public readonly ?ShouldQueue $then = null,
    ) {}

    /**
     * Record, run the inner job, and record again.
     *
     * @return void
     */
    public function handle(): void
    {
        AuditLog::record(self::BEFORE);

        if ($this->signsInAs !== null) {
            Auth::guard('web')->setUser((new StubAuthUser)->forceFill(['id' => $this->signsInAs]));
        }

        try {
            Bus::dispatchSync($this->inner);
        } catch (\RuntimeException) {
            // An inner job that throws is one of the things under test; what
            // matters is the frame this job has afterwards
        }

        if ($this->signsInAs !== null) {
            Auth::guard('web')->forgetUser();
        }

        AuditLog::record(self::AFTER);

        if ($this->then === null) {
            return;
        }

        Bus::dispatchSync($this->then);
    }
}
