<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Jobs;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\Auth;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use Tests\Unit\Stubs\StubAuthUser;

/**
 * A queued job that records one activity, optionally after signing a user in on
 * the `web` guard and leaving it signed in, or after failing itself and
 * carrying on, which are the two things a job can do that outlive its frame.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingJob implements ShouldQueue
{
    use Queueable;

    /** @var string The code the job records unless it is given another. */
    public const string CODE = 'job.recorded';

    /**
     * Constructor.
     *
     * @param  string  $code
     * @param  ?int  $signsInAs
     * @param  bool  $failsItselfFirst
     */
    public function __construct(

        /** The code the job records. */
        public readonly string $code = self::CODE,

        /** The id of the user the job signs in and leaves signed in, if any. */
        public readonly ?int $signsInAs = null,

        /** Whether the job fails itself before it records. */
        public readonly bool $failsItselfFirst = false,
    ) {}

    /**
     * Record the activity.
     *
     * @return void
     */
    public function handle(): void
    {
        if ($this->signsInAs !== null) {
            Auth::guard('web')->setUser((new StubAuthUser)->forceFill(['id' => $this->signsInAs]));
        }

        if ($this->failsItselfFirst) {
            $this->fail();
        }

        AuditLog::record($this->code);
    }
}
