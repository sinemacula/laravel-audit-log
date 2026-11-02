<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Console\Events\CommandFinished;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use Tests\Fixtures\Commands\RecordingCommand;

/**
 * A provider that audits the end of jobs and commands from its `boot()`, as an
 * application does, booted after the package's. It records only while its
 * switch is on, and for commands only the recording one, so a test class can
 * list it without every job and migration recording more.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AuditsFrameEndsProvider extends ServiceProvider
{
    /** @var string The configuration key that turns the listeners on. */
    public const string SWITCH = 'testing.audits_frame_ends';

    /** @var string What `Queue::after()` records. */
    public const string JOB_PROCESSED = 'listener.job_processed';

    /** @var string What `Queue::failing()` records. */
    public const string JOB_FAILED = 'listener.job_failed';

    /** @var string What `Queue::exceptionOccurred()` records. */
    public const string JOB_EXCEPTION = 'listener.job_exception';

    /** @var string What a `CommandFinished` listener records. */
    public const string COMMAND_FINISHED = 'listener.command_finished';

    /**
     * Listen to the end of each job and command.
     *
     * @return void
     */
    public function boot(): void
    {
        Queue::after(fn (): null => $this->audit(self::JOB_PROCESSED));
        Queue::failing(fn (): null => $this->audit(self::JOB_FAILED));
        Queue::exceptionOccurred(fn (): null => $this->audit(self::JOB_EXCEPTION));

        Event::listen(CommandFinished::class, fn (CommandFinished $event): null => $event->command === RecordingCommand::NAME ? $this->audit(self::COMMAND_FINISHED) : null);
    }

    /**
     * Record the code, while the switch is on.
     *
     * @param  string  $code
     * @return null
     */
    private function audit(string $code): null
    {
        if ($this->app->make(Repository::class)->get(self::SWITCH) === true) {
            AuditLog::record($code);
        }

        return null;
    }
}
