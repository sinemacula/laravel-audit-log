<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane\Fixtures;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

/**
 * An Artisan command that records an activity, then fails when told to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingCommand extends Command
{
    /** @var string The command's name. */
    public const string NAME = 'reports:schedule';

    /** @var string The code the command records. */
    public const string CODE = 'report.scheduled';

    /** @var string The message the command fails with. */
    public const string MESSAGE = 'The report could not be scheduled.';

    /** @var string The name and signature of the console command. */
    protected $signature = self::NAME . ' {--fail : Fail once the activity is recorded}';

    /** @var string The console command description. */
    protected $description = 'Record an activity, and fail when told to.';

    /**
     * Record the activity, then fail when told to.
     *
     * @return int
     *
     * @throws \RuntimeException
     */
    public function handle(): int
    {
        AuditLog::record(self::CODE);

        if ($this->option('fail') === true) {
            throw new \RuntimeException(self::MESSAGE);
        }

        return self::SUCCESS;
    }
}
