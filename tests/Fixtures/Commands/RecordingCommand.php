<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Commands;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

/**
 * A console command that records one activity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingCommand extends Command
{
    /** @var string The command's name. */
    public const string NAME = 'audit-test:record';

    /** @var string The code it records unless it is given another. */
    public const string CODE = 'command.recorded';

    /** @var string The name and signature of the console command. */
    protected $signature = self::NAME . ' {code=' . self::CODE . '}';

    /** @var string The console command description. */
    protected $description = 'Record one activity';

    /**
     * Record the activity.
     *
     * @return int
     */
    public function handle(): int
    {
        $code = $this->argument('code');

        AuditLog::record(is_string($code) ? $code : self::CODE);

        return self::SUCCESS;
    }
}
