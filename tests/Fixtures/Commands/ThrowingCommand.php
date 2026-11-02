<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Commands;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

/**
 * A console command that records one activity and then throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ThrowingCommand extends Command
{
    /** @var string The command's name. */
    public const string NAME = 'audit-test:throw';

    /** @var string The code it records before it throws. */
    public const string CODE = 'command.throwing';

    /** @var string The message of what it throws. */
    public const string MESSAGE = 'The command failed.';

    /** @var string The name and signature of the console command. */
    protected $signature = self::NAME;

    /** @var string The console command description. */
    protected $description = 'Record one activity, then throw';

    /**
     * Record the activity, then throw.
     *
     * @return int
     *
     * @throws \RuntimeException
     */
    public function handle(): int
    {
        AuditLog::record(self::CODE);

        throw new \RuntimeException(self::MESSAGE);
    }
}
