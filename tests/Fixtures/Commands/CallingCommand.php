<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Commands;

use Illuminate\Console\Command;

/**
 * A console command that runs another through its own `$this->call()`, which
 * dispatches no console event, so the inner command never has a frame of its
 * own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CallingCommand extends Command
{
    /** @var string The command's name. */
    public const string NAME = 'audit-test:call';

    /** @var string The code the inner command records. */
    public const string INNER_CODE = 'command.called';

    /** @var string The name and signature of the console command. */
    protected $signature = self::NAME;

    /** @var string The console command description. */
    protected $description = 'Run the recording command through its own call';

    /**
     * Run the recording command.
     *
     * @return int
     */
    public function handle(): int
    {
        return $this->call(RecordingCommand::NAME, ['code' => self::INNER_CODE]);
    }
}
