<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Commands;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

/**
 * A console command that records one activity, runs what a test gives it (a
 * nested Artisan call, a sync-queue job), and records another: what it records
 * after shows the frame it got back, whether the inner work succeeded or threw.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class NestingCommand extends Command
{
    /** @var string The command's name. */
    public const string NAME = 'audit-test:nest';

    /** @var string The code it records before the inner work. */
    public const string BEFORE = 'command.before_inner';

    /** @var string The code it records after the inner work. */
    public const string AFTER = 'command.after_inner';

    /** @var string The name and signature of the console command. */
    protected $signature = self::NAME;

    /** @var string The console command description. */
    protected $description = 'Record, run the inner work, and record again';

    /**
     * Constructor.
     *
     * @param  \Closure(): void  $inner
     */
    public function __construct(

        /** The inner work. */
        private readonly \Closure $inner,
    ) {
        parent::__construct();
    }

    /**
     * Record, run the inner work, and record again.
     *
     * @return int
     */
    public function handle(): int
    {
        AuditLog::record(self::BEFORE);

        try {
            ($this->inner)();
        } catch (\RuntimeException) {
            // Inner work that throws is one of the things under test; what
            // matters is the frame this command has afterwards
        }

        AuditLog::record(self::AFTER);

        return self::SUCCESS;
    }
}
