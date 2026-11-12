<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Reconciler;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `audit-log:reconcile`: rewrites the lifecycle activity records the journal
 * holds but no entry records, for the last `--since` days.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:reconcile')]
final class ReconcileCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:reconcile'
        . ' {--since=' . Reconciler::DEFAULT_SINCE_DAYS . ' : The days to look back, from 1 to ' . Reconciler::MAX_SINCE_DAYS . '}'
        . ' {--json : Write the counts as one JSON object}';

    /** @var string The console command description. */
    protected $description = 'Write again the lifecycle activity records the journal says are missing';

    /**
     * Reconcile the days looked back and print the counts.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle  $lifecycle
     * @return int
     *
     * @throws \JsonException
     */
    public function handle(AuditLifecycle $lifecycle): int
    {
        try {
            $since = IntegerSetting::from('The --since option', $this->option('since'), 1, Reconciler::MAX_SINCE_DAYS);
        } catch (\InvalidArgumentException $refusal) {
            // The refusal names the option and its range, never what was given
            $this->error($refusal->getMessage());

            return self::INVALID;
        }

        try {
            $result = $lifecycle->reconcile($since);
        } catch (\Throwable $exception) {
            $this->error(sprintf('The reconciliation stopped with %s.', get_debug_type($exception)));

            return self::FAILURE;
        }

        if ($this->option('json') === true) {
            $this->output->writeln(json_encode($result->toArray(), JSON_THROW_ON_ERROR), OutputInterface::OUTPUT_RAW);
        } else {
            $this->line(sprintf(
                'Examined %d operations: recorded %d, already recorded %d, unverifiable %d, unfinished %d, failed %d.',
                $result->examined,
                $result->recorded,
                $result->alreadyRecorded,
                $result->unverifiable,
                $result->unfinished,
                $result->failed,
            ));
        }

        return $result->isComplete() ? self::SUCCESS : self::FAILURE;
    }
}
