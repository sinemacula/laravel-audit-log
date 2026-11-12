<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Delivery\ReplayResult;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `audit-log:replay`: replays the signed records of a spill file, the outbox's
 * failed rows, or both, the spill first; `--dry-run` changes nothing.
 *
 * An unsigned line is never replayed, since signing editable bytes cannot
 * establish where they came from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:replay')]
final class ReplayCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:replay {--outbox : Requeue the failed rows of the outbox and drain} {--spill= : A spill file to replay} {--dry-run : Change nothing}';

    /** @var string The console command description. */
    protected $description = 'Replay the audit records a failed write left in a spill file or the outbox';

    /**
     * Replay what the options name, then print each run's tally.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Replayer  $replayer
     * @return int
     */
    public function handle(Replayer $replayer): int
    {
        $path   = $this->option('spill');
        $outbox = $this->option('outbox')  === true;
        $dryRun = $this->option('dry-run') === true;

        if (!is_string($path) && !$outbox) {
            $this->error('Say what to replay: --spill with the path of a file, --outbox, or both.');

            return self::INVALID;
        }

        $spillExit  = is_string($path) ? $this->replay('Spill', static fn (): ReplayResult => $replayer->spill($path, $dryRun)) : self::SUCCESS;
        $outboxExit = $outbox ? $this->replay('Outbox', static fn (): ReplayResult => $replayer->outbox($dryRun)) : self::SUCCESS;

        return max($spillExit, $outboxExit);
    }

    /**
     * Run one replay and print how it ended, returning the exit code it earns.
     *
     * @param  string  $source
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Delivery\ReplayResult  $work
     * @return int
     */
    private function replay(string $source, #[\SensitiveParameter] \Closure $work): int
    {
        try {
            $result = $work();
        } catch (\InvalidArgumentException $exception) {
            // The package's refusals of an argument name a path or a setting,
            // never a value of a record
            $this->error($exception->getMessage());

            return self::FAILURE;
        } catch (\Throwable $exception) {
            $this->error(sprintf('The %s replay stopped with %s.', strtolower($source), get_debug_type($exception)));

            return self::FAILURE;
        }

        $this->printResult($source, $result);

        return $result->hasSkippedOrFailed() ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Print the replay's counts, then each failure it skipped lines for, then
     * its events.
     *
     * @param  string  $source
     * @param  \SineMacula\Laravel\AuditLog\Delivery\ReplayResult  $result
     * @return void
     */
    private function printResult(string $source, ReplayResult $result): void
    {
        $this->line(sprintf(
            '%s: replayed %d, would replay %d, pruned %d, failed %d, deferred %d, skipped %d.',
            $source,
            $result->replayed(),
            $result->wouldReplay(),
            $result->pruned(),
            $result->failed(),
            $result->deferred(),
            array_sum($result->skipped()),
        ));

        foreach ($result->skipped() as $failure => $count) {
            $this->line(sprintf('Skipped as %s: %d.', $failure, $count));
        }

        foreach ($result->events() as $event) {
            $this->line($event);
        }

        if ($result->omittedEvents() === 0) {
            return;
        }

        $this->line(sprintf('And %d more.', $result->omittedEvents()));
    }
}
