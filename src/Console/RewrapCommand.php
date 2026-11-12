<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\RewrapResult;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Formatter\OutputFormatter;

/**
 * `audit-log:rewrap`: rewraps every owner's key onto the current wrapping key
 * in journalled batches; `--rotate` also supersedes live keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:rewrap')]
final class RewrapCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:rewrap'
        . ' {--by-type= : The type of the operator rewrapping the keys}'
        . ' {--by-id= : The id of the operator rewrapping the keys}'
        . ' {--reason= : The reason code the keys are rewrapped for}'
        . ' {--reference= : The ticket or case the rewrap answers to}'
        . ' {--rotate : Also supersede every live key, so each unit opens a new generation}'
        . ' {--dry-run : Count what a run would do and change nothing}';

    /** @var string The console command description. */
    protected $description = 'Rewrap the owners\' keys onto the current wrapping key';

    /**
     * Rewrap the keys, or count what a run would do, and print the result.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle  $lifecycle
     * @return int
     */
    public function handle(AuditLifecycle $lifecycle): int
    {
        try {
            $authority = LifecycleOptions::authority($this);
        } catch (\InvalidArgumentException $refusal) {
            // Each refusal names the option, never what was given
            $this->error($refusal->getMessage());

            return self::INVALID;
        }

        try {
            $result = $lifecycle->rewrap($authority, $this->option('rotate') === true, $this->option('dry-run') === true);
        } catch (\Throwable $exception) {
            $this->error(sprintf('The rewrap failed with %s; the batches it committed stand.', get_debug_type($exception)));

            return self::FAILURE;
        }

        $this->printResult($result);

        return self::SUCCESS;
    }

    /**
     * Print how the run ended, its counts and skipped keys, and a warning when
     * its record could not be written.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RewrapResult  $result
     * @return void
     */
    private function printResult(RewrapResult $result): void
    {
        $this->line(sprintf('%s %s: %s.', $result->dryRun ? 'Dry run' : 'Rewrap', $result->operationId, $result->status->value));
        $this->line(sprintf(
            '%s %d keys onto wrapping key %s, superseded %d and skipped %d, in %d batches.',
            $result->dryRun ? 'Would rewrap' : 'Rewrapped',
            $result->rewrapped,
            $result->wrapKeyId,
            $result->rotated,
            $result->skipped,
            $result->batches,
        ));

        if ($result->skippedKeyIds !== []) {
            $ids = array_map(static fn (string $id): string => OutputFormatter::escape(TextSanitizer::clean($id)), $result->skippedKeyIds);

            $this->line(sprintf('Skipped keys: %s.', implode(', ', $ids)));
        }

        if ($result->dryRun || $result->recorded) {
            return;
        }

        $this->warn('The rewrap\'s audit_log.keys_rewrapped record could not be written; audit-log:reconcile writes it from the journal.');
    }
}
