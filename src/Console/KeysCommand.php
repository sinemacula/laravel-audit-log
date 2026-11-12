<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `audit-log:keys`: with `--rebuild-uses` adds every key use missing from the
 * verified entries, never removing one; `--dry-run` only counts.
 *
 * Key uses are an index derived from signed entries, so the rebuild needs no
 * authority and journals nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:keys')]
final class KeysCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:keys'
        . ' {--rebuild-uses : Add the key uses missing from the verified entries}'
        . ' {--dry-run : Count what the rebuild would add and change nothing}';

    /** @var string The console command description. */
    protected $description = 'Rebuild the key uses of the owners\' keys from the verified entries';

    /**
     * Rebuild the key uses, or count what a rebuild would add, and print it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle  $lifecycle
     * @return int
     */
    public function handle(AuditLifecycle $lifecycle): int
    {
        if ($this->option('rebuild-uses') !== true) {
            $this->error('The --rebuild-uses option is required: it is the only maintenance audit-log:keys runs.');

            return self::INVALID;
        }

        try {
            $result = $lifecycle->rebuildKeyUses($this->option('dry-run') === true);
        } catch (\Throwable $exception) {
            $this->error(sprintf('The key-use rebuild failed with %s.', get_debug_type($exception)));

            return self::FAILURE;
        }

        $this->line(sprintf('Read %d entries: %d verified, %d skipped.', $result->entries, $result->verified, $result->skipped));
        $this->line(sprintf($result->dryRun ? 'Would add %d key uses.' : 'Added %d key uses.', $result->added));

        return self::SUCCESS;
    }
}
