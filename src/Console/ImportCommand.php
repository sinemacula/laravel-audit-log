<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportResult;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Records\SourceSettings;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `audit-log:import`: imports another system's records as accepted, never
 * witnessed, activity, or with `--close` marks a stopped batch `interrupted`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:import')]
final class ImportCommand extends Command
{
    /** @var string Pattern of a batch id: a lower-case UUID. */
    private const string BATCH_ID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var list<string> The options an import takes that a close does not. */
    private const array IMPORT_ONLY = ['source', 'region', 'from-export', 'dry-run', 'hold', 'hold-basis'];

    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:import'
        . ' {file? : The NDJSON file to import}'
        . ' {--source= : The id of the source that asserted the records}'
        . ' {--region= : The source\'s region}'
        . ' {--from-export : Read this package\'s own export lines}'
        . ' {--dry-run : Read, validate and classify, and write nothing}'
        . ' {--hold : Place a hold on the batch with its start}'
        . ' {--hold-basis= : The hold\'s basis: legal_claim, regulatory, investigation or other}'
        . ' {--close= : Mark the running batch given interrupted instead of importing}'
        . ' {--by-type= : The type of the operator importing}'
        . ' {--by-id= : The id of the operator importing}'
        . ' {--reason= : The reason code the import is made for}'
        . ' {--reference= : The ticket or case the import answers to}'
        . ' {--json : Write the result as one JSON object}';

    /** @var string The console command description. */
    protected $description = 'Import another system\'s audit records, or close an import that stopped';

    /**
     * Import the file, or close the batch, and print the result.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle  $lifecycle
     * @param  \SineMacula\Laravel\AuditLog\Records\SourceSettings  $sources
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public function handle(AuditLifecycle $lifecycle, SourceSettings $sources): int
    {
        try {
            $authority = LifecycleOptions::authority($this);
            $close     = $this->option('close');
            $work      = is_string($close) ? $this->closing($close) : $this->importing($sources);
        } catch (\InvalidArgumentException $refusal) {
            // A refusal never quotes a line of the file
            $this->error(self::shown($refusal->getMessage()));

            return self::INVALID;
        }

        try {
            $result = $work($lifecycle, $authority);
        } catch (\Throwable $exception) {
            $this->error(sprintf('The import stopped with %s.', get_debug_type($exception)));

            return self::FAILURE;
        }

        $this->printResult($result);

        return self::SUCCESS;
    }

    /**
     * The work of closing the batch the option names, given with no file and no
     * import option.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $batchId
     * @return \Closure(\SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle, \SineMacula\Laravel\AuditLog\Lifecycle\Authority): \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult
     *
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function closing(string $batchId): \Closure
    {
        $given = array_filter(self::IMPORT_ONLY, fn (string $option): bool => !in_array($this->option($option), [null, false], true));

        if ($this->argument('file') !== null || $given !== []) {
            throw new \InvalidArgumentException('The --close option takes no file and no other option of an import.');
        }

        if (preg_match(self::BATCH_ID_PATTERN, $batchId) !== 1) {
            throw new \InvalidArgumentException('The --close option must name a batch by its id, a lower-case UUID.');
        }

        return static fn (AuditLifecycle $lifecycle, Authority $authority): ImportResult => $lifecycle->closeImport($batchId, $authority);
    }

    /**
     * The work of importing the file from the source the options name, which is
     * never this installation.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\SourceSettings  $sources
     * @return \Closure(\SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle, \SineMacula\Laravel\AuditLog\Lifecycle\Authority): \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult
     *
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function importing(SourceSettings $sources): \Closure
    {
        $file   = $this->argument('file');
        $source = $this->option('source');

        if (!is_string($file) || !is_string($source)) {
            throw new \InvalidArgumentException('Name the file to import and its --source, or a batch to --close.');
        }

        if ($source === $sources->id()) {
            throw new \InvalidArgumentException('The --source option is never this installation\'s own source; its own records come back through audit-log:replay.');
        }

        $region   = $this->option('region');
        $region   = is_string($region) ? $region : null;
        $imported = $this->option('from-export') === true ? ImportSource::fromExport($file, $source, $region) : ImportSource::fromFile($file, $source, $region);
        $dryRun   = $this->option('dry-run')     === true;
        $hold     = $this->option('hold')        === true;
        $basis    = $this->holdBasis($hold);

        return static fn (AuditLifecycle $lifecycle, Authority $authority): ImportResult => $lifecycle->import($imported, $authority, $dryRun, $hold, $basis);
    }

    /**
     * The basis `--hold-basis` names, which goes only with `--hold`, or `other`
     * when it names none.
     *
     * @param  bool  $hold
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis
     *
     * @throws \InvalidArgumentException
     */
    private function holdBasis(bool $hold): HoldBasis
    {
        $basis = $this->option('hold-basis');

        if ($basis === null) {
            return HoldBasis::OTHER;
        }

        if (!$hold) {
            throw new \InvalidArgumentException('The --hold-basis option goes only with --hold.');
        }

        return LifecycleOptions::basis('hold-basis', is_string($basis) ? $basis : null);
    }

    /**
     * Print the batch, its counts and its notes, or with `--json` the result as
     * one JSON object.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult  $result
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function printResult(ImportResult $result): void
    {
        if ($this->option('json') === true) {
            // Written raw, so nothing an id holds is read as a style
            $this->output->writeln(json_encode($result->toArray(), JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE), OutputInterface::OUTPUT_RAW);

            return;
        }

        $this->line($result->dryRun ? 'Dry run: nothing was written.' : sprintf('Batch %s: %s.', $result->batchId, $result->status?->value));
        $this->line(sprintf(
            'Read %d lines: %s %d, duplicates %d, conflicts %d, rejected %d.',
            $result->linesRead,
            $result->dryRun ? 'would import' : 'imported',
            $result->imported,
            $result->duplicates,
            $result->conflicts,
            $result->rejected,
        ));

        foreach ($result->rejections as $reason => $count) {
            $this->line(sprintf('Rejected as %s: %d.', $reason, $count));
        }

        $this->printNotes($result);
    }

    /**
     * Print what the counts leave out.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult  $result
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function printNotes(ImportResult $result): void
    {
        if ($result->dropped > 0) {
            $this->line(sprintf('Dropped %d values shaped as an encrypted envelope.', $result->dropped));
        }

        if ($result->conflictIds !== []) {
            $this->line(sprintf('Conflicting source record ids: %s.', implode(', ', array_map(self::shown(...), $result->conflictIds))));
        }

        if ($result->pastRetention === null) {
            $this->warn('The lines past their retention on arrival could not be counted: the retention policy failed to answer.');
        }

        if ($result->pastRetention > 0) {
            $this->warn(sprintf('%d lines were past their retention on arrival; the next prune deletes them unless a hold keeps them.', $result->pastRetention));
        }

        if ($result->holdId !== null) {
            $this->line(sprintf('Hold %s keeps the batch.', $result->holdId));
        }

        if ($result->dryRun || $result->recorded) {
            return;
        }

        $this->warn('The import\'s activity records could not all be written; audit-log:reconcile writes them from the journal.');
    }

    /**
     * The text as a line shows it: repaired and stripped of control characters,
     * with nothing in it read as a style.
     *
     * @param  string  $text
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function shown(string $text): string
    {
        return OutputFormatter::escape(TextSanitizer::clean($text));
    }
}
