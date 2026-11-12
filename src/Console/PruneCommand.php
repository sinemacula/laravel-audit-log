<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneResult;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `audit-log:prune`: deletes the entries retention no longer keeps, journalling
 * each deletion; `--dry-run` only plans, and `--max-seconds` bounds the run.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:prune')]
final class PruneCommand extends Command
{
    /** @var int How many hexadecimal characters of a tenant's digest a plan shows. */
    private const int TENANT_DIGEST_LENGTH = 12;

    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:prune'
        . ' {--dry-run : Plan the run and change nothing}'
        . ' {--max-seconds= : Stop between chunks after this many seconds, from ' . RetentionSettings::LEAST_SECONDS . ' to ' . RetentionSettings::MOST_SECONDS . '}'
        . ' {--json : Write the result as one JSON object}';

    /** @var string The console command description. */
    protected $description = 'Prune the audit entries retention no longer keeps';

    /**
     * Run or plan the prune, then print what it did.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle  $lifecycle
     * @return int
     *
     * @throws \JsonException
     */
    public function handle(AuditLifecycle $lifecycle): int
    {
        try {
            $maxSeconds = $this->maxSeconds();
        } catch (\InvalidArgumentException $refusal) {
            // The refusal names the option and its range, never what was given
            $this->error($refusal->getMessage());

            return self::INVALID;
        }

        try {
            $result = $lifecycle->prune($this->option('dry-run') === true, $maxSeconds);
        } catch (\Throwable $exception) {
            $this->error(sprintf('The prune stopped with %s.', get_debug_type($exception)));

            return self::FAILURE;
        }

        if ($this->option('json') === true) {
            // Written raw, so nothing an id holds is read as a style
            $this->output->writeln(json_encode(self::arrayOf($result), JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE), OutputInterface::OUTPUT_RAW);
        } else {
            $this->printResult($result);
        }

        return self::exitCodeOf($result);
    }

    /**
     * The time budget the option gives, or `null` for the configured one.
     *
     * @return ?int
     *
     * @throws \InvalidArgumentException
     */
    private function maxSeconds(): ?int
    {
        $value = $this->option('max-seconds');

        return $value === null ? null : IntegerSetting::from('The --max-seconds option', $value, RetentionSettings::LEAST_SECONDS, RetentionSettings::MOST_SECONDS);
    }

    /**
     * Print how the run ended and its counts, then its plan for a dry run, and
     * a warning when its record could not be written.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneResult  $result
     * @return void
     */
    private function printResult(PruneResult $result): void
    {
        $status = $result->failure === null ? $result->status->value : sprintf('%s (%s)', $result->status->value, $result->failure);

        $this->line(sprintf('%s %s: %s.', $result->dryRun ? 'Dry run' : 'Run', $result->operationId, $status));

        if ($result->plan === null) {
            $this->line(sprintf('Deleted %d entries from %d seals.', $result->deleted, $result->seals));
        } else {
            $this->printPlan($result->plan);
        }

        $this->line(sprintf('Kept %d held and %d pending delivery.', $result->held, $result->pendingDelivery));
        $this->line(sprintf('Skipped %d seals%s.', $result->skippedSeals, $result->skippedSealIds === [] ? '' : ': ' . implode(', ', $result->skippedSealIds)));
        $this->line(sprintf('Cursor %d, %d seals remaining.', $result->cursor, $result->remaining));

        if ($result->dryRun || $result->recorded) {
            return;
        }

        $this->warn('The run\'s audit_log.pruned record could not be written; audit-log:reconcile writes it from the journal.');
    }

    /**
     * Print a dry run's plan: the totals, each category and tenant pair with
     * its cut-off, then each seal.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array{pairs: list<array{category: string, tenant_type: ?string, tenant_id: ?string, cutoff: ?string, eligible: int}>, seals: array<int, int>}  $plan
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function printPlan(array $plan): void
    {
        $this->line(sprintf('Would delete %d entries from %d seals.', array_sum(array_column($plan['pairs'], 'eligible')), count($plan['seals'])));

        foreach ($plan['pairs'] as $pair) {
            $digest = self::tenantDigestOf($pair['tenant_type'], $pair['tenant_id']);
            $tenant = $digest === null ? 'no tenant' : 'tenant ' . $digest;

            $this->line(sprintf('Plan %s, %s, cut-off %s: %d eligible.', $pair['category'], $tenant, $pair['cutoff'] ?? 'never', $pair['eligible']));
        }

        foreach ($plan['seals'] as $sequence => $eligible) {
            $this->line(sprintf('Plan seal %d: %d eligible.', $sequence, $eligible));
        }
    }

    /**
     * The result as `--json` writes it: its map, with each pair of a dry run's
     * plan naming its tenant by its digest rather than by its reference.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneResult  $result
     * @return array<string, array<array-key, array<array-key, array<string, int|string|null>|int>|int|string>|bool|int|string|null>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function arrayOf(PruneResult $result): array
    {
        $array = $result->toArray();

        if ($array['plan'] === null) {
            return $array;
        }

        $array['plan']['pairs'] = array_map(static fn (array $pair): array => [
            'category' => $pair['category'],
            'tenant'   => self::tenantDigestOf($pair['tenant_type'], $pair['tenant_id']),
            'cutoff'   => $pair['cutoff'],
            'eligible' => $pair['eligible'],
        ], $array['plan']['pairs']);

        return $array;
    }

    /**
     * The digest a plan names a tenant by: the first 12 hexadecimal characters
     * of the SHA-256 of its canonical type and id; `null` for no tenant.
     *
     * @param  ?string  $type
     * @param  ?string  $id
     * @return ?string
     */
    private static function tenantDigestOf(?string $type, ?string $id): ?string
    {
        if ($type === null || $id === null) {
            return null;
        }

        return substr(hash('sha256', CanonicalEncoder::encode([$type, $id])), 0, self::TENANT_DIGEST_LENGTH);
    }

    /**
     * The exit code the run earns: a failure for a failed run and for a run
     * that skipped a seal, and a success otherwise, a dry run's always.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneResult  $result
     * @return int
     */
    private static function exitCodeOf(PruneResult $result): int
    {
        if ($result->status === PruneStatus::FAILED || (!$result->dryRun && $result->skippedSeals > 0)) {
            return self::FAILURE;
        }

        return self::SUCCESS;
    }
}
