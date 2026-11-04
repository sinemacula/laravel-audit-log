<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `audit-log:holds`: lists the active holds, replayed from the verified journal
 * under the lifecycle lock and never read from the holds projection, or with
 * `--rebuild` rebuilds the projection from the journal and says how many holds
 * it now holds.
 *
 * Each hold is shown by its id, its basis, when it was placed, its review date,
 * its scope's digest and the scope's dimensions: how many tenants and
 * references it names, whether it keeps the entries of no tenant, its
 * categories, its window and its import batch. The tenants and references
 * themselves are never printed. `--json` writes the listing, or the count, as
 * one JSON object instead.
 *
 * It exits 0 once it has listed or rebuilt, and 1 when the journal fails
 * verification or the lock cannot be taken, named by the class of the failure
 * alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:holds')]
final class HoldsCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:holds'
        . ' {--rebuild : Rebuild the holds projection from the journal}'
        . ' {--json : Write the result as one JSON object}';

    /** @var string The console command description. */
    protected $description = 'List the active holds on audit entries, or rebuild their projection';

    /**
     * List the active holds, or rebuild their projection, and print the result.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle  $lifecycle
     * @return int
     *
     * @throws \JsonException
     */
    public function handle(AuditLifecycle $lifecycle): int
    {
        $rebuild = $this->option('rebuild') === true;

        try {
            $result = $rebuild ? $lifecycle->rebuildHolds() : $lifecycle->holds();
        } catch (\Throwable $exception) {
            $this->error(sprintf('The holds could not be read: %s.', get_debug_type($exception)));

            return self::FAILURE;
        }

        if (is_int($result)) {
            $this->printRebuilt($result);

            return self::SUCCESS;
        }

        $this->printHolds($result);

        return self::SUCCESS;
    }

    /**
     * Print how many holds the rebuilt projection holds.
     *
     * @param  int  $count
     * @return void
     *
     * @throws \JsonException
     */
    private function printRebuilt(int $count): void
    {
        if ($this->option('json') === true) {
            $this->json(['rebuilt' => $count]);

            return;
        }

        $this->line(sprintf('The holds projection holds %d active holds.', $count));
    }

    /**
     * Print each active hold, or say there is none.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\Hold>  $holds
     * @return void
     *
     * @throws \JsonException
     */
    private function printHolds(array $holds): void
    {
        $listed = array_map(static fn (#[\SensitiveParameter] Hold $hold): array => self::listed($hold), $holds);

        if ($this->option('json') === true) {
            $this->json(['holds' => $listed]);

            return;
        }

        if ($listed === []) {
            $this->line('No hold is active.');

            return;
        }

        foreach ($listed as $hold) {
            $this->line(sprintf('%s %s, placed %s, review %s, scope %s.', $hold['id'], $hold['basis'], $hold['placed_at'], $hold['review_by'] ?? 'none', $hold['scope_digest']));
            $this->line('  ' . self::dimensions($hold['dimensions']));
        }
    }

    /**
     * Write the line as one JSON object.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array<string, int|list<array{id: string, basis: string, placed_at: string, review_by: ?string, scope_digest: string, dimensions: array<string, bool|int|list<string>|string|null>}>>  $line
     * @return void
     *
     * @throws \JsonException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function json(array $line): void
    {
        // Written raw, so nothing an id holds is read as a style
        $this->output->writeln(json_encode($line, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE), OutputInterface::OUTPUT_RAW);
    }

    /**
     * The hold as the listing shows it: its id, basis, placement, review date,
     * scope digest and the scope's dimensions, counting the tenants and the
     * references rather than naming them.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Hold  $hold
     * @return array{id: string, basis: string, placed_at: string, review_by: ?string, scope_digest: string, dimensions: array{tenants: ?int, tenantless: bool, about: ?int, categories: ?list<string>, from: ?string, to: ?string, import_batch: ?string}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function listed(#[\SensitiveParameter] Hold $hold): array
    {
        $scope = $hold->scope->toArray();

        return [
            'id'           => $hold->id,
            'basis'        => $hold->basis->value,
            'placed_at'    => $hold->placedAt,
            'review_by'    => $hold->reviewBy,
            'scope_digest' => $hold->scope->digest(),
            'dimensions'   => [
                'tenants'      => $scope['tenants'] === null ? null : count($scope['tenants']),
                'tenantless'   => $scope['tenantless'],
                'about'        => $scope['about'] === null ? null : count($scope['about']),
                'categories'   => $scope['categories'],
                'from'         => $scope['from'],
                'to'           => $scope['to'],
                'import_batch' => $scope['import_batch'],
            ],
        ];
    }

    /**
     * The scope's dimensions as a line shows them.
     *
     * @param  array{tenants: ?int, tenantless: bool, about: ?int, categories: ?list<string>, from: ?string, to: ?string, import_batch: ?string}  $dimensions
     * @return string
     */
    private static function dimensions(array $dimensions): string
    {
        return sprintf(
            'tenants %s, tenantless %s, about %s, categories %s, from %s, to %s, import batch %s.',
            $dimensions['tenants'] === null ? 'any' : (string) $dimensions['tenants'],
            $dimensions['tenantless'] ? 'kept' : 'not kept',
            $dimensions['about']      === null ? 'anyone' : (string) $dimensions['about'],
            $dimensions['categories'] === null ? 'any' : implode(' ', $dimensions['categories']),
            $dimensions['from']         ?? 'open',
            $dimensions['to']           ?? 'open',
            $dimensions['import_batch'] ?? 'any',
        );
    }
}
