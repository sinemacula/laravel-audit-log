<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `audit-log:hold`: places a hold that keeps the entries its scope matches from
 * being pruned until it is released.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:hold')]
final class HoldCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:hold'
        . ' {--all : Start the scope from every entry}'
        . ' {--tenant=* : Start the scope from the entries of the tenant given as type:id}'
        . ' {--tenantless : Start the scope from, or add, the entries of no tenant}'
        . ' {--about=* : Keep only the activity of the reference given as type:id, as actor or subject}'
        . ' {--category=* : Keep only the category given}'
        . ' {--from= : Keep only what occurred at or after this time or date}'
        . ' {--to= : Keep only what occurred before this time or date}'
        . ' {--import-batch= : Keep only the entries of the import batch given}'
        . ' {--basis= : legal_claim, regulatory, investigation or other}'
        . ' {--review-by= : The time or date the hold is due for review}'
        . ' {--by-type= : The type of the operator placing the hold}'
        . ' {--by-id= : The id of the operator placing the hold}'
        . ' {--reason= : The reason code the hold is placed for}'
        . ' {--reference= : The ticket or case the hold answers to}';

    /** @var string The console command description. */
    protected $description = 'Place a hold that keeps audit entries from being pruned';

    /**
     * Place the hold the options describe and print its id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle  $lifecycle
     * @return int
     */
    public function handle(AuditLifecycle $lifecycle): int
    {
        try {
            $scope     = $this->scope();
            $basis     = $this->basis();
            $reviewBy  = $this->option('review-by');
            $reviewBy  = is_string($reviewBy) ? LifecycleOptions::instant('review-by', $reviewBy) : null;
            $authority = LifecycleOptions::authority($this);
        } catch (\InvalidArgumentException $refusal) {
            // Each refusal names the option or dimension, never what was given
            $this->error($refusal->getMessage());

            return self::INVALID;
        }

        try {
            $result = $lifecycle->hold($scope, $authority, $basis, $reviewBy);
        } catch (\Throwable $exception) {
            $this->error(sprintf('The hold was refused with %s.', get_debug_type($exception)));

            return self::FAILURE;
        }

        $this->line(sprintf('Placed hold %s.', $result->hold->id));

        if (!$result->recorded) {
            $this->warn('The hold\'s audit_log.held record could not be written; audit-log:reconcile writes it from the journal.');
        }

        return self::SUCCESS;
    }

    /**
     * The scope the options describe: started from exactly one of `--all`,
     * `--tenant` or `--tenantless`, then narrowed by each dimension given.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope
     *
     * @throws \InvalidArgumentException
     */
    private function scope(): HoldScope
    {
        $scope = $this->started();
        $about = $this->references('about');

        if ($about !== []) {
            $scope = $scope->about(...$about);
        }

        $categories = $this->strings('category');

        if ($categories !== []) {
            $scope = $scope->categories(...$categories);
        }

        $from = $this->option('from');
        $to   = $this->option('to');

        if (is_string($from) || is_string($to)) {
            $scope = $scope->occurredBetween(is_string($from) ? LifecycleOptions::instant('from', $from) : null, is_string($to) ? LifecycleOptions::instant('to', $to) : null);
        }

        $batch = $this->option('import-batch');

        return is_string($batch) ? $scope->importBatch($batch) : $scope;
    }

    /**
     * The scope the starting options give: every entry, the tenants' entries
     * with or without those of no tenant, or only those of no tenant.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope
     *
     * @throws \InvalidArgumentException
     */
    private function started(): HoldScope
    {
        $all        = $this->option('all')        === true;
        $tenantless = $this->option('tenantless') === true;
        $tenants    = $this->references('tenant');

        if ($all === ($tenants !== [] || $tenantless)) {
            throw new \InvalidArgumentException('Start the scope with exactly one of --all, --tenant or --tenantless; --tenant may take --tenantless too.');
        }

        return match (true) {
            $all            => HoldScope::all(),
            $tenants === [] => HoldScope::tenantless(),
            $tenantless     => HoldScope::tenants(...$tenants)->withTenantless(),
            default         => HoldScope::tenants(...$tenants),
        };
    }

    /**
     * The basis `--basis` names, which is required.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis
     *
     * @throws \InvalidArgumentException
     */
    private function basis(): HoldBasis
    {
        $basis = $this->option('basis');

        if (!is_string($basis)) {
            throw new \InvalidArgumentException('The --basis option is required.');
        }

        return LifecycleOptions::basis('basis', $basis);
    }

    /**
     * The references the option gives, each as `type:id`.
     *
     * @param  'about'|'tenant'  $option
     * @return list<\SineMacula\Laravel\AuditLog\Records\Reference>
     *
     * @throws \InvalidArgumentException
     */
    private function references(string $option): array
    {
        return array_map(static fn (string $value): Reference => LifecycleOptions::reference($option, $value), $this->strings($option));
    }

    /**
     * The values a repeatable option gives.
     *
     * @param  'about'|'category'|'tenant'  $option
     * @return list<string>
     */
    private function strings(string $option): array
    {
        $values = $this->option($option);

        return is_array($values) ? array_values(array_filter($values, is_string(...))) : [];
    }
}
