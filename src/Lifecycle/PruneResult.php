<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;

/**
 * What a prune run did, or for a dry run would do; once `committed`, the chunks
 * it committed stand whatever followed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, array<array-key, array<array-key, array<array-key, int|string|null>|int>|int|string>|bool|int|string|null>
 */
final readonly class PruneResult implements Arrayable
{
    /** @var int The most categories counted by name; the rest are summed under `_other`. */
    public const int MAX_CATEGORIES = 50;

    /** @var string The name the categories beyond the largest are summed under, which no category can have. */
    public const string OTHER = '_other';

    /** @var int The most skipped seals named by id. */
    public const int MAX_SKIPPED_IDS = 100;

    /** @var array<string, int> The entries deleted per category, the 50 largest by name and the rest under `_other`. */
    public array $categories;

    /** @var list<string> The ids of the seals the run skipped, at most 100, in the order it skipped them. */
    public array $skippedSealIds;

    /**
     * Constructor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $operationId
     * @param  bool  $committed
     * @param  bool  $dryRun
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus  $status
     * @param  ?string  $failure
     * @param  ?string  $policyVersion
     * @param  int  $deleted
     * @param  int  $seals
     * @param  int  $held
     * @param  int  $pendingDelivery
     * @param  int  $skippedSeals
     * @param  int  $cursor
     * @param  int  $remaining
     * @param  array<string, int>  $categories
     * @param  int  $tenantsAffected
     * @param  list<string>  $skippedSealIds
     * @param  ?array{pairs: list<array{category: string, tenant_type: ?string, tenant_id: ?string, cutoff: ?string, eligible: int}>, seals: array<int, int>}  $plan
     * @param  bool  $recorded
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The run's id, which every journal row of the run and its record name. */
        public string $operationId,

        /** Whether the run committed its start row: `false` for a dry run and a run that failed before it. */
        public bool $committed,

        /** Whether the run was a dry run, which writes nothing. */
        public bool $dryRun,

        /** How the run ended. */
        public PruneStatus $status,

        /** Why the run failed (`policy_failed`, `configuration_refused`, `journal_broken` or `prune_failed`), or `null`. */
        public ?string $failure,

        /** The version of the policy the run ran under, or `null` when it failed before it was read. */
        public ?string $policyVersion,

        /** How many entries the run deleted. */
        public int $deleted,

        /** How many seals the run deleted entries of. */
        public int $seals,

        /** How many eligible entries an active hold kept. */
        public int $held,

        /** How many eligible entries an outbox row or an undelivered receipt kept. */
        public int $pendingDelivery,

        /** How many seals the run skipped as unauthenticated or with deletes that kept mismatching. */
        public int $skippedSeals,

        /** The sequence of the last seal walked to its end, which the next run resumes after. */
        public int $cursor,

        /** How many seals from the cursor to the run's boundary it did not walk. */
        public int $remaining,

        // Not promoted: bounded before it is kept
        array $categories,

        /** How many tenants the run deleted entries of. */
        public int $tenantsAffected,

        // Not promoted: bounded before it is kept
        array $skippedSealIds,

        /** The plan of a dry run, per pair and per seal, or `null` for a run that is not one. */
        public ?array $plan = null,

        /** Whether the run's `audit_log.pruned` record was written. */
        public bool $recorded = false,
    ) {
        $this->categories     = self::bounded($categories);
        $this->skippedSealIds = array_slice($skippedSealIds, 0, self::MAX_SKIPPED_IDS);
    }

    /**
     * The 50 largest counts by name, ties bytewise, and the rest summed under
     * `_other`.
     *
     * @param  array<string, int>  $categories
     * @return array<string, int>
     *
     * @internal
     */
    public static function bounded(array $categories): array
    {
        $summed = array_key_exists(self::OTHER, $categories);
        $other  = $categories[self::OTHER] ?? 0;

        unset($categories[self::OTHER]);

        $named = array_keys($categories);

        usort($named, static fn (string $left, string $right): int => ($categories[$right] <=> $categories[$left]) ?: strcmp($left, $right));

        $bounded = [];

        foreach ($named as $index => $category) {
            if ($index < self::MAX_CATEGORIES) {
                $bounded[$category] = $categories[$category];

                continue;
            }

            $summed = true;
            $other += $categories[$category];
        }

        return $summed ? [...$bounded, self::OTHER => $other] : $bounded;
    }

    /**
     * The result with whether its record was written.
     *
     * @param  bool  $recorded
     * @return self
     *
     * @internal
     */
    public function withRecorded(bool $recorded): self
    {
        return new self(
            $this->operationId,
            $this->committed,
            $this->dryRun,
            $this->status,
            $this->failure,
            $this->policyVersion,
            $this->deleted,
            $this->seals,
            $this->held,
            $this->pendingDelivery,
            $this->skippedSeals,
            $this->cursor,
            $this->remaining,
            $this->categories,
            $this->tenantsAffected,
            $this->skippedSealIds,
            $this->plan,
            $recorded,
        );
    }

    /**
     * The result as a map, under snake-case keys.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{operation_id: string, committed: bool, recorded: bool, dry_run: bool, status: string, failure: ?string, policy_version: ?string, deleted: int, seals: int, held: int, pending_delivery: int, skipped_seals: int, skipped_seal_ids: list<string>, cursor: int, remaining: int, categories: array<string, int>, tenants_affected: int, plan: ?array{pairs: list<array{category: string, tenant_type: ?string, tenant_id: ?string, cutoff: ?string, eligible: int}>, seals: array<int, int>}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'operation_id'     => $this->operationId,
            'committed'        => $this->committed,
            'recorded'         => $this->recorded,
            'dry_run'          => $this->dryRun,
            'status'           => $this->status->value,
            'failure'          => $this->failure,
            'policy_version'   => $this->policyVersion,
            'deleted'          => $this->deleted,
            'seals'            => $this->seals,
            'held'             => $this->held,
            'pending_delivery' => $this->pendingDelivery,
            'skipped_seals'    => $this->skippedSeals,
            'skipped_seal_ids' => $this->skippedSealIds,
            'cursor'           => $this->cursor,
            'remaining'        => $this->remaining,
            'categories'       => $this->categories,
            'tenants_affected' => $this->tenantsAffected,
            'plan'             => $this->plan,
        ];
    }
}
