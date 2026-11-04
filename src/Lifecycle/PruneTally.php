<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;

/**
 * The running count of one prune: what its committed chunks deleted and kept,
 * the seals it skipped, where it got to, why it stopped, and, in a dry run, its
 * plan per pair and per seal; then the journal's finish row, the progress and
 * the result it ends with.
 *
 * Only a chunk whose transaction committed is counted, so a rolled-back or
 * retried attempt never shows in the counts. Nothing is kept per entry, and per
 * tenant only the pairs deleted from, so the tally grows with the categories,
 * the tenants and the skipped seals, never with the entries. The finish row
 * holds the distinct decisions of the run, at most 1,000, with the count beyond
 * them and a digest of every pair's decision, so it is bounded whatever the
 * tenants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PruneTally
{
    /** @var int The most distinct decisions a finish row holds. */
    public const int MAX_DECISIONS = 1000;

    /** @var array<string, int> The counts of the run, by their name in the journal and the progress. */
    private array $counts = ['deleted' => 0, 'seals' => 0, 'held' => 0, 'pending_delivery' => 0, 'skipped_seals' => 0, 'cursor' => 0, 'boundary' => 0];

    /** @var array<string, int> The entries deleted per category. */
    private array $categories = [];

    /** @var array<string, true> The tenant pairs deleted from, by their canonical encoding. */
    private array $tenants = [];

    /** @var list<string> The ids of the seals skipped, in the order they were skipped. */
    private array $skippedSealIds = [];

    /** @var array<string, array{category: string, tenant_type: ?string, tenant_id: ?string, cutoff: ?string, eligible: int}> A dry run's plan per pair, by the pair's canonical encoding, in the order first planned. */
    private array $pairs = [];

    /** @var array<int, int> A dry run's eligible entries per seal, by the seal's sequence. */
    private array $sealPlan = [];

    /** @var ?string The id of the last seal a committed chunk deleted from. */
    private ?string $lastTouched = null;

    /** @var ?string The version of the policy the run runs under, once read. */
    private ?string $policyVersion = null;

    /** @var bool Whether the run has committed its start row. */
    private bool $started = false;

    /** @var bool Whether the run stopped on its time budget. */
    private bool $stopped = false;

    /** @var ?string Why the run failed, once it has. */
    private ?string $failure = null;

    /** @var int The most entries one chunk deletes. */
    private int $batch = 1;

    /** @var int When the run's time budget ends, as a Unix time; never, until the run is limited. */
    private int $deadline = PHP_INT_MAX;

    /**
     * Constructor.
     *
     * @param  string  $runId
     * @param  bool  $dryRun
     */
    public function __construct(

        /** The run's id. */
        public readonly string $runId,

        /** Whether the run is a dry run. */
        public readonly bool $dryRun,
    ) {}

    /**
     * Note the run's policy version, cursor and boundary, and, when it is not a
     * dry run, that its start row committed.
     *
     * @param  string  $policyVersion
     * @param  int  $cursor
     * @param  int  $boundary
     * @return void
     */
    public function start(string $policyVersion, int $cursor, int $boundary): void
    {
        $this->policyVersion      = $policyVersion;
        $this->counts['cursor']   = $cursor;
        $this->counts['boundary'] = $boundary;
        $this->started            = !$this->dryRun;
    }

    /**
     * Limit the run: the most entries a chunk deletes, and how long it runs
     * from the Unix time it started before it stops between chunks.
     *
     * @param  int  $batch
     * @param  int  $maxSeconds
     * @param  int  $startedAt
     * @return void
     */
    public function limit(int $batch, int $maxSeconds, int $startedAt): void
    {
        $this->batch    = $batch;
        $this->deadline = $startedAt + $maxSeconds;
    }

    /**
     * The most entries one chunk deletes.
     *
     * @return int
     */
    public function batch(): int
    {
        return $this->batch;
    }

    /**
     * Whether the run's time budget has ended by the Unix time given.
     *
     * @param  int  $now
     * @return bool
     */
    public function isPastBudget(int $now): bool
    {
        return $now >= $this->deadline;
    }

    /**
     * Note the policy version the run read before it started, or failed.
     *
     * @param  string  $policyVersion
     * @return void
     */
    public function underPolicy(string $policyVersion): void
    {
        $this->policyVersion = $policyVersion;
    }

    /**
     * Note that the run walked the seal at the sequence to its end.
     *
     * @param  int  $sequence
     * @return void
     */
    public function walked(int $sequence): void
    {
        $this->counts['cursor'] = $sequence;
    }

    /**
     * Note that the run skipped the seal, by its id when it has one.
     *
     * @param  ?string  $sealId
     * @return void
     */
    public function skipped(?string $sealId): void
    {
        $this->counts['skipped_seals']++;

        if ($sealId === null || count($this->skippedSealIds) >= PruneResult::MAX_SKIPPED_IDS) {
            return;
        }

        $this->skippedSealIds[] = $sealId;
    }

    /**
     * Count a committed chunk of the seal: what it deleted, by the category and
     * tenant of each deleted entry's planned row, and what it kept.
     *
     * @param  string  $sealId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneChunkOutcome  $outcome
     * @param  array<string, array<string, scalar|null>>  $rows
     * @return void
     */
    public function committed(string $sealId, PruneChunkOutcome $outcome, #[\SensitiveParameter] array $rows): void
    {
        $this->counts['held']             += $outcome->held;
        $this->counts['pending_delivery'] += $outcome->pendingDelivery;

        if ($outcome->deleted === []) {
            return;
        }

        $this->counts['deleted'] += count($outcome->deleted);

        if ($this->lastTouched !== $sealId) {
            $this->counts['seals']++;
            $this->lastTouched = $sealId;
        }

        foreach ($outcome->deleted as $id) {
            $row      = $rows[$id] ?? [];
            $category = (string) ($row['category'] ?? '');

            $this->categories[$category] = ($this->categories[$category] ?? 0) + 1;

            if (!isset($row['tenant_type'], $row['tenant_id'])) {
                continue;
            }

            $this->tenants[CanonicalEncoder::encode([$row['tenant_type'], $row['tenant_id']])] = true;
        }
    }

    /**
     * Count an eligible entry of a dry run's plan, under its pair's decision
     * and its seal's sequence, as held when a hold keeps it.
     *
     * @param  int  $sequence
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecision  $decision
     * @param  bool  $held
     * @return void
     */
    public function planned(int $sequence, RetentionDecision $decision, bool $held): void
    {
        $pair = CanonicalEncoder::encode([$decision->category, $decision->tenant?->type, $decision->tenant?->id]);

        $this->pairs[$pair] ??= [
            'category'    => $decision->category,
            'tenant_type' => $decision->tenant?->type,
            'tenant_id'   => $decision->tenant?->id,
            'cutoff'      => $decision->cutoff,
            'eligible'    => 0,
        ];

        if ($held) {
            $this->counts['held']++;

            return;
        }

        $this->pairs[$pair]['eligible']++;
        $this->sealPlan[$sequence] = ($this->sealPlan[$sequence] ?? 0) + 1;
    }

    /**
     * Note that the run stopped on its time budget.
     *
     * @return void
     */
    public function stop(): void
    {
        $this->stopped = true;
    }

    /**
     * Note that the run failed, for the reason given.
     *
     * @param  'configuration_refused'|'journal_broken'|'policy_failed'|'prune_failed'  $reason
     * @return void
     */
    public function fail(string $reason): void
    {
        $this->failure ??= $reason;
    }

    /**
     * Whether the run committed its start row, so its finish row is owed.
     *
     * @return bool
     */
    public function hasStarted(): bool
    {
        return $this->started;
    }

    /**
     * How the run ends: failed once it has failed; partial when it stopped on
     * its time budget, skipped a seal, or left an eligible entry held or
     * awaiting delivery; complete otherwise.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus
     */
    public function status(): PruneStatus
    {
        return match (true) {
            $this->failure !== null => PruneStatus::FAILED,
            $this->stopped,
            $this->counts['skipped_seals']    > 0,
            $this->counts['held']             > 0,
            $this->counts['pending_delivery'] > 0 => PruneStatus::PARTIAL,
            default                               => PruneStatus::COMPLETE,
        };
    }

    /**
     * The payload of the run's finish row: its status and why it failed, its
     * counts, its cursor and what it left, its deletions per category, the
     * tenants it deleted from, and its decisions, bounded.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $decisions
     * @return array<string, array<array-key, array<array-key, int|string|null>|int>|int|string|null>
     */
    public function finishPayload(RetentionDecisions $decisions): array
    {
        $all      = $decisions->all();
        $distinct = self::distinct($all);

        return [
            'run_id'            => $this->runId,
            'phase'             => 'finish',
            'status'            => $this->status()->value,
            'failure'           => $this->failure,
            'deleted'           => $this->counts['deleted'],
            'seals'             => $this->counts['seals'],
            'held'              => $this->counts['held'],
            'pending_delivery'  => $this->counts['pending_delivery'],
            'skipped_seals'     => $this->counts['skipped_seals'],
            'cursor'            => $this->counts['cursor'],
            'remaining'         => $this->remaining(),
            'categories'        => PruneResult::bounded($this->categories),
            'tenants_affected'  => count($this->tenants),
            'pairs'             => count($all),
            'decisions'         => array_slice($distinct, 0, self::MAX_DECISIONS),
            'decisions_omitted' => max(0, count($distinct) - self::MAX_DECISIONS),
            'decisions_digest'  => hash('sha256', CanonicalEncoder::encode(array_map(static fn (RetentionDecision $decision): array => $decision->toArray(), $all))),
        ];
    }

    /**
     * The progress the run leaves under `retention.last_run`, as of the instant
     * given.
     *
     * @param  string  $at
     * @return array{at: string, run_id: string, status: string, deleted: int, cursor: int}
     */
    public function progress(string $at): array
    {
        return ['at' => $at, 'run_id' => $this->runId, 'status' => $this->status()->value, 'deleted' => $this->counts['deleted'], 'cursor' => $this->counts['cursor']];
    }

    /**
     * The run's result.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\PruneResult
     */
    public function result(): PruneResult
    {
        return new PruneResult(
            $this->runId,
            $this->started,
            $this->dryRun,
            $this->status(),
            $this->failure,
            $this->policyVersion,
            $this->counts['deleted'],
            $this->counts['seals'],
            $this->counts['held'],
            $this->counts['pending_delivery'],
            $this->counts['skipped_seals'],
            $this->counts['cursor'],
            $this->remaining(),
            $this->categories,
            count($this->tenants),
            $this->skippedSealIds,
            $this->dryRun ? ['pairs' => array_values($this->pairs), 'seals' => $this->sealPlan] : null,
        );
    }

    /**
     * How many seals from the cursor to the boundary the run did not walk.
     *
     * @return int
     */
    private function remaining(): int
    {
        return max(0, $this->counts['boundary'] - $this->counts['cursor']);
    }

    /**
     * The distinct decisions among those given, each as its category, the days
     * kept and preserved, its cut-off and the pairs that share it, sorted
     * bytewise by their canonical encoding.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecision>  $decisions
     * @return list<array{0: string, 1: ?int, 2: ?int, 3: ?string, 4: int}>
     */
    private static function distinct(array $decisions): array
    {
        $distinct = [];

        foreach ($decisions as $decision) {
            $key = CanonicalEncoder::encode([$decision->category, $decision->retainDays, $decision->preserveDays, $decision->cutoff]);

            $distinct[$key] ??= [$decision->category, $decision->retainDays, $decision->preserveDays, $decision->cutoff, 0];
            $distinct[$key][4]++;
        }

        ksort($distinct, SORT_STRING);

        return array_values($distinct);
    }
}
