<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;

/**
 * The privileged operations on the log's lifecycle: placing and releasing
 * holds, pruning what retention no longer keeps, importing another system's
 * records and closing an import that stopped, listing the active holds and
 * rebuilding their projection, and writing again the activity records the
 * journal says are missing.
 *
 * Each operation commits with the journal row that describes it, and its
 * activity record, `audit_log.held`, `audit_log.released`, `audit_log.pruned`
 * or `audit_log.imported`, is written only after that commit: a record that
 * cannot be written never undoes the operation, is reported, and shows as
 * `recorded: false` on the result, and `reconcile()` writes it later from the
 * journal. "Fail closed" names the recording attempt alone. A release of a hold
 * that is not active is recorded `denied` and rethrown, and an import that
 * fails once its start has committed is recorded as a failure, after its hold,
 * and rethrown. A dry run commits nothing and records nothing.
 *
 * The class authorises nothing: the authority is whoever the caller says it is,
 * and the boundary is the maintenance connection's credentials and the
 * application's own authorisation before it calls. Holds, prunes and the
 * journal make the destruction of entries accountable, never impossible:
 * whoever holds the maintenance credentials can still delete rows, and the
 * seals and the journal make that detectable.
 *
 * Every operation resolves its services from the container on each call, so the
 * class outlives requests safely.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuditLifecycle
{
    /** @var string The reason a release of a hold that is not active is recorded denied with. */
    private const string UNKNOWN_HOLD = 'unknown_hold';

    /** @var string The reason an import that failed is recorded with. */
    private const string IMPORT_FAILED = 'import_failed';

    /** @var string The reason a closed import is recorded with. */
    private const string INTERRUPTED = 'interrupted';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container every service an operation uses is resolved from on each call. */
        private Container $container,
    ) {}

    /**
     * Place a hold of the scope, on the basis and with the review date given,
     * on the authority given, then record it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis  $basis
     * @param  ?\DateTimeInterface  $reviewBy
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\HoldResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function hold(#[\SensitiveParameter] HoldScope $scope, Authority $authority, HoldBasis $basis, ?\DateTimeInterface $reviewBy = null): HoldResult
    {
        $operationId = $this->operationId();
        $hold        = $this->container->make(HoldKeeper::class)->place($operationId, $scope, $authority, $basis, $reviewBy);

        return new HoldResult($operationId, $this->recordHeld($hold), $hold);
    }

    /**
     * Release the active hold of the id on the authority given, then record it.
     * A hold the verified journal does not hold active is recorded `denied` and
     * refused.
     *
     * @param  string  $holdId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ReleaseResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\UnknownHoldException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function release(string $holdId, Authority $authority): ReleaseResult
    {
        $operationId = $this->operationId();
        $hold        = $this->released($operationId, $holdId, $authority);

        return new ReleaseResult($operationId, $this->recordReleased($operationId, $holdId, $authority, Outcome::SUCCESS), $hold);
    }

    /**
     * Run a prune, or with `$dryRun` plan one, within the time budget given or
     * the configured one, then record it unless it was a dry run: a success for
     * a complete or partial run and a failure, with its reason, otherwise.
     *
     * @param  bool  $dryRun
     * @param  ?int  $maxSeconds
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\PruneResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function prune(bool $dryRun = false, ?int $maxSeconds = null): PruneResult
    {
        $result = $this->container->make(Pruner::class)->run($dryRun, $maxSeconds);

        if ($dryRun) {
            return $result;
        }

        $failed   = $result->status === PruneStatus::FAILED;
        $evidence = new LifecycleEvidence([
            'operation_id'     => $result->operationId,
            'status'           => $result->status->value,
            'policy_version'   => $result->policyVersion,
            'deleted'          => $result->deleted,
            'seals'            => $result->seals,
            'held'             => $result->held,
            'pending_delivery' => $result->pendingDelivery,
            'skipped_seals'    => $result->skippedSeals,
            'categories'       => $result->categories,
            'tenants_affected' => $result->tenantsAffected,
            'outcome'          => ($failed ? Outcome::FAILURE : Outcome::SUCCESS)->value,
        ]);

        $recorded = $this->recorder()->record(PackageActivity::PRUNED, null, $evidence, $failed ? Outcome::FAILURE : Outcome::SUCCESS, $failed ? $result->failure : null);

        return $result->withRecorded($recorded);
    }

    /**
     * Import the source on the authority given, or plan it as a dry run, with a
     * hold on its batch, of the basis given, placed with its start when one is
     * asked for; then, unless it was a dry run, record the hold once its start
     * has committed and the import once it ends. An import that fails after its
     * start committed is recorded as a failure and rethrown.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSource  $source
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  bool  $dryRun
     * @param  bool  $hold
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis  $basis
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     */
    public function import(ImportSource $source, Authority $authority, bool $dryRun = false, bool $hold = false, HoldBasis $basis = HoldBasis::OTHER): ImportResult
    {
        $importer = $this->container->make(AuditImporter::class);

        if ($dryRun) {
            return $importer->import($source, $authority, true);
        }

        [$result, $held] = $this->imported($importer, $source, $authority, $hold, $basis);

        $recorded = $this->recordImported($result, $source->sourceId, $source->format->value, $authority);

        return $result->withRecorded($recorded && $held);
    }

    /**
     * Close the batch whose import stopped, on the authority given: journal its
     * finish when the journal lacks it and make it final, then record it. A
     * batch whose finish its import had journalled already is made final with
     * that status and not recorded again, since the import's own record, or
     * `audit-log:reconcile`, records that finish.
     *
     * @param  string  $batchId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function closeImport(string $batchId, Authority $authority): ImportResult
    {
        $result = $this->container->make(AuditImporter::class)->close($batchId, $authority);

        if (!$result->committed) {
            return $result;
        }

        $batch  = $this->batch($batchId);
        $source = $batch['source_id']    ?? null;
        $format = $batch['input_format'] ?? null;

        $recorded = $this->recordImported($result, is_string($source) ? $source : null, is_string($format) ? $format : null, $authority);

        return $result->withRecorded($recorded);
    }

    /**
     * The active holds, in the order they were placed, replayed from the
     * verified journal under the lifecycle lock, never read from the
     * projection.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Lifecycle\Hold>
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function holds(): array
    {
        return $this->container->make(HoldKeeper::class)->active();
    }

    /**
     * Rebuild the holds projection from the verified journal, and return how
     * many holds it now holds.
     *
     * @return int
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function rebuildHolds(): int
    {
        return $this->container->make(HoldKeeper::class)->rebuild($this->operationId());
    }

    /**
     * Write again every activity record the journal says is missing, for the
     * operations journalled within the days looked back, from 1 to 3650, and
     * return the tally.
     *
     * @param  int  $sinceDays
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ReconcileResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function reconcile(int $sinceDays = Reconciler::DEFAULT_SINCE_DAYS): ReconcileResult
    {
        return $this->container->make(Reconciler::class)->reconcile($sinceDays);
    }

    /**
     * The hold of the id released on the authority given, under the operation;
     * a hold the verified journal does not hold active is recorded `denied`,
     * and its refusal rethrown, as is any other failure.
     *
     * @param  string  $operationId
     * @param  string  $holdId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Hold
     *
     * @throws \Throwable
     */
    private function released(string $operationId, string $holdId, Authority $authority): Hold
    {
        try {
            return $this->container->make(HoldKeeper::class)->release($operationId, $holdId, $authority);
        } catch (\Throwable $exception) {
            if ($exception instanceof UnknownHoldException) {
                $this->recordReleased($operationId, $holdId, $authority, Outcome::DENIED);
            }

            throw $exception;
        }
    }

    /**
     * The source imported on the authority given, with the hold asked for, and
     * whether the hold's record, when it placed one, was written once its start
     * committed; an import that fails after its start committed is recorded as
     * a failure and rethrown, as is any other failure.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\AuditImporter  $importer
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSource  $source
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  bool  $hold
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis  $basis
     * @return array{0: \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult, 1: bool}
     *
     * @throws \Throwable
     */
    private function imported(AuditImporter $importer, ImportSource $source, Authority $authority, bool $hold, HoldBasis $basis): array
    {
        $started = null;
        $held    = true;

        try {
            $result = $importer->import($source, $authority, false, $hold, $basis, function (ImportResult $start) use (&$started, &$held): void {
                $started = $start;
                $held    = $start->hold === null || $this->recordHeld($start->hold);
            });
        } catch (\Throwable $exception) {
            if ($started instanceof ImportResult) {
                $this->recordImported($this->failed($started), $source->sourceId, $source->format->value, $authority);
            }

            throw $exception;
        }

        return [$result, $held];
    }

    /**
     * Record the hold placed, by its operator, and say whether the record was
     * written.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Hold  $hold
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    private function recordHeld(#[\SensitiveParameter] Hold $hold): bool
    {
        $evidence = new LifecycleEvidence([
            'operation_id'     => $hold->operationId,
            'hold_id'          => $hold->id,
            'basis'            => $hold->basis->value,
            'scope_digest'     => $hold->scope->digest(),
            'review_by'        => $hold->reviewBy,
            'authority_reason' => $hold->reason,
            'outcome'          => Outcome::SUCCESS->value,
        ]);

        return $this->recorder()->record(PackageActivity::HELD, $hold->operator, $evidence, Outcome::SUCCESS);
    }

    /**
     * Record the release of the hold, or its refusal, by the authority's
     * operator, and say whether the record was written.
     *
     * @param  string  $operationId
     * @param  string  $holdId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    private function recordReleased(string $operationId, string $holdId, Authority $authority, Outcome $outcome): bool
    {
        $evidence = new LifecycleEvidence([
            'operation_id'     => $operationId,
            'hold_id'          => $holdId,
            'authority_reason' => $authority->reason,
            'outcome'          => $outcome->value,
        ]);

        return $this->recorder()->record(PackageActivity::RELEASED, $authority->operator, $evidence, $outcome, $outcome === Outcome::DENIED ? self::UNKNOWN_HOLD : null);
    }

    /**
     * Record the import, or the close of its batch, by the authority's
     * operator: a success for a complete or partial batch, and a failure, with
     * its reason, for a failed or interrupted one; and say whether the record
     * was written.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult  $result
     * @param  ?string  $sourceId
     * @param  ?string  $format
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    private function recordImported(ImportResult $result, ?string $sourceId, ?string $format, Authority $authority): bool
    {
        $reason = match ($result->status) {
            ImportStatus::FAILED      => self::IMPORT_FAILED,
            ImportStatus::INTERRUPTED => self::INTERRUPTED,
            default                   => null,
        };

        $outcome  = $reason === null ? Outcome::SUCCESS : Outcome::FAILURE;
        $evidence = new LifecycleEvidence([
            'operation_id'     => $result->operationId,
            'batch_id'         => $result->batchId,
            'source_id'        => $sourceId,
            'format'           => $format,
            'status'           => $result->status?->value,
            'lines_read'       => $result->linesRead,
            'imported'         => $result->imported,
            'duplicates'       => $result->duplicates,
            'conflicts'        => $result->conflicts,
            'rejected'         => $result->rejected,
            'hold_id'          => $result->holdId,
            'authority_reason' => $authority->reason,
            'outcome'          => $outcome->value,
        ]);

        return $this->recorder()->record(PackageActivity::IMPORTED, $authority->operator, $evidence, $outcome, $reason);
    }

    /**
     * The result of the import whose start committed and which then failed: its
     * batch `failed`, with the counts its batch row holds, or those of its
     * start when the row cannot be read.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult  $started
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult
     */
    private function failed(ImportResult $started): ImportResult
    {
        try {
            $batch = $started->batchId === null ? [] : $this->batch($started->batchId);
        } catch (\Throwable) {
            // The failure is recorded all the same, with the counts the start
            // had, since the journal holds the batch's own
            $batch = [];
        }

        $count = static fn (string $column, int $started): int => IntegerSetting::parse($batch[$column] ?? null) ?? $started;

        return new ImportResult(
            operationId: $started->operationId,
            committed: true,
            recorded: false,
            dryRun: false,
            batchId: $started->batchId,
            status: ImportStatus::FAILED,
            holdId: $started->holdId,
            hold: $started->hold,
            linesRead: $count('lines_read', $started->linesRead),
            imported: $count('imported', $started->imported),
            duplicates: $count('duplicates', $started->duplicates),
            conflicts: $count('conflicts', $started->conflicts),
            rejected: $count('rejected', $started->rejected),
            rejections: $started->rejections,
            conflictIds: $started->conflictIds,
            pastRetention: $started->pastRetention,
            dropped: $started->dropped,
        );
    }

    /**
     * The stored row of the batch, or none when it cannot be found.
     *
     * @param  string  $batchId
     * @return array<string, scalar|null>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function batch(string $batchId): array
    {
        return $this->container->make(ImportBatches::class)->find($batchId) ?? [];
    }

    /**
     * A fresh operation id: a UUID v7 of the clock's time.
     *
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function operationId(): string
    {
        return Str::uuid7($this->container->make(Clock::class)->now())->toString();
    }

    /**
     * The writer of the operations' activity records.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecorder
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function recorder(): LifecycleRecorder
    {
        return $this->container->make(LifecycleRecorder::class);
    }
}
