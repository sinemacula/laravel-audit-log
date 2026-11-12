<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint;
use SineMacula\Laravel\AuditLog\Keys\KeyUseRebuilder;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The privileged operations on the log's lifecycle, each recording its activity
 * only after it commits; it authorises nothing and resolves services per call.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuditLifecycle
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolves every service an operation uses on each call. */
        private Container $container,
    ) {}

    /**
     * Place a hold of the scope, then record it.
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

        return new HoldResult($operationId, $this->records()->recordHeld($hold), $hold);
    }

    /**
     * Release the active hold, then record it; a hold that is not active is
     * recorded `denied` and refused.
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

        return new ReleaseResult($operationId, $this->records()->recordReleased($operationId, $holdId, $authority, Outcome::SUCCESS), $hold);
    }

    /**
     * Run a prune within the time budget, or the configured one, then record it
     * unless it was a dry run.
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

        return $result->withRecorded($this->records()->recordPruned($result));
    }

    /**
     * Import the source, or plan it as a dry run, optionally holding its batch;
     * a failure after the start committed is recorded and rethrown.
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

        $recorded = $this->records()->recordImported($result, $source->sourceId, $source->format->value, $authority);

        return $result->withRecorded($recorded && $held);
    }

    /**
     * Close the batch whose import stopped, then record it unless its import
     * had already journalled the finish.
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

        $recorded = $this->records()->recordImported($result, is_string($source) ? $source : null, is_string($format) ? $format : null, $authority);

        return $result->withRecorded($recorded);
    }

    /**
     * The active holds in placement order, replayed from the verified journal,
     * never read from the projection.
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
     * Rebuild the holds projection from the verified journal, returning how
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
     * Write again every activity record the journal says is missing within the
     * days looked back, 1 to 3650.
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
     * Erase the owner, all or nothing unless `$partial`, refusing older outbox
     * rows unless `$pending`; a refusal is recorded `denied` and rethrown.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  bool  $partial
     * @param  bool  $pending
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult
     *
     * @throws \Throwable
     */
    public function erase(#[\SensitiveParameter] Model|Reference $owner, Authority $authority, bool $partial = false, bool $pending = false): ErasureResult
    {
        $operationId = $this->operationId();
        $reference   = $owner instanceof Model ? Reference::to($owner) : $owner;
        $fingerprint = $this->container->make(OwnerFingerprint::class)->of($reference);

        return $this->records()->recordedErasure(
            $operationId,
            $fingerprint,
            $authority,
            fn (string $operationId): ErasureResult => $this->container->make(Eraser::class)->erase($operationId, $reference, $authority, $partial, $pending),
        );
    }

    /**
     * Reinstate the erased owner so a key may be created for it again, then
     * record it; an owner who is not erased is recorded `denied` and refused.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ReinstateResult
     *
     * @throws \Throwable
     */
    public function reinstate(#[\SensitiveParameter] Model|Reference $owner, Authority $authority): ReinstateResult
    {
        $operationId = $this->operationId();
        $reference   = $owner instanceof Model ? Reference::to($owner) : $owner;
        $fingerprint = $this->container->make(OwnerFingerprint::class)->of($reference);

        try {
            $result = $this->container->make(Reinstater::class)->reinstate($operationId, $reference, $authority);
        } catch (\Throwable $exception) {
            if ($exception instanceof ReinstatementRefusedException) {
                $this->records()->recordReinstatementRefused($operationId, $fingerprint, $authority);
            }

            throw $exception;
        }

        return $result->withRecorded($this->records()->recordReinstated($result, $authority));
    }

    /**
     * Rewrap every owner's key onto the current wrapping key, superseding every
     * live key with `$rotate`; a failed run keeps the batches it committed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  bool  $rotate
     * @param  bool  $dryRun
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\RewrapResult
     *
     * @throws \Throwable
     */
    public function rewrap(Authority $authority, bool $rotate = false, bool $dryRun = false): RewrapResult
    {
        $operationId = $this->operationId();

        try {
            $result = $this->container->make(Rewrapper::class)->rewrap($operationId, $authority, $rotate, $dryRun);
        } catch (\Throwable $exception) {
            if (!$dryRun) {
                $this->records()->recordRewrapFailed($operationId, $authority, $exception);
            }

            throw $exception;
        }

        return $dryRun ? $result : $result->withRecorded($this->records()->recordRewrapped($result, $authority));
    }

    /**
     * Erase again, after a restore, every owner the erasures file names,
     * journalling the restore reconciled once every owner is erased whole.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ReapplyResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     */
    public function reapplyErasures(string $path, Authority $authority): ReapplyResult
    {
        return $this->container->make(ErasureReapplier::class)->reapply(
            $this->operationId(),
            $path,
            $authority,
            fn (#[\SensitiveParameter] Reference $owner, ErasureRun $erasures): ErasureResult => $this->records()->recordedErasure(
                $this->operationId(),
                $this->container->make(OwnerFingerprint::class)->of($owner),
                $authority,
                fn (string $operationId): ErasureResult => $this->container->make(Eraser::class)->erase($operationId, $owner, $authority, true, true, $erasures),
            ),
        );
    }

    /**
     * Add the key uses missing from the entries whose signature verifies, never
     * removing one.
     *
     * @param  bool  $dryRun
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\KeyUseRebuildResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function rebuildKeyUses(bool $dryRun = false): KeyUseRebuildResult
    {
        return $this->container->make(KeyUseRebuilder::class)->rebuild($dryRun);
    }

    /**
     * Release the hold, recording a refusal `denied` before rethrowing it.
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
                $this->records()->recordReleased($operationId, $holdId, $authority, Outcome::DENIED);
            }

            throw $exception;
        }
    }

    /**
     * The import's result and whether its hold's record was written.
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
                $held    = $start->hold === null || $this->records()->recordHeld($start->hold);
            });
        } catch (\Throwable $exception) {
            if ($started instanceof ImportResult) {
                $this->records()->recordImported($this->failed($started), $source->sourceId, $source->format->value, $authority);
            }

            throw $exception;
        }

        return [$result, $held];
    }

    /**
     * The result of an import that failed after its start committed, with the
     * counts its batch row holds, or its start's when the row cannot be read.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult  $started
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult
     */
    private function failed(ImportResult $started): ImportResult
    {
        try {
            $batch = $started->batchId === null ? [] : $this->batch($started->batchId);
        } catch (\Throwable) {
            // Recorded with the start's counts; the journal holds the batch's
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
     * The stored row of the batch, or an empty array when it is not found.
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
     * A fresh UUID v7 operation id at the clock's time.
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
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecords
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function records(): LifecycleRecords
    {
        return $this->container->make(LifecycleRecords::class);
    }
}
