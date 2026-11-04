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
 * The privileged operations on the log's lifecycle: placing and releasing
 * holds, pruning what retention no longer keeps, importing another system's
 * records and closing an import that stopped, listing the active holds and
 * rebuilding their projection, erasing an owner, reinstating one, rewrapping
 * and rotating the owners' keys, erasing again after a restore, rebuilding the
 * key uses, and writing again the activity records the journal says are
 * missing.
 *
 * Each operation commits with the journal row that describes it, and its
 * activity record, `audit_log.held`, `audit_log.released`, `audit_log.pruned`,
 * `audit_log.imported`, `audit_log.subject_erased`, `audit_log.keys_reinstated`
 * or `audit_log.keys_rewrapped`, is written only after that commit, through
 * `LifecycleRecords`: a record that cannot be written never undoes the
 * operation, is reported, and shows as `recorded: false` on the result, and
 * `reconcile()` writes it later from the journal. "Fail closed" names the
 * recording attempt alone. A release of a hold that is not active, a refused
 * erasure and a reinstatement of an owner who is not erased are recorded
 * `denied` and rethrown; an import that fails once its start has committed is
 * recorded as a failure, after its hold, and an erasure or a rewrap that fails
 * is recorded as a failure, each then rethrown. A dry run commits nothing and
 * records nothing.
 *
 * The class authorises nothing: the authority is whoever the caller says it is,
 * and the boundary is the maintenance connection's credentials and the
 * application's own authorisation before it calls. Holds, prunes, erasures and
 * the journal make the destruction of entries and keys accountable, never
 * impossible: whoever holds the database credentials can still delete rows and
 * keys, or restore them, and the seals, the key rows' signatures and the
 * journal make that detectable.
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

        return new HoldResult($operationId, $this->records()->recordHeld($hold), $hold);
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

        return new ReleaseResult($operationId, $this->records()->recordReleased($operationId, $holdId, $authority, Outcome::SUCCESS), $hold);
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

        return $result->withRecorded($this->records()->recordPruned($result));
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

        $recorded = $this->records()->recordImported($result, $source->sourceId, $source->format->value, $authority);

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

        $recorded = $this->records()->recordImported($result, is_string($source) ? $source : null, is_string($format) ? $format : null, $authority);

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
     * Erase the owner on the authority given, all or nothing unless `$partial`
     * lets the keys nothing blocks go, refusing outbox rows older than the
     * erasure unless `$pending` accepts them, then record it. An owner already
     * erased that holds no key is recorded `already_erased`. A refusal, an
     * `ErasureRefusedException`, is recorded `denied` and rethrown; a failure,
     * a `JournalBrokenException` for a journal that does not verify, a
     * `LifecycleContentionException`, an `OwnerLockTimeoutException`, an
     * `InstallationMismatchException` or anything else, is recorded as one and
     * rethrown. The owner's fingerprint is taken first, so a ring that cannot
     * take it throws before anything is recorded.
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
     * Reinstate the erased owner on the authority given, so a key may be
     * created for the owner again above the floor of its erasure, then record
     * it. An owner who is not erased is recorded `denied` and its
     * `ReinstatementRefusedException` rethrown; any other failure, a
     * `JournalBrokenException` for a journal or a marker the verified chain
     * does not hold among them, is rethrown unrecorded.
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
     * Rewrap every owner's key onto the key wrapper's current wrapping key on
     * the authority given, and with `$rotate` supersede every live key, so the
     * next write of each unit opens its next generation; or with `$dryRun`
     * count what a run would do. Then, unless it was a dry run, record it: a
     * run that fails, with a `JournalBrokenException` or anything else, is
     * recorded as a failure and rethrown, and the batches it committed stand.
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
     * Erase again every owner the erasures file at the path names, after a
     * restore, on the authority given: each owner erased in part and accepting
     * pending deliveries, as `erase()` erases and records one, the run
     * confirming the installation once and carrying the verified journal from
     * owner to owner, and the restore journalled reconciled, with the anchor's
     * head, only once every owner is erased whole or was already.
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
     * Add the key uses missing from the entries whose signature verifies, on
     * the storage connection's writer, never removing one; or with `$dryRun`
     * count what a rebuild would add.
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
                $this->records()->recordReleased($operationId, $holdId, $authority, Outcome::DENIED);
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
     * The records of the operations' activity, each written after its operation
     * has committed.
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
