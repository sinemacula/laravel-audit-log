<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;

/**
 * Builds the evidence of each lifecycle operation's activity record, and has
 * `LifecycleRecorder` write it once the operation has committed: a hold, a
 * release, a prune, an import, an erasure, a reinstatement and a rewrap, each
 * with the properties its code retains, in that code's order, by the
 * authority's operator, or by no one for a prune.
 *
 * A refusal is recorded `denied` with the reason it names: a release of a hold
 * that is not active `unknown_hold`, an erasure by its refusal, and a
 * reinstatement of an owner who is not erased `not_erased`. A failure is
 * recorded `failure`: an import's `import_failed` or `interrupted`, a prune's
 * own reason, and an erasure's or a rewrap's `journal_broken` when the journal
 * did not verify, and `erasure_failed` or `rewrap_failed` for anything else, a
 * code and never the failure's message, since a failed statement's message
 * carries its bindings. A refused or failed operation wrote nothing, so its
 * record names no journal row and counts nothing it did not do.
 *
 * An erasure's `blocked` holds the reasons its kept keys were blocked by, or
 * the reasons a `blocked` refusal gave, each once and counted 1, at most 50,
 * sorted bytewise, with how many more there were under `_other`. An owner is
 * named by nothing but its keyed fingerprint and the id of the ring key it was
 * taken under, which are personal data while they can be linked to the owner.
 *
 * Each method answers whether the record was written; a record that was not is
 * reported once by the recorder and never undoes the operation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LifecycleRecords
{
    /** @var int The most reasons an erasure's `blocked` names; the rest are counted under `_other`. */
    public const int MAX_BLOCKED = 50;

    /** @var string The name the reasons beyond the first 50 are counted under, which no reason can have. */
    public const string OTHER = '_other';

    /** @var string The reason a release of a hold that is not active is recorded denied with. */
    private const string UNKNOWN_HOLD = 'unknown_hold';

    /** @var string The reason an import that failed is recorded with. */
    private const string IMPORT_FAILED = 'import_failed';

    /** @var string The reason a closed import is recorded with. */
    private const string INTERRUPTED = 'interrupted';

    /** @var string The reason an operation the verified journal refused is recorded with. */
    private const string JOURNAL_BROKEN = 'journal_broken';

    /** @var string The reason an erasure that failed otherwise is recorded with. */
    private const string ERASURE_FAILED = 'erasure_failed';

    /** @var string The reason a rewrap that failed otherwise is recorded with. */
    private const string REWRAP_FAILED = 'rewrap_failed';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecorder  $recorder
     */
    public function __construct(

        /** The writer of every record, after its operation has committed. */
        private LifecycleRecorder $recorder,
    ) {}

    /**
     * Record the hold placed, by its operator, and say whether the record was
     * written.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Hold  $hold
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public function recordHeld(#[\SensitiveParameter] Hold $hold): bool
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

        return $this->recorder->record(PackageActivity::HELD, $hold->operator, $evidence, Outcome::SUCCESS);
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
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public function recordReleased(string $operationId, string $holdId, Authority $authority, Outcome $outcome): bool
    {
        $evidence = new LifecycleEvidence([
            'operation_id'     => $operationId,
            'hold_id'          => $holdId,
            'authority_reason' => $authority->reason,
            'outcome'          => $outcome->value,
        ]);

        return $this->recorder->record(PackageActivity::RELEASED, $authority->operator, $evidence, $outcome, $outcome === Outcome::DENIED ? self::UNKNOWN_HOLD : null);
    }

    /**
     * Record the prune run, by no one: a success for a complete or partial run
     * and a failure, with its reason, for a failed one; and say whether the
     * record was written.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneResult  $result
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public function recordPruned(PruneResult $result): bool
    {
        $outcome  = $result->status === PruneStatus::FAILED ? Outcome::FAILURE : Outcome::SUCCESS;
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
            'outcome'          => $outcome->value,
        ]);

        return $this->recorder->record(PackageActivity::PRUNED, null, $evidence, $outcome, $outcome === Outcome::FAILURE ? $result->failure : null);
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
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public function recordImported(ImportResult $result, ?string $sourceId, ?string $format, Authority $authority): bool
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

        return $this->recorder->record(PackageActivity::IMPORTED, $authority->operator, $evidence, $outcome, $reason);
    }

    /**
     * The erasure the closure makes under the operation, recorded: one that
     * committed or found the owner already erased is recorded as such, and
     * anything it throws is recorded as a refusal or a failure about the owner
     * of the fingerprint given, then rethrown.
     *
     * @param  string  $operationId
     * @param  array{0: string, 1: string}  $fingerprint
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  \Closure(string): \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult  $erase
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult
     *
     * @throws \Throwable
     */
    public function recordedErasure(string $operationId, array $fingerprint, Authority $authority, #[\SensitiveParameter] \Closure $erase): ErasureResult
    {
        try {
            $result = $erase($operationId);
        } catch (\Throwable $exception) {
            $this->recordErasureRefused($operationId, $fingerprint, $authority, $exception);

            throw $exception;
        }

        return $result->withRecorded($this->recordErased($result, $authority));
    }

    /**
     * Record the erasure that committed, or found the owner already erased, by
     * the authority's operator, and say whether the record was written.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult  $result
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public function recordErased(ErasureResult $result, Authority $authority): bool
    {
        $evidence = new LifecycleEvidence([
            'operation_id'      => $result->operationId,
            'erasure_id'        => $result->erasureId,
            'owner_fingerprint' => $result->fingerprint,
            'fingerprint_key'   => $result->fingerprintKey,
            'status'            => $result->status->value,
            'keys_destroyed'    => $result->keysDestroyed,
            'keys_kept'         => $result->keysKept,
            'entries_affected'  => $result->entriesAffected,
            'blocked'           => self::blocked($result->blocked),
            'pending_accepted'  => $result->pendingAccepted,
            'authority_reason'  => $authority->reason,
            'outcome'           => Outcome::SUCCESS->value,
        ]);

        return $this->recorder->record(PackageActivity::SUBJECT_ERASED, $authority->operator, $evidence, Outcome::SUCCESS);
    }

    /**
     * Record the erasure that was refused, `denied` with its refusal, or that
     * failed, a `failure` with `journal_broken` or `erasure_failed`, about the
     * owner of the fingerprint given, by the authority's operator; and say
     * whether the record was written. A refusal's own fingerprint is preferred.
     *
     * @param  string  $operationId
     * @param  array{0: string, 1: string}  $fingerprint
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  \Throwable  $exception
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public function recordErasureRefused(string $operationId, array $fingerprint, Authority $authority, #[\SensitiveParameter] \Throwable $exception): bool
    {
        if ($exception instanceof ErasureRefusedException) {
            $refusal = $exception->refusal();
            $blocked = $refusal === ErasureRefusal::BLOCKED ? $exception->reasons() : [];

            return $this->recordUnerased($operationId, [$exception->fingerprintKey(), $exception->fingerprint()], $authority, Outcome::DENIED, $refusal->value, $blocked);
        }

        $reason = $exception instanceof JournalBrokenException ? self::JOURNAL_BROKEN : self::ERASURE_FAILED;

        return $this->recordUnerased($operationId, $fingerprint, $authority, Outcome::FAILURE, $reason, []);
    }

    /**
     * Record the reinstatement that committed, by the authority's operator, and
     * say whether the record was written.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ReinstateResult  $result
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public function recordReinstated(ReinstateResult $result, Authority $authority): bool
    {
        $evidence = new LifecycleEvidence([
            'operation_id'      => $result->operationId,
            'reinstatement_id'  => $result->reinstatementId,
            'owner_fingerprint' => $result->fingerprint,
            'fingerprint_key'   => $result->fingerprintKey,
            'generation_floor'  => $result->generationFloor,
            'authority_reason'  => $authority->reason,
            'outcome'           => Outcome::SUCCESS->value,
        ]);

        return $this->recorder->record(PackageActivity::KEYS_REINSTATED, $authority->operator, $evidence, Outcome::SUCCESS);
    }

    /**
     * Record the reinstatement refused because the owner of the fingerprint
     * given is not erased, `denied` with `not_erased`, by the authority's
     * operator, and say whether the record was written.
     *
     * @param  string  $operationId
     * @param  array{0: string, 1: string}  $fingerprint
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public function recordReinstatementRefused(string $operationId, array $fingerprint, Authority $authority): bool
    {
        $evidence = new LifecycleEvidence([
            'operation_id'      => $operationId,
            'reinstatement_id'  => null,
            'owner_fingerprint' => $fingerprint[1],
            'fingerprint_key'   => $fingerprint[0],
            'generation_floor'  => null,
            'authority_reason'  => $authority->reason,
            'outcome'           => Outcome::DENIED->value,
        ]);

        return $this->recorder->record(PackageActivity::KEYS_REINSTATED, $authority->operator, $evidence, Outcome::DENIED, ReinstatementRefusedException::NOT_ERASED);
    }

    /**
     * Record the rewrap that ended, complete or partial, by the authority's
     * operator, and say whether the record was written.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RewrapResult  $result
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public function recordRewrapped(RewrapResult $result, Authority $authority): bool
    {
        $evidence = new LifecycleEvidence([
            'operation_id'     => $result->operationId,
            'status'           => $result->status->value,
            'keys_rewrapped'   => $result->rewrapped,
            'keys_rotated'     => $result->rotated,
            'keys_skipped'     => $result->skipped,
            'wrap_key_id'      => $result->wrapKeyId,
            'batches'          => $result->batches,
            'authority_reason' => $authority->reason,
            'outcome'          => Outcome::SUCCESS->value,
        ]);

        return $this->recorder->record(PackageActivity::KEYS_REWRAPPED, $authority->operator, $evidence, Outcome::SUCCESS);
    }

    /**
     * Record the rewrap that failed, with `journal_broken` or `rewrap_failed`,
     * by the authority's operator, and say whether the record was written. The
     * batches it committed stand, and their journal rows count them; the record
     * counts nothing.
     *
     * @param  string  $operationId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  \Throwable  $exception
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public function recordRewrapFailed(string $operationId, Authority $authority, #[\SensitiveParameter] \Throwable $exception): bool
    {
        $evidence = new LifecycleEvidence([
            'operation_id'     => $operationId,
            'status'           => null,
            'keys_rewrapped'   => null,
            'keys_rotated'     => null,
            'keys_skipped'     => null,
            'wrap_key_id'      => null,
            'batches'          => null,
            'authority_reason' => $authority->reason,
            'outcome'          => Outcome::FAILURE->value,
        ]);

        $reason = $exception instanceof JournalBrokenException ? self::JOURNAL_BROKEN : self::REWRAP_FAILED;

        return $this->recorder->record(PackageActivity::KEYS_REWRAPPED, $authority->operator, $evidence, Outcome::FAILURE, $reason);
    }

    /**
     * The `blocked` an erasure's record keeps of the reasons: each once,
     * counted 1, the first 50 bytewise, and how many more there were under
     * `_other`.
     *
     * @param  list<string>  $reasons
     * @return array<string, int>
     */
    public static function blocked(array $reasons): array
    {
        $unique = array_values(array_unique($reasons));

        sort($unique, SORT_STRING);

        $named   = array_fill_keys(array_slice($unique, 0, self::MAX_BLOCKED), 1);
        $further = count($unique) - count($named);

        return $further > 0 ? [...$named, self::OTHER => $further] : $named;
    }

    /**
     * Record an erasure that wrote nothing, refused or failed, about the owner
     * of the fingerprint, with its outcome, its reason and the reasons it was
     * blocked by, and say whether the record was written.
     *
     * @param  string  $operationId
     * @param  array{0: string, 1: string}  $fingerprint
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  string  $reason
     * @param  list<string>  $blocked
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    private function recordUnerased(string $operationId, array $fingerprint, Authority $authority, Outcome $outcome, string $reason, array $blocked): bool
    {
        $evidence = new LifecycleEvidence([
            'operation_id'      => $operationId,
            'erasure_id'        => null,
            'owner_fingerprint' => $fingerprint[1],
            'fingerprint_key'   => $fingerprint[0],
            'status'            => null,
            'keys_destroyed'    => 0,
            'keys_kept'         => 0,
            'entries_affected'  => 0,
            'blocked'           => self::blocked($blocked),
            'pending_accepted'  => false,
            'authority_reason'  => $authority->reason,
            'outcome'           => $outcome->value,
        ]);

        return $this->recorder->record(PackageActivity::SUBJECT_ERASED, $authority->operator, $evidence, $outcome, $reason);
    }
}
