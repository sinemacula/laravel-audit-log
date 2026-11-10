<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\RewrapStatus;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Builds, from verified journal rows, the record each lifecycle operation
 * needs, for `Reconciler` to write when no entry holds it: a hold, a release, a
 * prune run, an import, an erasure, a reinstatement and a rewrap run, each with
 * exactly the properties its code retains and the operation would have
 * recorded, by the row's operator, or by no one for a prune, with its outcome
 * and reason.
 *
 * A builder answers `null` for a row, or a start row it needs, that does not
 * describe its operation, so the reconciler counts it unverifiable and never
 * records it. Only a committed operation is journalled, so every record here is
 * a success but a failed prune or import; a refusal wrote no row, and is never
 * reconciled. A rewrap run is journalled a batch to a row, so its record sums
 * the rows of its operation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReconciledOperations
{
    /** @var list<string> The reasons a failed prune's record may give. */
    private const array PRUNE_FAILURES = ['policy_failed', 'configuration_refused', 'journal_broken', 'prune_failed'];

    /** @var array<string, ?string> The reason each status of an import's finish gives its record, `null` for a success. */
    private const array IMPORT_STATUSES = ['complete' => null, 'partial' => null, 'failed' => 'import_failed', 'interrupted' => 'interrupted'];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The record of a hold: its operation, its id, basis, scope digest and
     * review date, the authority's reason, by its operator; `null` when the row
     * and its payload do not describe a hold.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  array<array-key, mixed>  $payload
     * @return ?array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: ?\SineMacula\Laravel\AuditLog\Records\Reference, 2: \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence, 3: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 4: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function held(#[\SensitiveParameter] JournalRow $row, #[\SensitiveParameter] array $payload): ?array
    {
        $scope    = $payload['scope'] ?? null;
        $basis    = is_string($payload['basis'] ?? null) ? HoldBasis::tryFrom($payload['basis']) : null;
        $reviewBy = $payload['review_by'] ?? null;
        $named    = $row->holdId !== null && ($payload['hold_id'] ?? null) === $row->holdId;
        $reviewed = $reviewBy                                              === null || is_string($reviewBy);

        if (!$named || !$reviewed || $basis === null || !is_array($scope)) {
            return null;
        }

        try {
            $digest = HoldScope::fromArray($scope)->digest();
        } catch (\UnexpectedValueException) {
            return null;
        }

        return self::operation(PackageActivity::HELD, $row, [
            'operation_id'     => $row->operationId,
            'hold_id'          => $row->holdId,
            'basis'            => $basis->value,
            'scope_digest'     => $digest,
            'review_by'        => $reviewBy,
            'authority_reason' => $row->reason,
            'outcome'          => Outcome::SUCCESS->value,
        ], Outcome::SUCCESS, null);
    }

    /**
     * The record of a release: its operation, the hold's id and the authority's
     * reason, by its operator; `null` when the row and its payload do not
     * describe a release.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  array<array-key, mixed>  $payload
     * @return ?array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: ?\SineMacula\Laravel\AuditLog\Records\Reference, 2: \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence, 3: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 4: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function released(#[\SensitiveParameter] JournalRow $row, #[\SensitiveParameter] array $payload): ?array
    {
        if ($row->holdId === null || ($payload['hold_id'] ?? null) !== $row->holdId) {
            return null;
        }

        return self::operation(PackageActivity::RELEASED, $row, [
            'operation_id'     => $row->operationId,
            'hold_id'          => $row->holdId,
            'authority_reason' => $row->reason,
            'outcome'          => Outcome::SUCCESS->value,
        ], Outcome::SUCCESS, null);
    }

    /**
     * The record of a finished prune run, by no one: the run's id, status,
     * policy version and counts from its finish and start rows, a success for a
     * complete or partial run and a failure otherwise; `null` without its
     * start, or when the finish does not describe a run.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $finish
     * @param  ?array<array-key, mixed>  $start
     * @return ?array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: ?\SineMacula\Laravel\AuditLog\Records\Reference, 2: \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence, 3: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 4: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function pruned(#[\SensitiveParameter] array $finish, #[\SensitiveParameter] ?array $start): ?array
    {
        $runId   = $finish['run_id']  ?? null;
        $status  = $finish['status']  ?? null;
        $failure = $finish['failure'] ?? null;

        if ($start === null || !is_string($runId) || !in_array($status, ['complete', 'partial', 'failed'], true)) {
            return null;
        }

        $outcome = $status  === 'failed' ? Outcome::FAILURE : Outcome::SUCCESS;
        $reason  = $outcome === Outcome::FAILURE && in_array($failure, self::PRUNE_FAILURES, true) ? $failure : null;

        return self::operation(PackageActivity::PRUNED, null, [
            'operation_id'     => $runId,
            'status'           => $status,
            'policy_version'   => self::scalar($start, 'policy_version'),
            'deleted'          => self::scalar($finish, 'deleted'),
            'seals'            => self::scalar($finish, 'seals'),
            'held'             => self::scalar($finish, 'held'),
            'pending_delivery' => self::scalar($finish, 'pending_delivery'),
            'skipped_seals'    => self::scalar($finish, 'skipped_seals'),
            'categories'       => self::counts($finish, 'categories'),
            'tenants_affected' => self::scalar($finish, 'tenants_affected'),
            'outcome'          => $outcome->value,
        ], $outcome, $reason);
    }

    /**
     * The record of a finished import, by the operator of its finish: its
     * batch, the source, format and hold from its start row, and the status and
     * counts from its finish, a success for a complete or partial import and a
     * failure otherwise; `null` without its start, or when the finish does not
     * describe an import.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  array<array-key, mixed>  $finish
     * @param  ?array<array-key, mixed>  $start
     * @return ?array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: ?\SineMacula\Laravel\AuditLog\Records\Reference, 2: \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence, 3: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 4: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function imported(#[\SensitiveParameter] JournalRow $row, #[\SensitiveParameter] array $finish, #[\SensitiveParameter] ?array $start): ?array
    {
        $status = $finish['status'] ?? null;

        if ($start === null || !is_string($finish['batch_id'] ?? null) || !is_string($status) || !array_key_exists($status, self::IMPORT_STATUSES)) {
            return null;
        }

        $reason  = self::IMPORT_STATUSES[$status];
        $outcome = $reason === null ? Outcome::SUCCESS : Outcome::FAILURE;

        return self::operation(PackageActivity::IMPORTED, $row, [
            'operation_id'     => $row->operationId,
            'batch_id'         => $finish['batch_id'],
            'source_id'        => self::scalar($start, 'source_id'),
            'format'           => self::scalar($start, 'format'),
            'status'           => $status,
            'lines_read'       => self::scalar($finish, 'lines_read'),
            'imported'         => self::scalar($finish, 'imported'),
            'duplicates'       => self::scalar($finish, 'duplicates'),
            'conflicts'        => self::scalar($finish, 'conflicts'),
            'rejected'         => self::scalar($finish, 'rejected'),
            'hold_id'          => self::scalar($start, 'hold_id'),
            'authority_reason' => $row->reason,
            'outcome'          => $outcome->value,
        ], $outcome, $reason);
    }

    /**
     * The record an operation needs: its code, its actor, the operator of the
     * row given or no one, its evidence, its outcome and its reason; `null`
     * when the row names an operator that is not a reference.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  array<string, array<array-key, scalar|null>|scalar|null>  $properties
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @return ?array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: ?\SineMacula\Laravel\AuditLog\Records\Reference, 2: \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence, 3: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 4: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function operation(
        PackageActivity $activity,
        #[\SensitiveParameter]
        ?JournalRow $row,
        #[\SensitiveParameter]
        array $properties,
        Outcome $outcome,
        ?string $reason,
    ): ?array {
        try {
            $actor = $row?->authorityType === null || $row->authorityId === null ? null : Reference::of($row->authorityType, $row->authorityId);

            return [$activity, $actor, new LifecycleEvidence($properties), $outcome, $reason];
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * The record of an erasure, by its operator: its operation, its row, the
     * owner's fingerprint and its key, how it ended, its counts, the reasons
     * its kept keys were blocked and whether it accepted pending deliveries;
     * `null` when the payload does not describe an erasure.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  array<array-key, mixed>  $payload
     * @return ?array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: ?\SineMacula\Laravel\AuditLog\Records\Reference, 2: \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence, 3: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 4: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function erased(#[\SensitiveParameter] JournalRow $row, #[\SensitiveParameter] array $payload): ?array
    {
        $reasons     = self::keptReasons($payload['kept'] ?? null);
        $counts      = self::erasureCounts($payload);
        $fingerprint = self::fingerprintOf($payload);

        if ($reasons === null || $counts === null || $fingerprint === null) {
            return null;
        }

        return self::operation(PackageActivity::SUBJECT_ERASED, $row, [
            'operation_id'      => $row->operationId,
            'erasure_id'        => $row->id,
            'owner_fingerprint' => $fingerprint[0],
            'fingerprint_key'   => $fingerprint[1],
            'status'            => ($reasons[0] === 0 ? ErasureStatus::COMPLETE : ErasureStatus::PARTIAL)->value,
            'keys_destroyed'    => $counts[0],
            'keys_kept'         => $reasons[0],
            'entries_affected'  => $counts[1],
            'blocked'           => LifecycleRecords::blocked($reasons[1]),
            'pending_accepted'  => $counts[2],
            'authority_reason'  => $row->reason,
            'outcome'           => Outcome::SUCCESS->value,
        ], Outcome::SUCCESS, null);
    }

    /**
     * The record of a reinstatement, by its operator: its operation, its row,
     * the owner's fingerprint and its key and the generation floor; `null` when
     * the payload does not describe a reinstatement.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  array<array-key, mixed>  $payload
     * @return ?array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: ?\SineMacula\Laravel\AuditLog\Records\Reference, 2: \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence, 3: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 4: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function reinstated(#[\SensitiveParameter] JournalRow $row, #[\SensitiveParameter] array $payload): ?array
    {
        $floor       = $payload['generation_floor'] ?? null;
        $fingerprint = self::fingerprintOf($payload);

        if ($fingerprint === null || !is_int($floor)) {
            return null;
        }

        return self::operation(PackageActivity::KEYS_REINSTATED, $row, [
            'operation_id'      => $row->operationId,
            'reinstatement_id'  => $row->id,
            'owner_fingerprint' => $fingerprint[0],
            'fingerprint_key'   => $fingerprint[1],
            'generation_floor'  => $floor,
            'authority_reason'  => $row->reason,
            'outcome'           => Outcome::SUCCESS->value,
        ], Outcome::SUCCESS, null);
    }

    /**
     * The record of each rewrap run among the verified rows, by its operator,
     * in the order its first batch was journalled: its operation, its status,
     * the keys its batches rewrapped onto another wrapping key, the live keys
     * they superseded, the keys they skipped, the wrapping key they wrapped
     * onto and how many batches it committed; `null` for a run any of whose
     * batches does not describe one. A run's batches journalled before the
     * window are not among the rows, and are not counted.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<array{0: \SineMacula\Laravel\AuditLog\Integrity\JournalRow, 1: array<array-key, mixed>}>  $rows
     * @return list<?array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: ?\SineMacula\Laravel\AuditLog\Records\Reference, 2: \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence, 3: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 4: ?string}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function rewrapped(#[\SensitiveParameter] array $rows): array
    {
        $runs = [];

        foreach ($rows as [$row, $payload]) {
            if ($row->kind !== JournalKind::REWRAP) {
                continue;
            }

            $runs[$row->operationId] ??= ['row' => $row, 'totals' => ['rewrapped' => 0, 'rotated' => 0, 'skipped' => 0, 'wrap_key_id' => null, 'batches' => 0]];
            $runs[$row->operationId]['totals'] = self::batchAdded($runs[$row->operationId]['totals'], $row, $payload);
        }

        return array_values(array_map(static fn (array $run): ?array => self::rewrapOf($run['row'], $run['totals']), $runs));
    }

    /**
     * The scalar under the key, or `null` when there is none.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $payload
     * @param  string  $key
     * @return scalar|null
     */
    private static function scalar(#[\SensitiveParameter] array $payload, string $key): bool|float|int|string|null
    {
        $value = $payload[$key] ?? null;

        return is_scalar($value) ? $value : null;
    }

    /**
     * The map of scalars under the key, its other values dropped, or `null`
     * when there is none.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $payload
     * @param  string  $key
     * @return ?array<array-key, scalar>
     */
    private static function counts(#[\SensitiveParameter] array $payload, string $key): ?array
    {
        $value = $payload[$key] ?? null;

        return is_array($value) ? array_filter($value, is_scalar(...)) : null;
    }

    /**
     * The record of a rewrap run from its first row and its totals; `null` when
     * a batch did not describe one.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  ?array{rewrapped: int, rotated: int, skipped: int, wrap_key_id: ?string, batches: int}  $totals
     * @return ?array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: ?\SineMacula\Laravel\AuditLog\Records\Reference, 2: \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence, 3: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 4: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function rewrapOf(#[\SensitiveParameter] JournalRow $row, ?array $totals): ?array
    {
        if ($totals === null) {
            return null;
        }

        return self::operation(PackageActivity::KEYS_REWRAPPED, $row, [
            'operation_id'     => $row->operationId,
            'status'           => ($totals['skipped'] > 0 ? RewrapStatus::PARTIAL : RewrapStatus::COMPLETE)->value,
            'keys_rewrapped'   => $totals['rewrapped'],
            'keys_rotated'     => $totals['rotated'],
            'keys_skipped'     => $totals['skipped'],
            'wrap_key_id'      => $totals['wrap_key_id'],
            'batches'          => $totals['batches'],
            'authority_reason' => $row->reason,
            'outcome'          => Outcome::SUCCESS->value,
        ], Outcome::SUCCESS, null);
    }

    /**
     * The run's totals with a batch's row added, its keys and its skipped keys,
     * named or counted alone; `null` once a row does not describe a batch of
     * the run.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?array{rewrapped: int, rotated: int, skipped: int, wrap_key_id: ?string, batches: int}  $totals
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  array<array-key, mixed>  $payload
     * @return ?array{rewrapped: int, rotated: int, skipped: int, wrap_key_id: ?string, batches: int}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function batchAdded(?array $totals, #[\SensitiveParameter] JournalRow $row, #[\SensitiveParameter] array $payload): ?array
    {
        $skipped = $payload['skipped']         ?? null;
        $unnamed = $payload['skipped_unnamed'] ?? 0;
        $counted = is_array($skipped) && array_is_list($skipped) && is_int($unnamed) && $unnamed >= 0;

        if ($totals === null || ($payload['run_id'] ?? null) !== $row->operationId || !$counted) {
            return null;
        }

        $totals = self::keysAdded($totals, $payload['keys'] ?? null);

        if ($totals === null) {
            return null;
        }

        $totals['skipped'] += count($skipped) + $unnamed;
        $totals['batches']++;

        return $totals;
    }

    /**
     * The totals with a batch's keys added: each key whose wrapping key changed
     * rewrapped, each whose state changed rotated, and the wrapping key its
     * keys are now under; `null` when the keys are not a list of changes, each
     * with its wrapping before and after.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array{rewrapped: int, rotated: int, skipped: int, wrap_key_id: ?string, batches: int}  $totals
     * @param  mixed  $keys
     * @return ?array{rewrapped: int, rotated: int, skipped: int, wrap_key_id: ?string, batches: int}
     */
    private static function keysAdded(array $totals, #[\SensitiveParameter] mixed $keys): ?array
    {
        if (!is_array($keys) || !array_is_list($keys)) {
            return null;
        }

        foreach ($keys as $key) {
            $change = self::changeOf($key);

            if ($change === null) {
                return null;
            }

            $totals['rewrapped'] += $change[0] ? 1 : 0;
            $totals['rotated']   += $change[1] ? 1 : 0;
            $totals['wrap_key_id'] = $change[2];
        }

        return $totals;
    }

    /**
     * What a rewrap batch's row lists of a key: whether its wrapping key
     * changed, whether its state changed, and the wrapping key it is now under;
     * `null` when it is not a change with its wrapping before and after.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $key
     * @return ?array{0: bool, 1: bool, 2: string}
     */
    private static function changeOf(#[\SensitiveParameter] mixed $key): ?array
    {
        if (!is_array($key)) {
            return null;
        }

        ['before' => $before, 'after' => $after] = $key + ['before' => null, 'after' => null];

        if (!is_array($before) || !is_array($after)) {
            return null;
        }

        $before += ['state' => null, 'wrap_key_id' => null];
        $after  += ['state' => null, 'wrap_key_id' => null];

        return is_string($after['wrap_key_id']) ? [$before['wrap_key_id'] !== $after['wrap_key_id'], $before['state'] !== $after['state'], $after['wrap_key_id']] : null;
    }

    /**
     * How many keys an erasure kept and every reason they were kept for, from
     * its payload's `kept`; `null` when that is not a list of kept keys, each
     * with a list of reasons.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $kept
     * @return ?array{0: int, 1: list<string>}
     */
    private static function keptReasons(#[\SensitiveParameter] mixed $kept): ?array
    {
        if (!is_array($kept) || !array_is_list($kept)) {
            return null;
        }

        $reasons = [];

        foreach ($kept as $key) {
            $given = is_array($key) ? ($key['reasons'] ?? null) : null;

            if (!is_array($given) || !array_is_list($given) || array_filter($given, is_string(...)) !== $given) {
                return null;
            }

            $reasons = [...$reasons, ...$given];
        }

        return [count($kept), $reasons];
    }

    /**
     * How many keys an erasure row's payload lists as destroyed, how many
     * entries it says they sealed, and whether it accepted pending deliveries;
     * `null` when it does not say each.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $payload
     * @return ?array{0: int, 1: int, 2: bool}
     */
    private static function erasureCounts(#[\SensitiveParameter] array $payload): ?array
    {
        $destroyed = $payload['destroyed']        ?? null;
        $affected  = $payload['entries_affected'] ?? null;
        $accepted  = $payload['pending_accepted'] ?? null;

        if (!is_array($destroyed) || !array_is_list($destroyed)) {
            return null;
        }

        return is_int($affected) && is_bool($accepted) ? [count($destroyed), $affected, $accepted] : null;
    }

    /**
     * The owner's fingerprint the payload names and the ring key it was taken
     * under, or `null` unless each is a string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $payload
     * @return ?array{0: string, 1: string}
     */
    private static function fingerprintOf(#[\SensitiveParameter] array $payload): ?array
    {
        $fingerprint = $payload['owner_fingerprint'] ?? null;
        $key         = $payload['fingerprint_key']   ?? null;

        return is_string($fingerprint) && is_string($key) ? [$fingerprint, $key] : null;
    }
}
