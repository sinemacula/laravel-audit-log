<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\ReconciledOperations;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;

/**
 * Unit tests for the records the reconciler writes from verified journal rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReconciledOperations::class)]
final class ReconciledOperationsTest extends TestCase
{
    /** @var string The operation every row names, unless a test gives another. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string The hold the hold and release rows name. */
    private const string HOLD_ID = '01932b4e-d000-7000-8000-000000000001';

    /** @var string The fingerprint an erasure and a reinstatement name their owner by. */
    private const string FINGERPRINT = 'ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34';

    /** @var array{0: string, 1: string} The operator of every row that carries an authority. */
    private const array OPERATOR = ['App\Models\User', '7'];

    /**
     * A hold row records the hold by its operator, with its scope's digest.
     *
     * @return void
     */
    public function testAHoldIsItsOperation(): void
    {
        $scope = HoldScope::all()->categories('security');
        $row   = self::row(JournalKind::HOLD, ['hold_id' => self::HOLD_ID, 'basis' => 'legal_claim', 'scope' => $scope->toArray(), 'review_by' => null], self::HOLD_ID);

        self::assertSame([
            PackageActivity::HELD,
            self::OPERATOR,
            [
                'operation_id'     => self::OPERATION,
                'hold_id'          => self::HOLD_ID,
                'basis'            => 'legal_claim',
                'scope_digest'     => $scope->digest(),
                'review_by'        => null,
                'authority_reason' => 'case.review',
                'outcome'          => 'success',
            ],
            Outcome::SUCCESS,
            null,
        ], self::flattened(ReconciledOperations::held($row, $row->payloadMap() ?? [])));
    }

    /**
     * Rows of `[payload]`: a hold row's payload that describes no hold.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideNoHolds(): iterable
    {
        $scope = HoldScope::all()->toArray();

        yield from [
            'another hold id'   => [['hold_id' => '01932b4e-d000-7000-8000-000000000002', 'basis' => 'other', 'scope' => $scope]],
            'an unknown basis'  => [['hold_id' => self::HOLD_ID, 'basis' => 'whim', 'scope' => $scope]],
            'no scope'          => [['hold_id' => self::HOLD_ID, 'basis' => 'other']],
            'a malformed scope' => [['hold_id' => self::HOLD_ID, 'basis' => 'other', 'scope' => ['categories' => 'security']]],
            'a review not text' => [['hold_id' => self::HOLD_ID, 'basis' => 'other', 'scope' => $scope, 'review_by' => 20270101]],
        ];
    }

    /**
     * A hold row whose payload does not describe its hold records nothing.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $payload
     * @return void
     */
    #[DataProvider('provideNoHolds')]
    public function testAHoldRowThatDescribesNoHoldIsNull(array $payload): void
    {
        self::assertNull(ReconciledOperations::held(self::row(JournalKind::HOLD, $payload, self::HOLD_ID), $payload));
    }

    /**
     * A release row records its release, unless it names another hold.
     *
     * @return void
     */
    public function testAReleaseIsItsOperation(): void
    {
        $row = self::row(JournalKind::RELEASE, ['hold_id' => self::HOLD_ID], self::HOLD_ID);

        $properties = ['operation_id' => self::OPERATION, 'hold_id' => self::HOLD_ID, 'authority_reason' => 'case.review', 'outcome' => 'success'];

        self::assertSame(
            [PackageActivity::RELEASED, self::OPERATOR, $properties, Outcome::SUCCESS, null],
            self::flattened(ReconciledOperations::released($row, ['hold_id' => self::HOLD_ID])),
        );
        self::assertNull(ReconciledOperations::released($row, ['hold_id' => '01932b4e-d000-7000-8000-000000000002']));
    }

    /**
     * Rows of `[status, failure, outcome, reason]` for a prune run's finish.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 3: ?string}>
     */
    public static function providePruneRuns(): iterable
    {
        yield from [
            'complete'                 => ['complete', null, Outcome::SUCCESS, null],
            'partial'                  => ['partial', null, Outcome::SUCCESS, null],
            'failed with its reason'   => ['failed', 'journal_broken', Outcome::FAILURE, 'journal_broken'],
            'failed with an odd one'   => ['failed', 'gremlins', Outcome::FAILURE, null],
            'a success naming failure' => ['complete', 'prune_failed', Outcome::SUCCESS, null],
        ];
    }

    /**
     * A prune run is recorded by no one; a failure keeps only a prune reason.
     *
     * @param  string  $status
     * @param  ?string  $failure
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @return void
     */
    #[DataProvider('providePruneRuns')]
    public function testAPruneRunIsItsOperation(string $status, ?string $failure, Outcome $outcome, ?string $reason): void
    {
        $finish = [
            'run_id'           => self::OPERATION,
            'status'           => $status,
            'failure'          => $failure,
            'deleted'          => 3,
            'seals'            => 1,
            'categories'       => ['security' => 3, 'odd' => [1]],
            'tenants_affected' => 1,
        ];
        $built = self::flattened(ReconciledOperations::pruned($finish, ['policy_version' => 'config:0123456789abcdef']));

        self::assertSame([PackageActivity::PRUNED, null], [$built[0], $built[1]]);
        self::assertSame([$outcome, $reason], [$built[3], $built[4]]);
        self::assertSame(['security' => 3], $built[2]['categories']);
        self::assertSame(['config:0123456789abcdef', null, $outcome->value], [$built[2]['policy_version'], $built[2]['held'], $built[2]['outcome']]);
    }

    /**
     * A prune run without its start, run id or a known status records nothing.
     *
     * @return void
     */
    public function testAPruneRunThatDescribesNoRunIsNull(): void
    {
        self::assertNull(ReconciledOperations::pruned(['run_id' => self::OPERATION, 'status' => 'complete'], null));
        self::assertNull(ReconciledOperations::pruned(['status' => 'complete'], []));
        self::assertNull(ReconciledOperations::pruned(['run_id' => self::OPERATION, 'status' => 'running'], []));
    }

    /**
     * Rows of `[status, outcome, reason]` for an import's finish.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 2: ?string}>
     */
    public static function provideImports(): iterable
    {
        yield from [
            'complete'    => ['complete', Outcome::SUCCESS, null],
            'partial'     => ['partial', Outcome::SUCCESS, null],
            'failed'      => ['failed', Outcome::FAILURE, 'import_failed'],
            'interrupted' => ['interrupted', Outcome::FAILURE, 'interrupted'],
        ];
    }

    /**
     * An import is recorded by its finish's operator from its start and finish.
     *
     * @param  string  $status
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @return void
     */
    #[DataProvider('provideImports')]
    public function testAnImportIsItsOperation(string $status, Outcome $outcome, ?string $reason): void
    {
        $finish = ['batch_id' => '01932b4e-b000-7000-8000-000000000001', 'status' => $status, 'lines_read' => 2];
        $start  = ['source_id' => 'crm-eu', 'format' => 'audit-log-import/v1', 'hold_id' => null];
        $built  = self::flattened(ReconciledOperations::imported(self::row(JournalKind::IMPORT_FINISHED, $finish), $finish, $start));

        self::assertSame([PackageActivity::IMPORTED, self::OPERATOR, $outcome, $reason], [$built[0], $built[1], $built[3], $built[4]]);
        self::assertSame(['crm-eu', 'audit-log-import/v1', $status, 2], [$built[2]['source_id'], $built[2]['format'], $built[2]['status'], $built[2]['lines_read']]);
    }

    /**
     * An import without its start, batch or a known status records nothing.
     *
     * @return void
     */
    public function testAnImportThatDescribesNoImportIsNull(): void
    {
        $row = self::row(JournalKind::IMPORT_FINISHED, []);

        self::assertNull(ReconciledOperations::imported($row, ['batch_id' => 'b', 'status' => 'complete'], null));
        self::assertNull(ReconciledOperations::imported($row, ['status' => 'complete'], []));
        self::assertNull(ReconciledOperations::imported($row, ['batch_id' => 'b', 'status' => 'running'], []));
    }

    /**
     * An erasure is `complete` when it kept nothing, else `partial`.
     *
     * @return void
     */
    public function testAnErasureIsItsOperation(): void
    {
        $complete = self::erasure([]);
        $built    = self::flattened(ReconciledOperations::erased($complete, $complete->payloadMap() ?? []));

        self::assertSame([PackageActivity::SUBJECT_ERASED, self::OPERATOR, Outcome::SUCCESS, null], [$built[0], $built[1], $built[3], $built[4]]);
        self::assertSame([
            'operation_id'      => self::OPERATION,
            'erasure_id'        => $complete->id,
            'owner_fingerprint' => self::FINGERPRINT,
            'fingerprint_key'   => 'k-2026',
            'status'            => 'complete',
            'keys_destroyed'    => 2,
            'keys_kept'         => 0,
            'entries_affected'  => 5,
            'blocked'           => [],
            'pending_accepted'  => true,
            'authority_reason'  => 'case.review',
            'outcome'           => 'success',
        ], $built[2]);

        $partial = self::erasure([['key_id' => 'a', 'reasons' => ['unverified', 'held:h1']], ['key_id' => 'b', 'reasons' => ['held:h1']]]);
        $built   = self::flattened(ReconciledOperations::erased($partial, $partial->payloadMap() ?? []));

        self::assertSame(['partial', 2, ['held:h1' => 1, 'unverified' => 1]], [$built[2]['status'], $built[2]['keys_kept'], $built[2]['blocked']]);
    }

    /**
     * Rows of `[key, value]`: a payload member that describes no erasure.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideNoErasures(): iterable
    {
        yield from [
            'no fingerprint'          => ['owner_fingerprint', null],
            'no fingerprint key'      => ['fingerprint_key', 7],
            'destroyed not a list'    => ['destroyed', ['a' => 1]],
            'affected not a count'    => ['entries_affected', '5'],
            'pending not a flag'      => ['pending_accepted', 1],
            'kept not a list'         => ['kept', 'none'],
            'kept with no reasons'    => ['kept', [['key_id' => 'a']]],
            'kept with a reason list' => ['kept', [['key_id' => 'a', 'reasons' => ['held:h1', 7]]]],
            'kept with a reason map'  => ['kept', [['key_id' => 'a', 'reasons' => ['first' => 'held:h1']]]],
            'kept not keys'           => ['kept', ['held:h1']],
        ];
    }

    /**
     * An erasure row whose payload describes no erasure records nothing.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideNoErasures')]
    public function testAnErasureRowThatDescribesNoErasureIsNull(string $key, mixed $value): void
    {
        $row = self::erasure([]);

        self::assertNull(ReconciledOperations::erased($row, [...$row->payloadMap() ?? [], $key => $value]));
    }

    /**
     * A reinstatement records its floor; one without a floor records nothing.
     *
     * @return void
     */
    public function testAReinstatementIsItsOperation(): void
    {
        $payload = ['owner_fingerprint' => self::FINGERPRINT, 'fingerprint_key' => 'k-2026', 'generation_floor' => 3];
        $row     = self::row(JournalKind::REINSTATE, $payload);

        self::assertSame([
            PackageActivity::KEYS_REINSTATED,
            self::OPERATOR,
            [
                'operation_id'      => self::OPERATION,
                'reinstatement_id'  => $row->id,
                'owner_fingerprint' => self::FINGERPRINT,
                'fingerprint_key'   => 'k-2026',
                'generation_floor'  => 3,
                'authority_reason'  => 'case.review',
                'outcome'           => 'success',
            ],
            Outcome::SUCCESS,
            null,
        ], self::flattened(ReconciledOperations::reinstated($row, $payload)));

        self::assertNull(ReconciledOperations::reinstated($row, [...$payload, 'generation_floor' => '3']));
        self::assertNull(ReconciledOperations::reinstated($row, [...$payload, 'owner_fingerprint' => null]));
    }

    /**
     * A rewrap run is summed once over its batches, in journal order.
     *
     * @return void
     */
    public function testARewrapRunIsSummedOverItsBatches(): void
    {
        $other = '01932b4e-9000-7000-8000-0000000000a2';
        $rows  = [
            self::batch(self::OPERATION, [self::change('d-old', 'd-new', 'live', 'superseded'), self::change('d-new', 'd-new', 'live', 'superseded')], []),
            self::pair(self::row(JournalKind::HOLD, ['hold_id' => self::HOLD_ID], self::HOLD_ID)),
            self::batch($other, [], ['k-1', 'k-2']),
            self::batch(self::OPERATION, [self::change('d-old', 'd-new', 'superseded', 'superseded')], ['k-3']),
        ];

        $built = array_map(self::flattened(...), ReconciledOperations::rewrapped($rows));

        self::assertCount(2, $built);
        self::assertSame([PackageActivity::KEYS_REWRAPPED, self::OPERATOR, Outcome::SUCCESS, null], [$built[0][0], $built[0][1], $built[0][3], $built[0][4]]);
        self::assertSame([
            'operation_id'     => self::OPERATION,
            'status'           => 'partial',
            'keys_rewrapped'   => 2,
            'keys_rotated'     => 2,
            'keys_skipped'     => 1,
            'wrap_key_id'      => 'd-new',
            'batches'          => 2,
            'authority_reason' => 'case.review',
            'outcome'          => 'success',
        ], $built[0][2]);
        $second = $built[1][2];

        self::assertSame(
            [$other, 'partial', 0, 2, null, 1],
            [$second['operation_id'], $second['status'], $second['keys_rewrapped'], $second['keys_skipped'], $second['wrap_key_id'], $second['batches']],
        );
    }

    /**
     * A run whose batches all changed keys and skipped none is `complete`.
     *
     * @return void
     */
    public function testARewrapRunThatSkippedNothingIsComplete(): void
    {
        $built = self::flattened(ReconciledOperations::rewrapped([self::batch(self::OPERATION, [self::change('d-old', 'd-new', 'live', 'live')], [])])[0]);

        self::assertSame(['complete', 1, 0, 0], [$built[2]['status'], $built[2]['keys_rewrapped'], $built[2]['keys_rotated'], $built[2]['keys_skipped']]);
    }

    /**
     * Keys a batch skipped without naming are counted with the named ones.
     *
     * @return void
     */
    public function testARewrapRunCountsTheKeysItSkippedUnnamed(): void
    {
        $batch = ['run_id' => self::OPERATION, 'rotate' => false, 'keys' => [], 'skipped' => ['k-1'], 'skipped_unnamed' => 2];
        $row   = self::pair(self::row(JournalKind::REWRAP, $batch, null, self::OPERATION));
        $built = self::flattened(ReconciledOperations::rewrapped([$row])[0]);

        self::assertSame(['partial', 3], [$built[2]['status'], $built[2]['keys_skipped']]);
    }

    /**
     * Rows of `[payload]`: a rewrap batch payload that describes no batch.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideNoBatches(): iterable
    {
        $change = self::change('d-old', 'd-new', 'live', 'live');

        yield from [
            'another run'            => [['run_id' => 'other', 'keys' => [], 'skipped' => []]],
            'keys not a list'        => [['run_id' => self::OPERATION, 'keys' => 'none', 'skipped' => []]],
            'skipped not a list'     => [['run_id' => self::OPERATION, 'keys' => [], 'skipped' => ['a' => 'k-1']]],
            'a key not a change'     => [['run_id' => self::OPERATION, 'keys' => ['k-1'], 'skipped' => []]],
            'a change with no after' => [['run_id' => self::OPERATION, 'keys' => [['key_id' => 'k', 'before' => $change['before']]], 'skipped' => []]],
            'an after with no key'   => [['run_id' => self::OPERATION, 'keys' => [['before' => $change['before'], 'after' => ['state' => 'live']]], 'skipped' => []]],
            'a before not a map'     => [['run_id' => self::OPERATION, 'keys' => [['key_id' => 'k', 'before' => 'live', 'after' => $change['after']]], 'skipped' => []]],
            'unnamed not a count'    => [['run_id' => self::OPERATION, 'keys' => [], 'skipped' => [], 'skipped_unnamed' => '1']],
            'unnamed below zero'     => [['run_id' => self::OPERATION, 'keys' => [], 'skipped' => [], 'skipped_unnamed' => -1]],
        ];
    }

    /**
     * A run with any batch that describes no batch is `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $payload
     * @return void
     */
    #[DataProvider('provideNoBatches')]
    public function testARunWithABatchThatDescribesNoBatchIsNull(array $payload): void
    {
        $good = self::batch(self::OPERATION, [self::change('d-old', 'd-new', 'live', 'live')], []);
        $bad  = self::pair(self::row(JournalKind::REWRAP, $payload));

        self::assertSame([null], ReconciledOperations::rewrapped([$good, $bad]));
        self::assertSame([null], ReconciledOperations::rewrapped([$bad, $good]));
    }

    /**
     * An operation is by the row's operator, or by no one when it names none.
     *
     * @return void
     */
    public function testAnOperationIsByTheRowsOperatorOrNoOne(): void
    {
        $built = self::flattened(ReconciledOperations::operation(PackageActivity::RELEASED, null, ['operation_id' => self::OPERATION], Outcome::DENIED, 'unknown_hold'));

        self::assertSame([PackageActivity::RELEASED, null, ['operation_id' => self::OPERATION], Outcome::DENIED, 'unknown_hold'], $built);

        $row   = self::row(JournalKind::HOLD, []);
        $built = self::flattened(ReconciledOperations::operation(PackageActivity::HELD, $row, ['operation_id' => self::OPERATION], Outcome::SUCCESS, null));

        self::assertSame(self::OPERATOR, $built[1]);
    }

    /**
     * Evidence that names no operation is never an operation.
     *
     * @return void
     */
    public function testEvidenceNamingNoOperationIsNull(): void
    {
        self::assertNull(ReconciledOperations::operation(PackageActivity::RELEASED, null, ['hold_id' => self::HOLD_ID], Outcome::SUCCESS, null));
    }

    /**
     * The constructor is private; reflection invokes it for coverage.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ReconciledOperations::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ReconciledOperations::class, $instance);
    }

    /**
     * An erasure row over five entries, two keys destroyed, those given kept.
     *
     * @param  list<array{key_id: string, reasons: list<string>}>  $kept
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private static function erasure(array $kept): JournalRow
    {
        return self::row(JournalKind::ERASURE, [
            'owner_fingerprint' => self::FINGERPRINT,
            'fingerprint_key'   => 'k-2026',
            'generation_floor'  => 2,
            'partial'           => $kept !== [],
            'pending_accepted'  => true,
            'pending_rows'      => 1,
            'destroyed'         => [['key_id' => 'x'], ['key_id' => 'y']],
            'kept'              => $kept,
            'entries_affected'  => 5,
        ]);
    }

    /**
     * A rewrap batch of the run listing its changes and skipped keys.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $runId
     * @param  list<array<string, mixed>>  $changes
     * @param  list<string>  $skipped
     * @return array{0: \SineMacula\Laravel\AuditLog\Integrity\JournalRow, 1: array<array-key, mixed>}
     */
    private static function batch(string $runId, array $changes, array $skipped): array
    {
        return self::pair(self::row(JournalKind::REWRAP, ['run_id' => $runId, 'rotate' => true, 'keys' => $changes, 'skipped' => $skipped], null, $runId));
    }

    /**
     * A batch's entry for a key whose wrapping key or state changed.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $from
     * @param  string  $to
     * @param  string  $stateBefore
     * @param  string  $stateAfter
     * @return array{key_id: string, before: array{state: string, wrapped_digest: string, wrap_key_id: string}, after: array{state: string, wrapped_digest: string, wrap_key_id: string}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function change(string $from, string $to, string $stateBefore, string $stateAfter): array
    {
        return [
            'key_id' => '01932b4e-f000-7000-8000-000000000001',
            'before' => ['state' => $stateBefore, 'wrapped_digest' => str_repeat('a', 64), 'wrap_key_id' => $from],
            'after'  => ['state' => $stateAfter, 'wrapped_digest' => str_repeat('b', 64), 'wrap_key_id' => $to],
        ];
    }

    /**
     * The row with its payload, as the reconciler pairs a verified row.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @return array{0: \SineMacula\Laravel\AuditLog\Integrity\JournalRow, 1: array<array-key, mixed>}
     */
    private static function pair(JournalRow $row): array
    {
        return [$row, $row->payloadMap() ?? []];
    }

    /**
     * An unsigned row of the kind, by the operator when it has an authority.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  array<array-key, mixed>  $payload
     * @param  ?string  $holdId
     * @param  string  $operationId
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private static function row(JournalKind $kind, array $payload, ?string $holdId = null, string $operationId = self::OPERATION): JournalRow
    {
        $carries = $kind->carriesAuthority();

        return JournalRow::draft(
            '01932b4e-c000-7000-8000-' . substr(hash('sha256', $kind->value . $operationId . json_encode($payload)), 0, 12),
            1,
            'app-eu-1',
            $kind,
            $operationId,
            '2026-11-04T10:00:00.000000Z',
            $carries ? self::OPERATOR : null,
            $carries ? 'case.review' : null,
            null,
            null,
            $holdId,
            $payload,
            null,
        );
    }

    /**
     * The operation's code, actor pair, properties, outcome and reason.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: ?\SineMacula\Laravel\AuditLog\Records\Reference, 2: \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence, 3: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 4: ?string}  $operation
     * @return array{0: \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity, 1: ?array{0: string, 1: string}, 2: array<string, mixed>, 3: \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, 4: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function flattened(?array $operation): array
    {
        self::assertNotNull($operation, 'The row was not taken for its operation.');

        [$activity, $actor, $evidence, $outcome, $reason] = $operation;

        return [$activity, $actor === null ? null : [$actor->type, $actor->id], $evidence->properties, $outcome, $reason];
    }
}
