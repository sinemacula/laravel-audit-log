<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureRefusedException;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportResult;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecordFailedException;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecords;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneResult;
use SineMacula\Laravel\AuditLog\Lifecycle\ReinstateResult;
use SineMacula\Laravel\AuditLog\Lifecycle\RewrapResult;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for the records of the lifecycle's operations: each code is
 * written by the authority's operator, or by no one for a prune, in no tenant,
 * with exactly the properties its code retains; a refusal is `denied` with the
 * reason it names and a failure a `failure` with a code, never a message; an
 * erasure's `blocked` names each reason once, at most 50, with the rest counted
 * under `_other`; and a record that cannot be written is reported once and
 * answered `false`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleRecords::class)]
final class LifecycleRecordsTest extends TestCase
{
    use ReadsTheTrail;

    /** @var string The operation every record names. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string The erasure row an erasure names. */
    private const string ERASURE_ROW = '01932b4e-9000-7000-8000-0000000000e1';

    /** @var array{0: string, 1: string} The ring key and the fingerprint every owner is named by. */
    private const array FINGERPRINT = ['k-2026', 'ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34'];

    /** @var ?\Tests\Fixtures\Privacy\RecordingExceptionHandler What every failure to record is reported to. */
    private ?RecordingExceptionHandler $reporter = null;

    /**
     * Freeze the clock and report to a recording handler.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-04 10:00:00', 'UTC'));

        $this->reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $this->reporter);
    }

    /**
     * Put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A hold is recorded by its operator, with its id, basis, scope digest and
     * review date.
     *
     * @return void
     */
    public function testAHoldIsRecordedByItsOperator(): void
    {
        $scope = HoldScope::all()->categories('security');
        $hold  = new Hold(
            id: '01932b4e-d000-7000-8000-000000000001',
            scope: $scope,
            basis: HoldBasis::REGULATORY,
            reviewBy: null,
            placedAt: '2026-11-04T10:00:00.000000Z',
            operator: self::authority()->operator,
            reason: 'case.review',
            externalReference: null,
            operationId: self::OPERATION,
            journalSequence: 1,
        );

        self::assertTrue($this->records()->recordHeld($hold));

        $record = $this->onlyRecord('audit_log.held');

        self::assertSame(['success', null, 'App\Models\User', '7'], [$record['outcome'], $record['reason'], $record['actor_type'], $record['actor_id']]);
        self::assertSameProperties([
            'operation_id'     => self::OPERATION,
            'hold_id'          => $hold->id,
            'basis'            => 'regulatory',
            'scope_digest'     => $scope->digest(),
            'review_by'        => null,
            'authority_reason' => 'case.review',
            'outcome'          => 'success',
        ], self::propertiesOf($record));
    }

    /**
     * A release is recorded a success with no reason, and a release refused
     * `denied` with `unknown_hold`.
     *
     * @return void
     */
    public function testAReleaseAndItsRefusalAreRecorded(): void
    {
        $records = $this->records();

        self::assertTrue($records->recordReleased(self::OPERATION, '01932b4e-d000-7000-8000-000000000001', self::authority(), Outcome::SUCCESS));
        self::assertTrue($records->recordReleased('01932b4e-9000-7000-8000-0000000000a2', '01932b4e-d000-7000-8000-000000000002', self::authority(), Outcome::DENIED));

        self::assertSame(['denied:unknown_hold', 'success:'], self::endings($this->readRecords('audit_log.released')));
    }

    /**
     * Rows of `[status, failure, outcome, reason]`: a prune run's status and
     * the outcome and reason its record carries.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus, 1: ?string, 2: string, 3: ?string}>
     */
    public static function providePruneRuns(): iterable
    {
        yield from [
            'complete' => [PruneStatus::COMPLETE, null, 'success', null],
            'partial'  => [PruneStatus::PARTIAL, null, 'success', null],
            'failed'   => [PruneStatus::FAILED, 'policy_failed', 'failure', 'policy_failed'],
        ];
    }

    /**
     * A prune run is recorded by no one: a success for a complete or partial
     * run and a failure, with the run's own reason, for a failed one.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus  $status
     * @param  ?string  $failure
     * @param  string  $outcome
     * @param  ?string  $reason
     * @return void
     */
    #[DataProvider('providePruneRuns')]
    public function testAPruneRunIsRecordedByNoOne(PruneStatus $status, ?string $failure, string $outcome, ?string $reason): void
    {
        $result = new PruneResult(self::OPERATION, true, false, $status, $failure, 'config:0123456789abcdef', 3, 1, 0, 0, 0, 1, 0, ['security' => 3], 1, []);

        self::assertTrue($this->records()->recordPruned($result));

        $record = $this->onlyRecord('audit_log.pruned');

        self::assertSame([$outcome, $reason, null, null], [$record['outcome'], $record['reason'], $record['actor_type'], $record['actor_id']]);
        self::assertSame(['security' => 3], self::propertiesOf($record)['categories']);
        self::assertSame($status->value, self::propertiesOf($record)['status']);
    }

    /**
     * Rows of `[status, outcome and reason]`: an import's status and how its
     * record ends.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus, 1: string}>
     */
    public static function provideImports(): iterable
    {
        yield from [
            'complete'    => [ImportStatus::COMPLETE, 'success:'],
            'partial'     => [ImportStatus::PARTIAL, 'success:'],
            'failed'      => [ImportStatus::FAILED, 'failure:import_failed'],
            'interrupted' => [ImportStatus::INTERRUPTED, 'failure:interrupted'],
        ];
    }

    /**
     * An import is recorded by its operator with its source, format and counts,
     * a failed or interrupted one as a failure.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus  $status
     * @param  string  $ending
     * @return void
     */
    #[DataProvider('provideImports')]
    public function testAnImportIsRecordedWithItsStatus(ImportStatus $status, string $ending): void
    {
        $result = new ImportResult(self::OPERATION, true, false, false, '01932b4e-b000-7000-8000-000000000001', $status, null, null, 2, 1, 0, 0, 1, [], [], 0, 0);

        self::assertTrue($this->records()->recordImported($result, 'crm-eu', 'audit-log-import/v1', self::authority()));

        $record = $this->onlyRecord('audit_log.imported');

        self::assertSame([$ending], self::endings([$record]));
        $properties = self::propertiesOf($record);

        self::assertSame(['crm-eu', 'audit-log-import/v1', 2], [$properties['source_id'], $properties['format'], $properties['lines_read']]);
    }

    /**
     * An erasure is recorded by the authority's operator, of no subject and no
     * tenant, with its row, the owner's fingerprint, its status, counts and
     * blocks, each reason once, sorted.
     *
     * @return void
     */
    public function testAnErasureIsRecordedWithItsCountsAndBlocks(): void
    {
        $blocked = ['unverified', 'held:01932b4e-d000-7000-8000-000000000001', 'unverified', 'preserved:billing'];
        $result  = new ErasureResult(self::OPERATION, self::ERASURE_ROW, ErasureStatus::PARTIAL, self::FINGERPRINT[1], self::FINGERPRINT[0], 2, 3, 7, $blocked, true);

        self::assertTrue($this->records()->recordErased($result, self::authority()));

        $record = $this->onlyRecord('audit_log.subject_erased');

        self::assertSame(['success', null], [$record['outcome'], $record['reason']]);
        self::assertSame([null, null, null, null], [$record['subject_type'], $record['subject_id'], $record['tenant_type'], $record['tenant_id']]);
        self::assertSameProperties([
            'operation_id'      => self::OPERATION,
            'erasure_id'        => self::ERASURE_ROW,
            'owner_fingerprint' => self::FINGERPRINT[1],
            'fingerprint_key'   => self::FINGERPRINT[0],
            'status'            => 'partial',
            'keys_destroyed'    => 2,
            'keys_kept'         => 3,
            'entries_affected'  => 7,
            'blocked'           => ['held:01932b4e-d000-7000-8000-000000000001' => 1, 'preserved:billing' => 1, 'unverified' => 1],
            'pending_accepted'  => true,
            'authority_reason'  => 'case.review',
            'outcome'           => 'success',
        ], self::propertiesOf($record));
    }

    /**
     * Rows of `[refusal, reasons, the blocked the record keeps]`: every
     * refusal, only a block's reasons kept as blocks.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal, 1: list<string>, 2: array<string, int>}>
     */
    public static function provideRefusals(): iterable
    {
        yield from [
            'blocked'               => [ErasureRefusal::BLOCKED, ['preserved:billing', 'held:h-1'], ['held:h-1' => 1, 'preserved:billing' => 1]],
            'pending delivery'      => [ErasureRefusal::PENDING_DELIVERY, [], []],
            'unsupported encrypter' => [ErasureRefusal::UNSUPPORTED_ENCRYPTER, ['App\Privacy\VaultEncrypter'], []],
            'key unverifiable'      => [ErasureRefusal::KEY_UNVERIFIABLE, ['01932b4e-f000-7000-8000-000000000001'], []],
            'too many keys'         => [ErasureRefusal::TOO_MANY_KEYS, [], []],
        ];
    }

    /**
     * A refused erasure is recorded `denied` with its refusal, naming the
     * fingerprint the refusal carries, no row, no status and nothing done.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureRefusal  $refusal
     * @param  list<string>  $reasons
     * @param  array<string, int>  $blocked
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testEachRefusalIsRecordedDenied(ErasureRefusal $refusal, array $reasons, array $blocked): void
    {
        $exception = ErasureRefusedException::of($refusal, $reasons, self::FINGERPRINT[1], self::FINGERPRINT[0]);

        self::assertTrue($this->records()->recordErasureRefused(self::OPERATION, ['other-key', 'other-print'], self::authority(), $exception));

        $record = $this->onlyRecord('audit_log.subject_erased');

        self::assertSame(['denied:' . $refusal->value], self::endings([$record]));
        self::assertSameProperties([
            'operation_id'      => self::OPERATION,
            'erasure_id'        => null,
            'owner_fingerprint' => self::FINGERPRINT[1],
            'fingerprint_key'   => self::FINGERPRINT[0],
            'status'            => null,
            'keys_destroyed'    => 0,
            'keys_kept'         => 0,
            'entries_affected'  => 0,
            'blocked'           => $blocked,
            'pending_accepted'  => false,
            'authority_reason'  => 'case.review',
            'outcome'           => 'denied',
        ], self::propertiesOf($record));
    }

    /**
     * A failed erasure is recorded a failure under the fingerprint given:
     * `journal_broken` for a journal that does not verify, `erasure_failed` for
     * anything else, and never the failure's message.
     *
     * @return void
     */
    public function testAFailedErasureIsRecordedWithACode(): void
    {
        $records = $this->records();

        $records->recordErasureRefused(self::OPERATION, self::FINGERPRINT, self::authority(), JournalBrokenException::at(Finding::JOURNAL_SIGNATURE, null));
        $records->recordErasureRefused('01932b4e-9000-7000-8000-0000000000a2', self::FINGERPRINT, self::authority(), new \RuntimeException('SQLSTATE: owner secret-42'));

        $erased = $this->readRecords('audit_log.subject_erased');

        self::assertSame(['failure:erasure_failed', 'failure:journal_broken'], self::endings($erased));
        self::assertStringNotContainsString('secret-42', (string) json_encode($erased));

        foreach ($erased as $record) {
            $properties = self::propertiesOf($record);

            self::assertSame([self::FINGERPRINT[1], self::FINGERPRINT[0], []], [$properties['owner_fingerprint'], $properties['fingerprint_key'], $properties['blocked']]);
        }
    }

    /**
     * The erasure a closure makes is recorded: one that commits as it returned,
     * marked recorded, and one that throws as a refusal under the fingerprint
     * given, rethrown unchanged; the closure is given the operation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecordedErasureRecordsWhatTheClosureDid(): void
    {
        $records = $this->records();
        $asked   = [];
        $result  = new ErasureResult(self::OPERATION, self::ERASURE_ROW, ErasureStatus::COMPLETE, self::FINGERPRINT[1], self::FINGERPRINT[0], 1, 0, 0, [], false);

        $erased = $records->recordedErasure(self::OPERATION, self::FINGERPRINT, self::authority(), static function (string $operationId) use (&$asked, $result): ErasureResult {
            $asked[] = $operationId;

            return $result;
        });

        self::assertTrue($erased->recorded);
        self::assertSame(self::ERASURE_ROW, $erased->erasureId);

        $refusal = ErasureRefusedException::of(ErasureRefusal::TOO_MANY_KEYS, [], self::FINGERPRINT[1], self::FINGERPRINT[0]);

        try {
            $refuse = static function (string $operationId) use (&$asked, $refusal): never {
                $asked[] = $operationId;

                throw $refusal;
            };

            $records->recordedErasure('01932b4e-9000-7000-8000-0000000000a2', self::FINGERPRINT, self::authority(), $refuse);

            self::fail('Expected the refusal to be rethrown.');
        } catch (ErasureRefusedException $exception) {
            self::assertSame($refusal, $exception);
        }

        self::assertSame([self::OPERATION, '01932b4e-9000-7000-8000-0000000000a2'], $asked);
        self::assertSame(['denied:too_many_keys', 'success:'], self::endings($this->readRecords('audit_log.subject_erased')));
    }

    /**
     * A reinstatement is recorded with its row and floor, and a refused one
     * `denied` with `not_erased`, naming neither.
     *
     * @return void
     */
    public function testAReinstatementAndItsRefusalAreRecorded(): void
    {
        $records = $this->records();

        self::assertTrue($records->recordReinstated(new ReinstateResult(self::OPERATION, self::ERASURE_ROW, self::FINGERPRINT[1], self::FINGERPRINT[0], 4), self::authority()));
        self::assertTrue($records->recordReinstatementRefused('01932b4e-9000-7000-8000-0000000000a2', self::FINGERPRINT, self::authority()));

        $reinstated = $this->readRecords('audit_log.keys_reinstated');

        self::assertSame(['denied:not_erased', 'success:'], self::endings($reinstated));

        $properties = array_map(static fn (array $record): array => self::propertiesOf($record), $reinstated);

        usort($properties, static fn (array $a, array $b): int => strcmp((string) $a['outcome'], (string) $b['outcome']));

        self::assertSame([null, null, self::FINGERPRINT[1]], [$properties[0]['reinstatement_id'], $properties[0]['generation_floor'], $properties[0]['owner_fingerprint']]);
        self::assertSame([self::ERASURE_ROW, 4, self::FINGERPRINT[0]], [$properties[1]['reinstatement_id'], $properties[1]['generation_floor'], $properties[1]['fingerprint_key']]);
    }

    /**
     * A rewrap is recorded with its status and counts, and a failed one as a
     * failure that counts nothing, `journal_broken` or `rewrap_failed`.
     *
     * @return void
     */
    public function testARewrapAndItsFailuresAreRecorded(): void
    {
        $records = $this->records();
        $result  = new RewrapResult(self::OPERATION, false, true, 'd-0123456789abcdef', 2, 3, 1, ['01932b4e-f000-7000-8000-000000000001'], 2);

        self::assertTrue($records->recordRewrapped($result, self::authority()));
        self::assertTrue($records->recordRewrapFailed('01932b4e-9000-7000-8000-0000000000a2', self::authority(), JournalBrokenException::at(Finding::JOURNAL_GAP, null)));
        self::assertTrue($records->recordRewrapFailed('01932b4e-9000-7000-8000-0000000000a3', self::authority(), new \RuntimeException('The wrapper is down.')));

        $rewrapped = $this->readRecords('audit_log.keys_rewrapped');

        self::assertSame(['failure:journal_broken', 'failure:rewrap_failed', 'success:'], self::endings($rewrapped));

        foreach ($rewrapped as $record) {
            $properties = self::propertiesOf($record);
            $expected   = $record['outcome'] === 'success'
                ? ['partial', 2, 3, 1, 'd-0123456789abcdef', 2]
                : [null, null, null, null, null, null];

            self::assertSame($expected, [
                $properties['status'], $properties['keys_rewrapped'], $properties['keys_rotated'], $properties['keys_skipped'], $properties['wrap_key_id'], $properties['batches'],
            ]);
        }
    }

    /**
     * A record that cannot be written is reported once and answered `false`.
     *
     * @return void
     */
    public function testARecordThatCannotBeWrittenAnswersFalse(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.keys', ['generation_floor']);

        $result = new ReinstateResult(self::OPERATION, self::ERASURE_ROW, self::FINGERPRINT[1], self::FINGERPRINT[0], 4);

        self::assertFalse($this->records()->recordReinstated($result, self::authority()));
        self::assertSame([], $this->readRecords('audit_log.keys_reinstated'));

        $reports = $this->reporter?->reports() ?? [];

        self::assertCount(1, $reports);
        self::assertInstanceOf(LifecycleRecordFailedException::class, $reports[0]);
    }

    /**
     * An erasure's blocks name each reason once, counted 1, sorted bytewise,
     * and nothing when there is none.
     *
     * @return void
     */
    public function testTheBlocksNameEachReasonOnceSorted(): void
    {
        self::assertSame([], LifecycleRecords::blocked([]));
        self::assertSame(['held:b' => 1, 'preserved:a' => 1, 'unverified' => 1], LifecycleRecords::blocked(['unverified', 'preserved:a', 'held:b', 'unverified']));
    }

    /**
     * At most 50 reasons are named, the first bytewise, and how many more there
     * were is counted under `_other`; exactly 50 names all of them and counts
     * nothing more.
     *
     * @return void
     */
    public function testTheBlocksAreBoundedAtFifty(): void
    {
        $fifty = array_map(static fn (int $index): string => sprintf('preserved:c%03d', $index), range(1, 50));

        self::assertSame(array_fill_keys($fifty, 1), LifecycleRecords::blocked(array_reverse($fifty)));

        $bounded = LifecycleRecords::blocked([...$fifty, 'preserved:c051', 'preserved:c052', 'preserved:c051']);

        self::assertCount(51, $bounded);
        self::assertSame(2, $bounded[LifecycleRecords::OTHER]);
        self::assertArrayNotHasKey('preserved:c051', $bounded);
        self::assertSame(array_fill_keys($fifty, 1), array_diff_key($bounded, [LifecycleRecords::OTHER => true]));
    }

    /**
     * The records the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecords
     */
    private function records(): LifecycleRecords
    {
        return app(LifecycleRecords::class);
    }

    /**
     * The one record of the code; the test fails when there is not exactly one.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $code
     * @return array<string, mixed>
     */
    private function onlyRecord(string $code): array
    {
        $records = $this->readRecords($code);

        self::assertCount(1, $records);

        return $records[0];
    }

    /**
     * How each record ended, as its outcome, a colon and its reason, sorted.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<array<string, mixed>>  $records
     * @return list<string>
     */
    private static function endings(array $records): array
    {
        $endings = array_map(static fn (array $record): string => sprintf('%s:%s', $record['outcome'], $record['reason'] ?? ''), $records);

        sort($endings);

        return $endings;
    }

    /**
     * The authority every record is written on.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review');
    }
}
