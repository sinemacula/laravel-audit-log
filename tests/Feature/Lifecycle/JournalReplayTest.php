<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\WritesTheJournal;
use Tests\TestCase;

/**
 * Feature tests for the journal as a destructive decision reads it, on
 * whichever engine the suite runs against: the active holds replayed from the
 * verified hold and release rows; every finding of the chain, a contradicted
 * latest seal, a malformed payload and an invalid transition refused, fail
 * closed; advancing reads only the rows after the head and finds a truncated or
 * replaced tail; only the payloads of policies, holds and releases are read, a
 * page of them at a time; the policy versions and the last run's finish known,
 * its payload checked; a replay is a value; and the projection is never read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JournalReplay::class)]
final class JournalReplayTest extends TestCase
{
    use SealsEntries, WritesTheJournal;

    /** @var string When every row is appended. */
    private const string NOW = '2026-11-02 09:00:00.123456';

    /** @var string A hold id. */
    private const string HOLD = '01932b4e-d000-7000-8000-000000000001';

    /** @var string Another hold id. */
    private const string OTHER_HOLD = '01932b4e-d000-7000-8000-000000000002';

    /** @var string A seal id a prune row names. */
    private const string SEAL = '01932b4e-c000-7000-8000-000000000001';

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));
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
     * Each active hold is rebuilt from its verified row and payload: its id,
     * scope, basis and review date from the payload, and when, by whom, why and
     * under which operation and sequence from the row, in the order the holds
     * were placed.
     *
     * @return void
     */
    public function testActiveHoldsAreReplayedFromTheChain(): void
    {
        $scope = HoldScope::tenants(Reference::of('organisation', 'org_01'))->categories('finance');
        $first = $this->holdRow(self::HOLD, $scope, '2027-05-01T00:00:00.000000Z');

        $this->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000001']);
        $this->holdRow(self::OTHER_HOLD);

        $replay = $this->verified();
        $holds  = $replay->holds();

        self::assertSame([self::HOLD, self::OTHER_HOLD], array_map(static fn (Hold $hold): string => $hold->id, $holds));
        self::assertSame($scope->toArray(), $holds[0]->scope->toArray());
        self::assertSame(HoldBasis::LEGAL_CLAIM, $holds[0]->basis);
        self::assertSame('2027-05-01T00:00:00.000000Z', $holds[0]->reviewBy);
        self::assertSame($first->occurredAt, $holds[0]->placedAt);
        self::assertSame(['type' => 'App\Models\User', 'id' => '7'], $holds[0]->operator->toArray());
        self::assertSame('case.review', $holds[0]->reason);
        self::assertSame('app:ticket-123', $holds[0]->externalReference);
        self::assertSame($first->operationId, $holds[0]->operationId);
        self::assertSame(1, $holds[0]->journalSequence);
        self::assertSame(3, $holds[1]->journalSequence);
        self::assertNull($holds[1]->reviewBy);
        self::assertSame($holds[0], $replay->hold(self::HOLD));
    }

    /**
     * A released hold is no longer active, nor held under its id, though the
     * chain remembers it was placed.
     *
     * @return void
     */
    public function testAReleasedHoldIsNotActive(): void
    {
        $this->holdRow(self::HOLD);
        $this->holdRow(self::OTHER_HOLD);
        $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD);

        $replay = $this->verified();

        self::assertSame([self::OTHER_HOLD], array_map(static fn (Hold $hold): string => $hold->id, $replay->holds()));
        self::assertNull($replay->hold(self::HOLD));
        self::assertTrue($replay->hasPlacedHold(self::HOLD));
        self::assertFalse($replay->hasPlacedHold('01932b4e-d000-7000-8000-000000000009'));
    }

    /**
     * Rows of `[what breaks the chain of three rows, the finding, the sequence
     * of the row it is found at]`: each finding of the chain.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: \Closure(self): mixed, 1: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 2: int}>
     */
    public static function provideBrokenChains(): iterable
    {
        yield from [
            'a deleted row'     => [static fn (self $test): int => $test->journalTable()->where('sequence', 2)->delete(), Finding::JOURNAL_GAP, 3],
            'another log'       => [static fn (self $test) => $test->tamperJournal(2, ['log_id' => 'another-log']), Finding::JOURNAL_GAP, 2],
            'an edited column'  => [static fn (self $test) => $test->tamperJournal(2, ['reason' => 'other.reason']), Finding::JOURNAL_SIGNATURE, 2],
            'an edited digest'  => [static fn (self $test) => $test->tamperJournal(2, ['payload_digest' => str_repeat('c', 64)]), Finding::JOURNAL_SIGNATURE, 2],
            'an unknown key'    => [static fn (self $test) => $test->tamperJournal(2, ['key_id' => 'retired']), Finding::JOURNAL_KEY, 2],
            'an unreadable row' => [static fn (self $test) => $test->tamperJournal(2, ['kind' => 'no_such_kind']), Finding::JOURNAL_MALFORMED, 2],
            'an edited hold'    => [static fn (self $test) => $test->tamperJournal(3, ['hold_id' => self::OTHER_HOLD]), Finding::JOURNAL_SIGNATURE, 3],
        ];
    }

    /**
     * Each finding of the chain refuses the replay, naming the finding and the
     * row it was found at.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(self): mixed  $break
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @param  int  $sequence
     * @return void
     */
    #[DataProvider('provideBrokenChains')]
    public function testABrokenChainRefuses(\Closure $break, Finding $finding, int $sequence): void
    {
        $this->holdRow(self::HOLD);
        $this->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000001']);
        $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD);

        $ids = array_column($this->journalRows(), 'id', 'sequence');

        $break($this);

        $exception = $this->refusal(fn (): JournalReplay => $this->verified());

        self::assertSame($finding, $exception->finding);
        self::assertSame($ids[$sequence], $exception->rowId);
    }

    /**
     * Rows of `[what appends the invalid transition]`: a release of a hold
     * never placed, a second release, and a hold id placed twice.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: \Closure(self): mixed}>
     */
    public static function provideInvalidTransitions(): iterable
    {
        yield from [
            'a release of no hold' => [static fn (self $test): JournalRow => $test->journalRow(JournalKind::RELEASE, ['hold_id' => self::OTHER_HOLD], self::OTHER_HOLD)],
            'a double release'     => [static function (self $test): JournalRow {
                $test->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD);

                return $test->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD);
            }],
            'a hold id placed twice' => [static fn (self $test): JournalRow => $test->holdRow(self::HOLD)],
        ];
    }

    /**
     * An invalid transition refuses the replay, at the row that makes it.
     *
     * @param  \Closure(self): \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $append
     * @return void
     */
    #[DataProvider('provideInvalidTransitions')]
    public function testAnInvalidTransitionRefuses(\Closure $append): void
    {
        $this->holdRow(self::HOLD);

        $row = $append($this);

        $exception = $this->refusal(fn (): JournalReplay => $this->verified());

        self::assertSame(Finding::JOURNAL_TRANSITION, $exception->finding);
        self::assertSame($row->id, $exception->rowId);
    }

    /**
     * A journal truncated behind the latest seal, a seal committed to another
     * head, and a seal whose commitment is half set each contradict the latest
     * seal, found at the seal.
     *
     * @return void
     */
    public function testATruncatedJournalAgainstTheLatestSealRefuses(): void
    {
        $this->holdRow(self::HOLD);
        $this->holdRow(self::OTHER_HOLD);
        $this->storeEntries(1);
        $this->sealAll();

        $seal = (string) $this->seals()[0]['id'];

        self::assertSame(2, (int) $this->seals()[0]['journal_sequence']);
        self::assertSame([2, (string) $this->seals()[0]['journal_head']], $this->verified()->head());

        $this->journalTable()->where('sequence', 2)->delete();

        $exception = $this->refusal(fn (): JournalReplay => $this->verified());

        self::assertSame(Finding::JOURNAL_COMMITMENT, $exception->finding);
        self::assertSame($seal, $exception->rowId);
    }

    /**
     * An earlier seal's higher commitment contradicts a journal truncated
     * behind it even when the latest seal committed to the shorter journal, a
     * backwards commitment the sealer now refuses but may already be stored:
     * the replay is refused at the earlier seal, so a hold the truncation
     * dropped never lets a prune through.
     *
     * @return void
     */
    public function testAnEarlierSealsHigherCommitmentRefuses(): void
    {
        $first = $this->holdRow(self::HOLD);

        $this->holdRow(self::OTHER_HOLD);
        $this->storeEntries(1);
        $this->sealAll();
        $this->storeEntries(1, '2026-11-01 12:00:01.000000');
        $this->sealAll();

        [$earlier, $latest] = array_map(static fn (array $seal): string => (string) $seal['id'], $this->seals());

        $this->journalTable()->where('sequence', 2)->delete();

        $backwards = ['journal_sequence' => 1, 'journal_head' => $first->hmac];

        DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->where('id', $latest)->update($backwards);

        $exception = $this->refusal(fn (): JournalReplay => $this->verified());

        self::assertSame(Finding::JOURNAL_COMMITMENT, $exception->finding);
        self::assertSame($earlier, $exception->rowId);
    }

    /**
     * Rows of `[the commitment's columns]`: commitments of the latest seal the
     * chain contradicts.
     *
     * @return iterable<string, array{0: array<string, int|string|null>}>
     */
    public static function provideContradictedCommitments(): iterable
    {
        yield from [
            'another head at the head'    => [['journal_sequence' => 2, 'journal_head' => str_repeat('d', 64)]],
            'another head below the head' => [['journal_sequence' => 1, 'journal_head' => str_repeat('d', 64)]],
            'a sequence past the head'    => [['journal_sequence' => 3, 'journal_head' => str_repeat('d', 64)]],
            'a sequence of 0'             => [['journal_sequence' => 0, 'journal_head' => str_repeat('d', 64)]],
            'a sequence without a head'   => [['journal_sequence' => 2, 'journal_head' => null]],
            'a head without a sequence'   => [['journal_sequence' => null, 'journal_head' => str_repeat('d', 64)]],
        ];
    }

    /**
     * A latest seal whose commitment the chain contradicts refuses the replay,
     * found at the seal.
     *
     * @param  array<string, int|string|null>  $commitment
     * @return void
     */
    #[DataProvider('provideContradictedCommitments')]
    public function testAContradictedCommitmentRefuses(array $commitment): void
    {
        $this->holdRow(self::HOLD);
        $this->holdRow(self::OTHER_HOLD);
        $this->storeEntries(1);
        $this->sealAll();

        $seal = (string) $this->seals()[0]['id'];

        DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->where('id', $seal)->update($commitment);

        $exception = $this->refusal(fn (): JournalReplay => $this->verified());

        self::assertSame(Finding::JOURNAL_COMMITMENT, $exception->finding);
        self::assertSame($seal, $exception->rowId);
    }

    /**
     * A latest seal that committed to a row below the head, or to none before
     * any row was written, is no contradiction: rows may follow a seal.
     *
     * @return void
     */
    public function testRowsAfterTheLatestSealAreNoContradiction(): void
    {
        $this->storeEntries(1);
        $this->sealAll();
        $this->holdRow(self::HOLD);

        self::assertSame([self::HOLD], array_map(static fn (Hold $hold): string => $hold->id, $this->verified()->holds()));

        $this->storeEntries(1, '2026-11-01 12:00:01.000000');
        $this->sealAll();
        $this->holdRow(self::OTHER_HOLD);

        self::assertSame(1, (int) $this->seals()[1]['journal_sequence']);
        self::assertCount(2, $this->verified()->holds());
    }

    /**
     * Advancing rereads the head's HMAC and then only the rows after it, by a
     * range bound on the sequence, and reads the payloads of the new policy,
     * hold and release rows alone.
     *
     * @return void
     */
    public function testAdvanceReadsOnlyNewRows(): void
    {
        $this->holdRow(self::HOLD);
        $this->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000001']);

        $replay = $this->verified();

        $this->holdRow(self::OTHER_HOLD);
        $this->journalRow(JournalKind::PRUNE_RUN, ['run_id' => 'run-1', 'phase' => 'start']);
        $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD);

        $statements = $this->journalStatements();
        $advanced   = $replay->advance($this->maintenance());

        self::assertSame([
            ['select', [2]],
            ['select', [2]],
            ['select', [3, 5]],
        ], array_map(static fn (array $statement): array => [$statement[0], $statement[1]], $statements->getArrayCopy()));
        self::assertSame([5, JournalRow::fromRow($this->journalRows()[4], false)->hmac], $advanced->head());
        self::assertSame([self::OTHER_HOLD], array_map(static fn (Hold $hold): string => $hold->id, $advanced->holds()));
    }

    /**
     * A tail truncated below the replay's head is found by advancing, before
     * any seal commits to it: the head's row is gone.
     *
     * @return void
     */
    public function testAdvanceFindsATruncatedTail(): void
    {
        $this->holdRow(self::HOLD);
        $this->holdRow(self::OTHER_HOLD);

        $replay = $this->verified();

        $this->journalTable()->where('sequence', 2)->delete();

        $exception = $this->refusal(fn (): JournalReplay => $replay->advance($this->maintenance()));

        self::assertSame(Finding::JOURNAL_GAP, $exception->finding);
        self::assertNull($exception->rowId);
    }

    /**
     * A head replaced since the replay read it, under another HMAC, is found by
     * advancing, at the row now stored there.
     *
     * @return void
     */
    public function testAdvanceFindsAReplacedHead(): void
    {
        $this->holdRow(self::HOLD);
        $this->holdRow(self::OTHER_HOLD);

        $replay = $this->verified();
        $head   = $this->journalRows()[1]['id'];

        $this->tamperJournal(2, ['hmac' => str_repeat('e', 64)]);

        $exception = $this->refusal(fn (): JournalReplay => $replay->advance($this->maintenance()));

        self::assertSame(Finding::JOURNAL_GAP, $exception->finding);
        self::assertSame($head, $exception->rowId);
    }

    /**
     * A row after the head that breaks the chain is found by advancing, as by
     * verifying.
     *
     * @return void
     */
    public function testAdvanceFindsABrokenNewRow(): void
    {
        $this->holdRow(self::HOLD);

        $replay = $this->verified();
        $row    = $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::OTHER_HOLD], self::OTHER_HOLD);

        $exception = $this->refusal(fn (): JournalReplay => $replay->advance($this->maintenance()));

        self::assertSame(Finding::JOURNAL_TRANSITION, $exception->finding);
        self::assertSame($row->id, $exception->rowId);
    }

    /**
     * Advancing a replay of nothing yet reads the journal from its first row,
     * and advancing one at the head reads nothing new.
     *
     * @return void
     */
    public function testAdvanceOfAnEmptyReplayReadsFromTheStart(): void
    {
        $this->holdRow(self::HOLD);

        $advanced = $this->replay()->advance($this->maintenance());

        self::assertSame(1, $advanced->head()[0] ?? null);
        self::assertCount(1, $advanced->holds());
        self::assertSame($advanced->head(), $advanced->advance($this->maintenance())->head());
    }

    /**
     * Only the payloads of policy, hold and release rows are read: a prune run
     * or prune row's payload edited without its digest goes unnoticed by the
     * replay, which decides nothing from it, while a hold's edited payload is a
     * signature finding.
     *
     * @return void
     */
    public function testOnlyPolicyHoldAndReleasePayloadsAreRead(): void
    {
        $this->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000001']);
        $this->journalRow(JournalKind::PRUNE_RUN, ['run_id' => 'run-1', 'phase' => 'start']);
        $this->journalRow(JournalKind::PRUNE, ['record' => ['seal_id' => self::SEAL], 'run_id' => 'run-1'], sealId: self::SEAL);
        $this->holdRow(self::HOLD);
        $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD);

        $statements = $this->journalStatements();

        $this->verified();

        self::assertSame([[1, 4, 5]], array_values(array_map(
            static fn (array $statement): array => $statement[1],
            array_filter($statements->getArrayCopy(), static fn (array $statement): bool => preg_match('/\bpayload\b/', $statement[2]) === 1),
        )));
        self::assertSame([], array_filter($statements->getArrayCopy(), static fn (array $statement): bool => str_contains($statement[2], '*')));

        $this->tamperJournal(2, ['payload' => '{"phase":"finish","run_id":"run-9"}']);
        $this->tamperJournal(3, ['payload' => '{}']);

        self::assertCount(0, $this->verified()->holds());

        $edited = ['hold_id' => self::HOLD, 'scope' => HoldScope::all()->toArray(), 'basis' => 'other', 'review_by' => null];

        $this->tamperJournal(4, ['payload' => CanonicalEncoder::encode($edited)]);

        $exception = $this->refusal(fn (): JournalReplay => $this->verified());

        self::assertSame(Finding::JOURNAL_SIGNATURE, $exception->finding);
        self::assertSame($this->journalRows()[3]['id'], $exception->rowId);
    }

    /**
     * Payloads are read a page of such rows to a statement, so a journal of
     * more policy rows than a page reads them in two, and every version is
     * known.
     *
     * @return void
     */
    public function testPayloadsAreReadAPageAtATime(): void
    {
        for ($version = 1; $version <= JournalReplay::PAGE + 1; $version++) {
            $this->journalRow(JournalKind::POLICY, ['version' => sprintf('config:%016d', $version)]);
        }

        $statements = $this->journalStatements();
        $replay     = $this->verified();

        $payloads = array_filter($statements->getArrayCopy(), static fn (array $statement): bool => preg_match('/\bpayload\b/', $statement[2]) === 1);

        self::assertSame([JournalReplay::PAGE, 1], array_values(array_map(static fn (array $statement): int => count($statement[1]), $payloads)));
        self::assertTrue($replay->hasPolicyVersion(sprintf('config:%016d', 1)));
        self::assertTrue($replay->hasPolicyVersion(sprintf('config:%016d', JournalReplay::PAGE + 1)));
        self::assertSame(JournalReplay::PAGE + 1, $replay->head()[0] ?? null);
    }

    /**
     * Every policy version journalled is known, and no other.
     *
     * @return void
     */
    public function testThePolicyVersionsAreKnown(): void
    {
        $this->journalRow(JournalKind::POLICY, ['version' => 'config:0000000000000001', 'policy' => 'App\Retention', 'settings' => null]);
        $this->journalRow(JournalKind::POLICY, ['version' => 'custom:v2', 'policy' => 'App\Retention', 'settings' => null]);

        $replay = $this->verified();

        self::assertTrue($replay->hasPolicyVersion('config:0000000000000001'));
        self::assertTrue($replay->hasPolicyVersion('custom:v2'));
        self::assertFalse($replay->hasPolicyVersion('custom:v3'));
        self::assertFalse($this->replay()->hasPolicyVersion('custom:v2'));
    }

    /**
     * Rows of `[payload, kind, hold id]`: policy, hold and release payloads
     * that do not say what their row records.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind, 2: ?string}>
     */
    public static function provideMalformedPayloads(): iterable
    {
        $hold = ['hold_id' => self::HOLD, 'scope' => HoldScope::all()->toArray(), 'basis' => 'legal_claim', 'review_by' => null];

        yield from [
            'a policy of no version'        => [['policy' => 'App\Retention'], JournalKind::POLICY, null],
            'a policy version of a number'  => [['version' => 2], JournalKind::POLICY, null],
            'a hold of no scope'            => [array_diff_key($hold, ['scope' => true]), JournalKind::HOLD, self::HOLD],
            'a hold of a malformed scope'   => [[...$hold, 'scope' => [...HoldScope::all()->toArray(), 'v' => 2]], JournalKind::HOLD, self::HOLD],
            'a hold of another basis'       => [[...$hold, 'basis' => 'whim'], JournalKind::HOLD, self::HOLD],
            'a hold of another hold id'     => [[...$hold, 'hold_id' => self::OTHER_HOLD], JournalKind::HOLD, self::HOLD],
            'a hold whose review is a date' => [[...$hold, 'review_by' => '2027-05-01'], JournalKind::HOLD, self::HOLD],
            'a hold whose review is a list' => [[...$hold, 'review_by' => [1]], JournalKind::HOLD, self::HOLD],
        ];
    }

    /**
     * A signed payload that does not say what its row records is malformed,
     * found at its row.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $payload
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  ?string  $holdId
     * @return void
     */
    #[DataProvider('provideMalformedPayloads')]
    public function testAMalformedPayloadRefuses(array $payload, JournalKind $kind, ?string $holdId): void
    {
        $row = $this->journalRow($kind, $payload, $holdId);

        $exception = $this->refusal(fn (): JournalReplay => $this->verified());

        self::assertSame(Finding::JOURNAL_MALFORMED, $exception->finding);
        self::assertSame($row->id, $exception->rowId);
    }

    /**
     * A release whose payload names another hold than its row is malformed.
     *
     * @return void
     */
    public function testAReleaseOfAnotherHoldInItsPayloadRefuses(): void
    {
        $this->holdRow(self::HOLD);

        $row = $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::OTHER_HOLD], self::HOLD);

        $exception = $this->refusal(fn (): JournalReplay => $this->verified());

        self::assertSame(Finding::JOURNAL_MALFORMED, $exception->finding);
        self::assertSame($row->id, $exception->rowId);
    }

    /**
     * The last run's finish is the payload of the latest prune run row whose
     * phase is `finish`, past a start with no finish, read by its sequence and
     * checked against the digest its verified row signs; with no finish there
     * is none.
     *
     * @return void
     */
    public function testTheLastRunFinishIsReadAndChecked(): void
    {
        $this->journalRow(JournalKind::PRUNE_RUN, ['run_id' => 'run-1', 'phase' => 'start']);

        self::assertNull($this->verified()->lastRunFinish($this->maintenance()));

        $this->journalRow(JournalKind::PRUNE_RUN, ['run_id' => 'run-1', 'phase' => 'finish', 'remaining' => 0]);
        $this->journalRow(JournalKind::PRUNE_RUN, ['run_id' => 'run-2', 'phase' => 'start']);
        $this->journalRow(JournalKind::PRUNE_RUN, ['run_id' => 'run-2', 'phase' => 'finish', 'remaining' => 7]);
        $this->journalRow(JournalKind::PRUNE_RUN, ['run_id' => 'run-3', 'phase' => 'start']);
        $this->holdRow(self::HOLD);

        $replay = $this->verified();

        self::assertSame(['phase' => 'finish', 'remaining' => 7, 'run_id' => 'run-2'], $replay->lastRunFinish($this->maintenance()));

        $this->tamperJournal(4, ['payload' => '{"phase":"finish","remaining":0,"run_id":"run-2"}']);

        $exception = $this->refusal(fn (): ?array => $replay->lastRunFinish($this->maintenance()));

        self::assertSame(Finding::JOURNAL_SIGNATURE, $exception->finding);
        self::assertSame($this->journalRows()[3]['id'], $exception->rowId);

        $this->journalTable()->where('sequence', 4)->delete();

        $exception = $this->refusal(fn (): ?array => $replay->lastRunFinish($this->maintenance()));

        self::assertSame(Finding::JOURNAL_GAP, $exception->finding);
        self::assertNull($exception->rowId);
    }

    /**
     * A run row whose payload was replaced by text that is not a canonical map
     * is malformed when the finish is read.
     *
     * @return void
     */
    public function testAnUnreadableRunPayloadIsMalformed(): void
    {
        $row    = $this->journalRow(JournalKind::PRUNE_RUN, ['run_id' => 'run-1', 'phase' => 'finish']);
        $replay = $this->verified();

        $this->tamperJournal(1, ['payload' => '{"run_id": "run-1"}']);

        $exception = $this->refusal(fn (): ?array => $replay->lastRunFinish($this->maintenance()));

        self::assertSame(Finding::JOURNAL_MALFORMED, $exception->finding);
        self::assertSame($row->id, $exception->rowId);
    }

    /**
     * The finish is found among more run rows than a page: the latest page is
     * read first, and an earlier page only when it holds no finish.
     *
     * @return void
     */
    public function testTheLastRunFinishIsFoundPastAPageOfStarts(): void
    {
        $this->journalRow(JournalKind::PRUNE_RUN, ['run_id' => 'run-0', 'phase' => 'finish']);

        for ($run = 1; $run <= JournalReplay::PAGE; $run++) {
            $this->journalRow(JournalKind::PRUNE_RUN, ['run_id' => 'run-' . $run, 'phase' => 'start']);
        }

        self::assertSame(['phase' => 'finish', 'run_id' => 'run-0'], $this->verified()->lastRunFinish($this->maintenance()));
    }

    /**
     * A replay is a value: advancing or accepting returns a new replay and
     * leaves the one it was called on as it was, and verifying again starts
     * afresh whatever the replay held.
     *
     * @return void
     */
    public function testAReplayIsAValue(): void
    {
        $this->holdRow(self::HOLD);

        $replay = $this->verified();

        $this->holdRow(self::OTHER_HOLD);

        $advanced = $replay->advance($this->maintenance());

        self::assertSame(1, $replay->head()[0] ?? null);
        self::assertCount(1, $replay->holds());
        self::assertFalse($replay->hasPlacedHold(self::OTHER_HOLD));
        self::assertSame(2, $advanced->head()[0] ?? null);
        self::assertCount(2, $advanced->holds());
        self::assertSame($advanced->head(), $replay->verify($this->maintenance())->head());
        self::assertSame($replay->head(), $replay->head());
    }

    /**
     * Accepting a signed row onto the head replays it as reading it would: a
     * policy's version is known, a hold is active and its release is not, a
     * prune run's finish is found by its digest once stored, and the row is the
     * last appended; the replay it was called on is left as it was.
     *
     * @return void
     */
    public function testAcceptReplaysTheRowItAccepts(): void
    {
        $empty  = $this->verified();
        $policy = $empty->accept($this->draftOnto($empty, JournalKind::POLICY, ['version' => 'custom:v1']));

        self::assertTrue($policy->hasPolicyVersion('custom:v1'));
        self::assertFalse($empty->hasPolicyVersion('custom:v1'));
        self::assertNull($empty->head());
        self::assertSame([1, $policy->lastAppended()?->hmac], $policy->head());

        $payload = ['hold_id' => self::HOLD, 'scope' => HoldScope::all()->toArray(), 'basis' => 'regulatory', 'review_by' => null];
        $held    = $policy->accept($this->draftOnto($policy, JournalKind::HOLD, $payload, self::HOLD));

        self::assertSame([self::HOLD], array_map(static fn (Hold $hold): string => $hold->id, $held->holds()));
        self::assertSame(HoldBasis::REGULATORY, $held->hold(self::HOLD)?->basis);
        self::assertSame([], $policy->holds());

        $finish = $this->draftOnto($held, JournalKind::PRUNE_RUN, ['run_id' => 'run-1', 'phase' => 'finish']);
        $run    = $held->accept($finish);

        $this->journalTable()->insert($finish->toRow());

        self::assertSame(['phase' => 'finish', 'run_id' => 'run-1'], $run->lastRunFinish($this->maintenance()));
        self::assertNull($held->lastRunFinish($this->maintenance()));

        $released = $run->accept($this->draftOnto($run, JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD));

        self::assertSame([], $released->holds());
        self::assertTrue($released->hasPlacedHold(self::HOLD));
        self::assertCount(1, $run->holds());
    }

    /**
     * A row the chain refuses is not accepted: a release of a hold never placed
     * is a transition, and a row signed for another place in the chain a gap,
     * each refused with the replay left as it was.
     *
     * @return void
     */
    public function testAcceptRefusesARowTheChainRefuses(): void
    {
        $replay = $this->verified();

        $exception = $this->refusal(fn (): JournalReplay => $replay->accept($this->draftOnto($replay, JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD)));

        self::assertSame(Finding::JOURNAL_TRANSITION, $exception->finding);

        $policy = $replay->accept($this->draftOnto($replay, JournalKind::POLICY, ['version' => 'custom:v1']));

        $exception = $this->refusal(fn (): JournalReplay => $policy->accept($this->draftOnto($replay, JournalKind::POLICY, ['version' => 'custom:v2'])));

        self::assertSame(Finding::JOURNAL_GAP, $exception->finding);
        self::assertSame(1, $policy->head()[0] ?? null);
        self::assertNull($replay->head());
    }

    /**
     * A hold accepted with a payload that does not describe a hold is
     * malformed, and nothing is accepted.
     *
     * @return void
     */
    public function testAcceptRefusesAMalformedHold(): void
    {
        $replay = $this->verified();
        $row    = $this->draftOnto($replay, JournalKind::HOLD, ['hold_id' => self::HOLD, 'basis' => 'legal_claim'], self::HOLD);

        $exception = $this->refusal(fn (): JournalReplay => $replay->accept($row));

        self::assertSame(Finding::JOURNAL_MALFORMED, $exception->finding);
        self::assertSame($row->id, $exception->rowId);
        self::assertSame([], $replay->holds());
    }

    /**
     * The holds projection is never read: a projection row deleted by hand
     * leaves its hold active, and one inserted by hand adds none.
     *
     * @return void
     */
    public function testAProjectionRowDeletedChangesNothing(): void
    {
        $hold = app(HoldKeeper::class)->place('01932b4e-9000-7000-8000-0000000000a1', HoldScope::all(), self::authority(), HoldBasis::INVESTIGATION, null);

        DB::connection(StorageConnection::name())->table(LifecycleTables::holdsTable())->delete();

        $replay = $this->verified();

        self::assertSame([$hold->id], array_map(static fn (Hold $active): string => $active->id, $replay->holds()));
        self::assertSame($hold->toArray(), $replay->holds()[0]->toArray());
    }

    /**
     * An empty journal replays nothing: no head, no hold, no policy version and
     * no finish.
     *
     * @return void
     */
    public function testAnEmptyJournalReplaysNothing(): void
    {
        $replay = $this->verified();

        self::assertNull($replay->head());
        self::assertSame([], $replay->holds());
        self::assertNull($replay->lastAppended());
        self::assertNull($replay->lastRunFinish($this->maintenance()));
    }

    /**
     * Append a hold of the id, of the scope and review date given or every
     * entry and none, signed at the next sequence by the default authority,
     * with an external reference; public, so a provider's closure can call it.
     *
     * @param  string  $holdId
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $scope
     * @param  ?string  $reviewBy
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    public function holdRow(string $holdId, ?HoldScope $scope = null, ?string $reviewBy = null): JournalRow
    {
        $payload = ['hold_id' => $holdId, 'scope' => ($scope ?? HoldScope::all())->toArray(), 'basis' => 'legal_claim', 'review_by' => $reviewBy];

        return $this->journalRow(JournalKind::HOLD, $payload, $holdId, externalReference: 'app:ticket-123');
    }

    /**
     * A row of the kind signed onto the replay's head: the next sequence,
     * linked to the head's HMAC, in the configured log, at the clock's time,
     * with the default authority when the kind carries one.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  array<array-key, mixed>  $payload
     * @param  ?string  $holdId
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private function draftOnto(JournalReplay $replay, JournalKind $kind, array $payload, ?string $holdId = null): JournalRow
    {
        $head      = $replay->head();
        $authority = $kind->carriesAuthority() ? self::JOURNAL_AUTHORITY : null;
        $now       = CarbonImmutable::now();

        $draft = JournalRow::draft(
            Str::uuid7($now)->toString(),
            ($head[0] ?? 0) + 1,
            app(SealSettings::class)->logId(),
            $kind,
            '01932b4e-9000-7000-8000-0000000000a1',
            StoredTime::format($now),
            $authority,
            $authority === null ? null : self::JOURNAL_REASON,
            null,
            null,
            $holdId,
            $payload,
            $head[1] ?? null,
        );

        return app(JournalSigner::class)->sign($draft);
    }

    /**
     * A query of the journal table on the storage connection's writer.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function journalTable(): Builder
    {
        return DB::connection(StorageConnection::name())->table(LifecycleTables::journalTable())->useWritePdo();
    }

    /**
     * Record each statement that reads the journal table from now on, as its
     * verb, its bindings and its SQL.
     *
     * @return \ArrayObject<int, array{0: string, 1: list<int|string|null>, 2: string}>
     */
    private function journalStatements(): \ArrayObject
    {
        /** @var \ArrayObject<int, array{0: string, 1: list<int|string|null>, 2: string}> $log */
        $log     = new \ArrayObject;
        $journal = LifecycleTables::journalTable();

        DB::listen(static function (QueryExecuted $query) use ($log, $journal): void {
            if (!preg_match('/\b' . $journal . '\b/', $query->sql)) {
                return;
            }

            /** @var list<int|string|null> $bindings */
            $bindings = array_map(static fn (mixed $binding): int|string|null => is_numeric($binding) ? (int) $binding : (is_string($binding) ? $binding : null), $query->bindings);

            $log->append([strtolower(strtok($query->sql, ' ') ?: ''), $bindings, $query->sql]);
        });

        return $log;
    }

    /**
     * What the call throws, as the journal broken; fails the test otherwise.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     */
    private function refusal(\Closure $call): JournalBrokenException
    {
        try {
            $call();
        } catch (JournalBrokenException $exception) {
            return $exception;
        }

        self::fail('Expected the journal to be refused as broken.');
    }

    /**
     * A replay of the whole journal, verified on the maintenance connection.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay
     */
    private function verified(): JournalReplay
    {
        return $this->replay()->verify($this->maintenance());
    }

    /**
     * A replay of nothing yet, of the configured log.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay
     */
    private function replay(): JournalReplay
    {
        return JournalReplay::start(app(JournalSigner::class), app(SealSettings::class)->logId());
    }

    /**
     * The maintenance connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function maintenance(): Connection
    {
        $connection = DB::connection(StorageConnection::forMaintenance());

        self::assertInstanceOf(Connection::class, $connection);

        return $connection;
    }

    /**
     * The authority every hold is placed with.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review');
    }
}
