<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\JournalChain;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;

/**
 * Unit tests for the journal's chain: a contiguous chain with no finding, each
 * gap (a missing, reordered or relinked row, or one of another log), a forged
 * row and an edited payload as signature findings, an unknown key as
 * unverifiable, a malformed row, each transition the chain refuses (releases,
 * hold ids placed again, prune rows of another seal, and, with payloads, runs
 * and batches finished without their start or twice), a bad row that is never
 * applied and counts once, the active holds, and a clone that is independent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JournalChain::class)]
final class JournalChainTest extends TestCase
{
    /** @var string The log every row belongs to. */
    private const string LOG_ID = 'app-eu-1';

    /** @var string The golden secret, the ring key `k2026`. */
    private const string SECRET = 'audit-log golden key 0123456789!';

    /** @var string A hold id. */
    private const string HOLD = '01932b4e-d000-7000-8000-000000000001';

    /** @var string Another hold id. */
    private const string OTHER_HOLD = '01932b4e-d000-7000-8000-000000000002';

    /** @var string A seal id. */
    private const string SEAL = '01932b4e-9000-7000-8000-000000000001';

    /** @var string A prune run's id. */
    private const string RUN = '01932b4e-e000-7000-8000-000000000001';

    /** @var string An import batch's id. */
    private const string BATCH = '01932b4e-f000-7000-8000-000000000001';

    /**
     * Every kind in a valid order, each row linked to the one before it, gives
     * no finding, and the head is the last row.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAContiguousChainHasNoFinding(): void
    {
        $rows  = self::everyKind();
        $chain = self::chain();

        foreach ($rows as $row) {
            self::assertSame([], $chain->accept($row), $row->kind->value);
        }

        $last = end($rows);

        self::assertInstanceOf(JournalRow::class, $last);

        self::assertFalse($chain->isBroken());
        self::assertSame(count($rows), $chain->rows());
        self::assertSame([$last->sequence, $last->hmac], $chain->head());
        self::assertSame([], $chain->activeHoldIds());
        self::assertTrue($chain->hasPlaced(self::HOLD));
        self::assertFalse($chain->hasPlaced(self::OTHER_HOLD));
    }

    /**
     * An empty chain has no head, no rows and no finding.
     *
     * @return void
     */
    public function testAnEmptyChainHasNoHead(): void
    {
        $chain = self::chain();

        self::assertNull($chain->head());
        self::assertSame(0, $chain->rows());
        self::assertFalse($chain->isBroken());
        self::assertSame([], $chain->activeHoldIds());
    }

    /**
     * A first row that is not at sequence 1 is a gap, and so is a row whose
     * predecessor is missing; the row after the gap follows it, so a deleted
     * row is one finding.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAMissingRowIsAGap(): void
    {
        [$first, $second, $third, $fourth] = self::sequence(4);

        $chain = self::chain();

        self::assertSame([], $chain->accept($first));
        self::assertSame([[Finding::JOURNAL_GAP, $third->id]], $chain->accept($third));
        self::assertSame([], $chain->accept($fourth));
        self::assertSame([4, $fourth->hmac], $chain->head());
        self::assertTrue($chain->isBroken());

        $late = self::chain();

        self::assertSame([[Finding::JOURNAL_GAP, $second->id]], $late->accept($second));
    }

    /**
     * A row read out of order is a gap, and so is the one read after it; a row
     * that does not move the chain forward never moves its head back.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAReorderedRowIsAGap(): void
    {
        [$first, $second, $third] = self::sequence(3);

        $chain = self::chain();

        $chain->accept($first);

        self::assertSame([[Finding::JOURNAL_GAP, $third->id]], $chain->accept($third));
        self::assertSame([[Finding::JOURNAL_GAP, $second->id]], $chain->accept($second));
        self::assertSame([3, $third->hmac], $chain->head());

        $repeated = self::chain();

        $repeated->accept($first);

        self::assertSame([[Finding::JOURNAL_GAP, $first->id]], $repeated->accept($first));
        self::assertSame(2, $repeated->rows());
    }

    /**
     * A row signed with a previous HMAC that is not its predecessor's is a gap,
     * however good its signature.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARelinkedRowIsAGap(): void
    {
        [$first] = self::sequence(1);

        $relinked = self::sign(self::draft(JournalKind::POLICY, 2, str_repeat('c', 64)));
        $chain    = self::chain();

        $chain->accept($first);

        self::assertSame([[Finding::JOURNAL_GAP, $relinked->id]], $chain->accept($relinked));
        self::assertSame([2, $relinked->hmac], $chain->head());
    }

    /**
     * A first row that names a row before it, and a later row that names none,
     * are each a gap, however good their signatures.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAStoredRowBreakingTheFirstRowsRuleIsAGap(): void
    {
        [$first, $second] = self::sequence(2);

        $linked   = JournalRow::fromRow([...$first->toRow(), 'previous_hmac' => $second->hmac], true);
        $unlinked = JournalRow::fromRow([...$second->toRow(), 'previous_hmac' => null], true);
        $chain    = self::chain();

        self::assertSame([[Finding::JOURNAL_GAP, $first->id], [Finding::JOURNAL_SIGNATURE, $first->id]], $chain->accept($linked));
        self::assertSame([[Finding::JOURNAL_GAP, $second->id], [Finding::JOURNAL_SIGNATURE, $second->id]], $chain->accept($unlinked));
    }

    /**
     * A row of another log is a gap, even signed and linked.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARowOfAnotherLogIsAGap(): void
    {
        $other = self::sign(self::draft(JournalKind::POLICY, 1, null, logId: 'app-eu-2'));

        self::assertSame([[Finding::JOURNAL_GAP, $other->id]], self::chain()->accept($other));
    }

    /**
     * A row whose signed column was edited, its HMAC kept, is a signature
     * finding: it is never applied, the head stays the last good row, and the
     * row after it still follows it as stored, so it is one finding.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAForgedRowIsASignatureFinding(): void
    {
        [$first, $second, $third] = self::sequence(3);

        $forged = JournalRow::fromRow([...$second->toRow(), 'reason' => 'case.forged'], true);
        $chain  = self::chain();

        $chain->accept($first);

        self::assertSame([[Finding::JOURNAL_SIGNATURE, $forged->id]], $chain->accept($forged));
        self::assertSame([1, $first->hmac], $chain->head());
        self::assertSame([], $chain->accept($third));
        self::assertSame([3, $third->hmac], $chain->head());
    }

    /**
     * A payload read with its row that is not the text its digest was taken of
     * is a signature finding, however good the row's HMAC.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnEditedPayloadIsASignatureFinding(): void
    {
        $hold   = self::sign(self::draft(JournalKind::HOLD, 1, null, holdId: self::HOLD, payload: ['hold_id' => self::HOLD]));
        $edited = JournalRow::fromRow([...$hold->toRow(), 'payload' => '{"hold_id":"' . self::OTHER_HOLD . '"}'], true);
        $chain  = self::chain();

        self::assertSame([[Finding::JOURNAL_SIGNATURE, $edited->id]], $chain->accept($edited));
        self::assertSame([], $chain->activeHoldIds());
        self::assertFalse($chain->hasPlaced(self::HOLD));
    }

    /**
     * A row signed under a key the ring does not hold is unverifiable, and is
     * never applied.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnUnknownKeyIsAJournalKeyFinding(): void
    {
        $foreign = new JournalSigner(self::ring(['k2024' => 'audit-log foreign key 0123456789!']));
        $row     = $foreign->sign(self::draft(JournalKind::HOLD, 1, null, holdId: self::HOLD));
        $chain   = self::chain();

        self::assertSame([[Finding::JOURNAL_KEY, $row->id]], $chain->accept($row));
        self::assertNull($chain->head());
        self::assertSame([], $chain->activeHoldIds());
    }

    /**
     * A row that could not be signed, as a draft is, is malformed.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnUnsignedRowIsMalformed(): void
    {
        $draft = self::draft(JournalKind::POLICY, 1, null);
        $chain = self::chain();

        self::assertSame([[Finding::JOURNAL_MALFORMED, $draft->id]], $chain->accept($draft));
        self::assertNull($chain->head());
        self::assertTrue($chain->isBroken());
    }

    /**
     * A row that cannot be read is one malformed finding, by the id given: the
     * row after it has nothing to link to and is held only to a later sequence,
     * and a row before the last read is still a gap.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAMalformedRowBreaksTheChainOnce(): void
    {
        [$first, $second, $third] = self::sequence(3);

        $chain = self::chain();

        $chain->accept($first);

        self::assertSame([[Finding::JOURNAL_MALFORMED, 'row-2']], $chain->acceptMalformed('row-2'));
        self::assertSame([], $chain->accept($third));
        self::assertSame([[Finding::JOURNAL_GAP, $second->id]], $chain->accept($second));
        self::assertSame([[Finding::JOURNAL_MALFORMED, null]], $chain->acceptMalformed(null));
        self::assertSame([[Finding::JOURNAL_GAP, $first->id]], $chain->accept($first));
        self::assertSame(6, $chain->rows());
        self::assertTrue($chain->isBroken());
        self::assertSame([3, $third->hmac], $chain->head());

        $leading = self::chain();

        $leading->acceptMalformed(null);

        self::assertSame([], $leading->accept($second));
    }

    /**
     * A release of a hold never placed, or of no hold, is a transition the
     * chain refuses.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAReleaseOfAnUnknownHoldIsATransition(): void
    {
        $release = self::sign(self::draft(JournalKind::RELEASE, 1, null, holdId: self::HOLD));
        $none    = self::sign(self::draft(JournalKind::RELEASE, 2, $release->hmac));
        $chain   = self::chain();

        self::assertSame([[Finding::JOURNAL_TRANSITION, $release->id]], $chain->accept($release));
        self::assertSame([[Finding::JOURNAL_TRANSITION, $none->id]], $chain->accept($none));
        self::assertSame([2, $none->hmac], $chain->head());
    }

    /**
     * A second release of one hold is a transition the chain refuses.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testADoubleReleaseIsATransition(): void
    {
        $rows  = self::linked([[JournalKind::HOLD, self::HOLD], [JournalKind::RELEASE, self::HOLD], [JournalKind::RELEASE, self::HOLD]]);
        $chain = self::chain();

        self::assertSame([], $chain->accept($rows[0]));
        self::assertSame([], $chain->accept($rows[1]));
        self::assertSame([[Finding::JOURNAL_TRANSITION, $rows[2]->id]], $chain->accept($rows[2]));
    }

    /**
     * A hold id placed while it is active is a transition, and so is a hold
     * that names no hold id.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAHoldIdPlacedTwiceIsATransition(): void
    {
        $rows  = self::linked([[JournalKind::HOLD, self::HOLD], [JournalKind::HOLD, self::HOLD], [JournalKind::HOLD, null]]);
        $chain = self::chain();

        $chain->accept($rows[0]);

        self::assertSame([[Finding::JOURNAL_TRANSITION, $rows[1]->id]], $chain->accept($rows[1]));
        self::assertSame([[Finding::JOURNAL_TRANSITION, $rows[2]->id]], $chain->accept($rows[2]));
        self::assertSame([self::HOLD], $chain->activeHoldIds());
    }

    /**
     * A hold id placed again after its release is a transition: hold ids are
     * never reused, and the refused hold is not active.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAReleasedHoldIdPlacedAgainIsATransition(): void
    {
        $rows  = self::linked([[JournalKind::HOLD, self::HOLD], [JournalKind::RELEASE, self::HOLD], [JournalKind::HOLD, self::HOLD]]);
        $chain = self::chain();

        $chain->accept($rows[0]);
        $chain->accept($rows[1]);

        self::assertSame([[Finding::JOURNAL_TRANSITION, $rows[2]->id]], $chain->accept($rows[2]));
        self::assertSame([], $chain->activeHoldIds());
        self::assertTrue($chain->hasPlaced(self::HOLD));
    }

    /**
     * A prune row whose record covers another seal than the one it names is a
     * transition, and so is one that names no seal or holds no record; read
     * without its payload, only the seal it names is checked.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAPruneRowNamingAnotherSealIsATransition(): void
    {
        $payloads = [
            'another seal' => ['run_id' => self::RUN, 'record' => ['seal_id' => '01932b4e-9000-7000-8000-000000000002']],
            'no record'    => ['run_id' => self::RUN],
            'no seal'      => ['run_id' => self::RUN, 'record' => ['v' => 2]],
            'a list'       => ['run_id' => self::RUN, 'record' => 'seal'],
        ];

        foreach ($payloads as $what => $payload) {
            [$start, $prune] = self::linked([[JournalKind::PRUNE_RUN, null, ['run_id' => self::RUN, 'phase' => 'start']], [JournalKind::PRUNE, null, $payload, self::SEAL]]);

            $chain = self::chain();

            $chain->accept($start);

            self::assertSame([[Finding::JOURNAL_TRANSITION, $prune->id]], $chain->accept($prune), $what);
        }

        [$start, $sealless] = self::linked([[JournalKind::PRUNE_RUN, null, ['run_id' => self::RUN, 'phase' => 'start']], [JournalKind::PRUNE, null, [], null]]);

        $chain = self::chain();

        $chain->accept(self::withoutPayload($start));

        self::assertSame([[Finding::JOURNAL_TRANSITION, $sealless->id]], $chain->accept(self::withoutPayload($sealless)));
    }

    /**
     * Rows of `[the rows, the index of the one refused]`: a prune run's finish
     * with no start, an import's finish with no start, and a prune chunk of no
     * open run.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind, 1: ?string, 2?: array<string, array<string, string>|int|string>, 3?: ?string}>, 1: int}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideFinishesWithoutTheirStart(): iterable
    {
        $record = ['seal_id' => self::SEAL];
        $start  = [JournalKind::PRUNE_RUN, null, ['run_id' => self::RUN, 'phase' => 'start']];

        yield from [
            'a prune run'          => [[[JournalKind::PRUNE_RUN, null, ['run_id' => self::RUN, 'phase' => 'finish']]], 0],
            'an import batch'      => [[[JournalKind::IMPORT_FINISHED, null, ['batch_id' => self::BATCH]]], 0],
            'a prune row'          => [[[JournalKind::PRUNE, null, ['run_id' => self::RUN, 'record' => $record], self::SEAL]], 0],
            'another run'          => [[$start, [JournalKind::PRUNE_RUN, null, ['run_id' => self::BATCH, 'phase' => 'finish']]], 1],
            'a prune of no run id' => [[$start, [JournalKind::PRUNE, null, ['record' => $record], self::SEAL]], 1],
            'a batch with no id'   => [[[JournalKind::IMPORT_STARTED, null, ['batch_id' => self::BATCH]], [JournalKind::IMPORT_FINISHED, null, []]], 1],
            'an unnamed start'     => [[[JournalKind::IMPORT_STARTED, null, ['batch_id' => 7]]], 0],
            'a phase of neither'   => [[[JournalKind::PRUNE_RUN, null, ['run_id' => self::RUN, 'phase' => 'resume']]], 0],
        ];
    }

    /**
     * Read with their payloads, a finish whose run or batch has no open start
     * is a transition, and so is a prune chunk of no open run.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind, 1: ?string, 2?: array<string, array<string, int|string>|int|string>, 3?: ?string}>  $specs
     * @param  int  $refused
     * @return void
     *
     * @throws \JsonException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[DataProvider('provideFinishesWithoutTheirStart')]
    public function testAFinishWithoutItsStartIsATransition(array $specs, int $refused): void
    {
        $rows  = self::linked($specs);
        $chain = self::chain();

        foreach ($rows as $index => $row) {
            self::assertSame($index === $refused ? [[Finding::JOURNAL_TRANSITION, $row->id]] : [], $chain->accept($row), (string) $index);
        }
    }

    /**
     * A second finish of one run or one batch is a transition, and so is a
     * second start of a run or a batch still open: each is dropped at its
     * finish.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testASecondFinishIsATransition(): void
    {
        $rows = self::linked([
            [JournalKind::PRUNE_RUN, null, ['run_id' => self::RUN, 'phase' => 'start']],
            [JournalKind::PRUNE_RUN, null, ['run_id' => self::RUN, 'phase' => 'start']],
            [JournalKind::PRUNE_RUN, null, ['run_id' => self::RUN, 'phase' => 'finish']],
            [JournalKind::PRUNE_RUN, null, ['run_id' => self::RUN, 'phase' => 'finish']],
            [JournalKind::IMPORT_STARTED, null, ['batch_id' => self::BATCH]],
            [JournalKind::IMPORT_STARTED, null, ['batch_id' => self::BATCH]],
            [JournalKind::IMPORT_FINISHED, null, ['batch_id' => self::BATCH]],
            [JournalKind::IMPORT_FINISHED, null, ['batch_id' => self::BATCH]],
        ]);

        $chain = self::chain();
        $found = array_map(static fn (JournalRow $row): int => count($chain->accept($row)), $rows);

        self::assertSame([0, 1, 0, 1, 0, 1, 0, 1], $found);
    }

    /**
     * Read without their payloads, as the pruner reads every row but a policy,
     * a hold and a release, a run's and a batch's rows are not paired.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testPairingIsNotCheckedWithoutPayloads(): void
    {
        $rows = self::linked([
            [JournalKind::PRUNE_RUN, null, ['run_id' => self::RUN, 'phase' => 'finish']],
            [JournalKind::PRUNE, null, ['run_id' => self::RUN, 'record' => ['seal_id' => self::OTHER_HOLD]], self::SEAL],
            [JournalKind::IMPORT_FINISHED, null, ['batch_id' => self::BATCH]],
            [JournalKind::IMPORT_FINISHED, null, ['batch_id' => self::BATCH]],
        ]);

        $chain = self::chain();

        foreach ($rows as $row) {
            self::assertSame([], $chain->accept(self::withoutPayload($row)), $row->kind->value);
        }

        self::assertFalse($chain->isBroken());
    }

    /**
     * A bad row is never applied: a forged hold places nothing, so a later
     * release of it is refused, and each bad row is one finding.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testABadRowIsNotAppliedAndCountsOnce(): void
    {
        $rows   = self::linked([[JournalKind::HOLD, self::HOLD], [JournalKind::HOLD, self::OTHER_HOLD], [JournalKind::RELEASE, self::OTHER_HOLD]]);
        $forged = JournalRow::fromRow([...$rows[1]->toRow(), 'external_reference' => 'CASE-FORGED'], true);
        $chain  = self::chain();

        self::assertSame([], $chain->accept($rows[0]));
        self::assertSame([[Finding::JOURNAL_SIGNATURE, $forged->id]], $chain->accept($forged));
        self::assertSame([[Finding::JOURNAL_TRANSITION, $rows[2]->id]], $chain->accept($rows[2]));
        self::assertSame([self::HOLD], $chain->activeHoldIds());
        self::assertFalse($chain->hasPlaced(self::OTHER_HOLD));
        self::assertSame(3, $chain->rows());
    }

    /**
     * The active holds follow the chain, in the order they were placed: each
     * placed, each released, a refused release changing nothing.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheActiveHoldsFollowTheChain(): void
    {
        $third = '01932b4e-d000-7000-8000-000000000003';
        $rows  = self::linked([
            [JournalKind::HOLD, self::OTHER_HOLD],
            [JournalKind::HOLD, self::HOLD],
            [JournalKind::HOLD, $third],
            [JournalKind::RELEASE, self::HOLD],
            [JournalKind::POLICY, null],
        ]);

        $chain  = self::chain();
        $active = [];

        foreach ($rows as $row) {
            $chain->accept($row);

            $active[] = $chain->activeHoldIds();
        }

        self::assertSame([
            [self::OTHER_HOLD],
            [self::OTHER_HOLD, self::HOLD],
            [self::OTHER_HOLD, self::HOLD, $third],
            [self::OTHER_HOLD, $third],
            [self::OTHER_HOLD, $third],
        ], $active);
        self::assertFalse($chain->isBroken());
    }

    /**
     * A clone of a chain is independent of it: rows read by either change
     * neither the other's head, its holds, its open runs, nor its findings.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testACloneIsIndependent(): void
    {
        $rows = self::linked([
            [JournalKind::HOLD, self::HOLD],
            [JournalKind::PRUNE_RUN, null, ['run_id' => self::RUN, 'phase' => 'start']],
            [JournalKind::RELEASE, self::HOLD],
            [JournalKind::PRUNE_RUN, null, ['run_id' => self::RUN, 'phase' => 'finish']],
        ]);

        $chain = self::chain();

        $chain->accept($rows[0]);
        $chain->accept($rows[1]);

        $clone = clone $chain;

        self::assertSame([], $clone->accept($rows[2]));
        self::assertSame([], $clone->accept($rows[3]));
        self::assertSame([], $clone->activeHoldIds());
        self::assertSame([self::HOLD], $chain->activeHoldIds());
        self::assertSame([2, $rows[1]->hmac], $chain->head());
        self::assertSame(2, $chain->rows());
        self::assertSame([], $chain->accept($rows[2]));
        self::assertSame([], $chain->accept($rows[3]));

        $clone->acceptMalformed(null);

        self::assertTrue($clone->isBroken());
        self::assertFalse($chain->isBroken());
    }

    /**
     * One row of every kind, linked, in an order the chain allows.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\JournalRow>
     */
    private static function everyKind(): array
    {
        return self::linked([
            [JournalKind::POLICY, null, ['version' => 'config:0123456789abcdef']],
            [JournalKind::HOLD, self::HOLD, ['hold_id' => self::HOLD]],
            [JournalKind::PRUNE_RUN, null, ['run_id' => self::RUN, 'phase' => 'start']],
            [JournalKind::PRUNE, null, ['run_id' => self::RUN, 'record' => ['seal_id' => self::SEAL]], self::SEAL],
            [JournalKind::PRUNE_RUN, null, ['run_id' => self::RUN, 'phase' => 'finish']],
            [JournalKind::RELEASE, self::HOLD, ['hold_id' => self::HOLD]],
            [JournalKind::IMPORT_STARTED, null, ['batch_id' => self::BATCH]],
            [JournalKind::IMPORT_FINISHED, null, ['batch_id' => self::BATCH]],
        ]);
    }

    /**
     * The number of policy rows, signed and linked from sequence 1.
     *
     * @param  int  $count
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\JournalRow>
     */
    private static function sequence(int $count): array
    {
        return self::linked(array_fill(0, $count, [JournalKind::POLICY, null]));
    }

    /**
     * The rows of each kind, hold id, payload and seal id given, signed and
     * linked from sequence 1.
     *
     * @param  list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind, 1: ?string, 2?: array<string, array<string, int|string>|int|string>, 3?: ?string}>  $specs
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\JournalRow>
     */
    private static function linked(array $specs): array
    {
        $rows     = [];
        $previous = null;

        foreach ($specs as $index => $spec) {
            $row      = self::sign(self::draft($spec[0], $index + 1, $previous, holdId: $spec[1], payload: $spec[2] ?? [], sealId: $spec[3] ?? null));
            $rows[]   = $row;
            $previous = $row->hmac;
        }

        return $rows;
    }

    /**
     * An unsigned row of the kind at the sequence, linked to the HMAC given.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  int  $sequence
     * @param  ?string  $previous
     * @param  ?string  $holdId
     * @param  array<string, array<string, int|string>|int|string>  $payload
     * @param  ?string  $sealId
     * @param  string  $logId
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private static function draft(
        JournalKind $kind,
        int $sequence,
        ?string $previous,
        ?string $holdId = null,
        array $payload = [],
        ?string $sealId = null,
        string $logId = self::LOG_ID,
    ): JournalRow {
        $authority = $kind->carriesAuthority() ? ['App\Models\User', '7'] : null;

        return JournalRow::draft(
            sprintf('01932b4e-b000-7000-8000-%012d', $sequence),
            $sequence,
            $logId,
            $kind,
            '01932b4e-c000-7000-8000-000000000001',
            '2026-10-31T23:42:00.000000Z',
            $authority,
            $authority === null ? null : 'case.review',
            null,
            $sealId,
            $holdId,
            $payload,
            $previous,
        );
    }

    /**
     * The row as it reads without its payload.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private static function withoutPayload(JournalRow $row): JournalRow
    {
        return JournalRow::fromRow($row->toRow(), false);
    }

    /**
     * The row signed under the golden key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $draft
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private static function sign(JournalRow $draft): JournalRow
    {
        return self::signer()->sign($draft);
    }

    /**
     * A chain of the log, verifying under the golden key.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalChain
     */
    private static function chain(): JournalChain
    {
        return new JournalChain(self::signer(), self::LOG_ID);
    }

    /**
     * A signer whose one key is the golden key, `k2026`.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalSigner
     */
    private static function signer(): JournalSigner
    {
        return new JournalSigner(self::ring(['k2026' => self::SECRET]));
    }

    /**
     * A ring of the keys given, by id, signing under the first.
     *
     * @param  non-empty-array<string, string>  $keys
     * @return \SineMacula\Laravel\AuditLog\Integrity\KeyRing
     */
    private static function ring(array $keys): KeyRing
    {
        return new KeyRing(new IntegritySettings(new Repository(['audit-log' => ['integrity' => ['keys' => $keys, 'current' => array_key_first($keys)]]])));
    }
}
