<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\JournalSummary;
use SineMacula\Laravel\AuditLog\Integrity\JournalVerifier;
use SineMacula\Laravel\AuditLog\Integrity\RunFinding;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\VerificationTally;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\WritesTheJournal;
use Tests\TestCase;

/**
 * Feature tests for the journal's verification, on whichever engine the suite
 * runs against: an empty journal with no seal passes, each seal commits to the
 * head when it was sealed, an edited row or payload is a signature finding, a
 * deleted row a gap, a truncated journal, a commitment running backwards,
 * dropped or unpaired each a commitment finding, each finding one run finding
 * with its first id and count, memory that never grows with the journal, and
 * every statement on the writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JournalVerifier::class)]
final class JournalVerifierTest extends TestCase
{
    use SealsEntries, WritesTheJournal;

    /** @var string A hold id. */
    private const string HOLD = '01932b4e-d000-7000-8000-000000000001';

    /** @var string Another hold id. */
    private const string OTHER_HOLD = '01932b4e-d000-7000-8000-000000000002';

    /** @var string An HMAC no row holds. */
    private const string OTHER_HMAC = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /**
     * A log with no seal and an empty journal passes, and reads none.
     *
     * @return void
     */
    public function testAnEmptyJournalAndNoSealsPass(): void
    {
        [$summary, $findings] = $this->verifyJournal();

        self::assertSame([], $findings);
        self::assertSame(['rows' => 0, 'head' => null, 'committed' => null], $summary->toArray());
    }

    /**
     * Each seal commits to the journal's head when it was sealed: none before
     * the first row, then the last row, and every commitment verifies.
     *
     * @return void
     */
    public function testEachSealCommitsToTheHeadWhenSealed(): void
    {
        $this->storeEntries(1);
        $this->sealAll();
        $this->journalHold(self::HOLD);

        $head = $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD);

        $this->storeEntries(1, '2026-11-01 12:00:01.000000');
        $this->sealAll();

        $seals = $this->seals();

        self::assertNull($seals[0]['journal_sequence']);
        self::assertNull($seals[0]['journal_head']);
        self::assertSame(2, (int) $seals[1]['journal_sequence']);
        self::assertSame($head->hmac, $seals[1]['journal_head']);

        [$summary, $findings] = $this->verifyJournal();

        self::assertSame([], $findings);
        self::assertSame(['rows' => 2, 'head' => 2, 'committed' => 2], $summary->toArray());
    }

    /**
     * A seal made before a later row commits to the row it saw, and the journal
     * growing past it is no finding.
     *
     * @return void
     */
    public function testAJournalThatGrewAfterTheLastSealPasses(): void
    {
        $this->journalHold(self::HOLD);
        $this->storeEntries(1);
        $this->sealAll();
        $this->journalHold(self::OTHER_HOLD);

        [$summary, $findings] = $this->verifyJournal();

        self::assertSame([], $findings);
        self::assertSame(['rows' => 2, 'head' => 2, 'committed' => 1], $summary->toArray());
    }

    /**
     * A row whose signed column was edited is a signature finding, found at
     * that row.
     *
     * @return void
     */
    public function testAnEditedRowIsTampered(): void
    {
        $this->journalHold(self::HOLD);

        $edited = $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD);

        $this->tamperJournal(2, ['reason' => 'case.forged']);

        [$summary, $findings] = $this->verifyJournal();

        self::assertEquals([new RunFinding(Finding::JOURNAL_SIGNATURE, $edited->id)], $findings);
        self::assertSame(1, $summary->head);
    }

    /**
     * A payload rewritten in its canonical form, its digest kept, is a
     * signature finding: the signature covers the payload through its digest.
     *
     * @return void
     */
    public function testAnEditedPayloadIsASignatureFinding(): void
    {
        $hold = $this->journalHold(self::HOLD);

        $this->tamperJournal(1, ['payload' => '{"basis":"other","hold_id":"' . self::HOLD . '","review_by":null}']);

        [, $findings] = $this->verifyJournal();

        self::assertEquals([new RunFinding(Finding::JOURNAL_SIGNATURE, $hold->id)], $findings);
    }

    /**
     * A row deleted from the middle of the journal is one gap, found at the row
     * after it.
     *
     * @return void
     */
    public function testADeletedRowIsAGap(): void
    {
        $this->journalHold(self::HOLD);
        $this->journalHold(self::OTHER_HOLD);

        $after = $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD);

        $this->journalTable()->where('sequence', 2)->delete();

        [$summary, $findings] = $this->verifyJournal();

        self::assertEquals([new RunFinding(Finding::JOURNAL_GAP, $after->id)], $findings);
        self::assertSame(2, $summary->rowsRead);
        self::assertSame(3, $summary->head);
    }

    /**
     * A journal truncated below the row a seal committed to contradicts the
     * seal: the commitment names no row, found at the seal, while what is left
     * of the chain is whole.
     *
     * @return void
     */
    public function testATruncatedJournalContradictsTheSealsCommitment(): void
    {
        $this->journalHold(self::HOLD);
        $this->journalHold(self::OTHER_HOLD);
        $this->storeEntries(1);
        $this->sealAll();

        $this->journalTable()->where('sequence', 2)->delete();

        [$summary, $findings] = $this->verifyJournal();

        self::assertEquals([new RunFinding(Finding::JOURNAL_COMMITMENT, (string) $this->seals()[0]['id'])], $findings);
        self::assertSame(['rows' => 1, 'head' => 1, 'committed' => 2], $summary->toArray());
    }

    /**
     * A seal that commits to a row under another HMAC than the row holds, as a
     * journal replaced since the seal would, contradicts it.
     *
     * @return void
     */
    public function testACommitmentToAnotherHeadIsTampered(): void
    {
        $this->journalHold(self::HOLD);
        $this->storeEntries(1);
        $this->sealAll();

        $sealId = (string) $this->seals()[0]['id'];

        $this->checkpoints()->where('id', $sealId)->update(['journal_head' => self::OTHER_HMAC]);

        [, $findings] = $this->verifyJournal();

        self::assertEquals([new RunFinding(Finding::JOURNAL_COMMITMENT, $sealId)], $findings);
    }

    /**
     * A seal whose commitment is to a lower sequence than the seal before it
     * runs backwards, found at that seal.
     *
     * @return void
     */
    public function testACommitmentRunningBackwardsIsTampered(): void
    {
        [$first, $second] = $this->twoCommittedSeals();

        $this->checkpoints()->where('id', $first)->update(['journal_sequence' => 2, 'journal_head' => $this->journalRows()[1]['hmac']]);
        $this->checkpoints()->where('id', $second)->update(['journal_sequence' => 1, 'journal_head' => $this->journalRows()[0]['hmac']]);

        [, $findings] = $this->verifyJournal();

        self::assertEquals([new RunFinding(Finding::JOURNAL_COMMITMENT, $second)], $findings);
    }

    /**
     * A seal that commits to no row after a seal that committed to one has
     * dropped the commitment, found at that seal.
     *
     * @return void
     */
    public function testACommitmentDroppedAfterOneWasMadeIsTampered(): void
    {
        [, $second] = $this->twoCommittedSeals();

        $this->checkpoints()->where('id', $second)->update(['journal_sequence' => null, 'journal_head' => null]);

        [, $findings] = $this->verifyJournal();

        self::assertEquals([new RunFinding(Finding::JOURNAL_COMMITMENT, $second)], $findings);
    }

    /**
     * A seal that names a sequence with no head, or a head with no sequence, or
     * a sequence below 1, is tampered, each found at its seal and counted.
     *
     * @return void
     */
    public function testAnUnpairedCommitmentIsTampered(): void
    {
        $this->sealSeparately(3);

        [$first, $second, $third] = array_map(static fn (array $seal): string => (string) $seal['id'], $this->seals());

        $this->checkpoints()->where('id', $first)->update(['journal_sequence' => 1]);
        $this->checkpoints()->where('id', $second)->update(['journal_head' => self::OTHER_HMAC]);
        $this->checkpoints()->where('id', $third)->update(['journal_sequence' => 0, 'journal_head' => self::OTHER_HMAC]);

        [, $findings] = $this->verifyJournal();

        self::assertEquals([new RunFinding(Finding::JOURNAL_COMMITMENT, $first, 3)], $findings);
    }

    /**
     * A transition the chain refuses, such as a release of a hold never placed,
     * is a transition finding at its row.
     *
     * @return void
     */
    public function testATransitionIsFound(): void
    {
        $release = $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD);

        [, $findings] = $this->verifyJournal();

        self::assertEquals([new RunFinding(Finding::JOURNAL_TRANSITION, $release->id)], $findings);
    }

    /**
     * Payloads are read, so a prune run's finish with no start is refused.
     *
     * @return void
     */
    public function testRunsArePairedFromTheirPayloads(): void
    {
        $finish = $this->journalRow(JournalKind::PRUNE_RUN, ['run_id' => (string) Str::uuid7(), 'phase' => 'finish']);

        [, $findings] = $this->verifyJournal();

        self::assertEquals([new RunFinding(Finding::JOURNAL_TRANSITION, $finish->id)], $findings);
    }

    /**
     * A row that cannot be read as a journal row is malformed, by its id, and
     * the row after it is no gap.
     *
     * @return void
     */
    public function testAMalformedRowIsMalformed(): void
    {
        $this->journalHold(self::HOLD);

        $malformed = $this->journalHold(self::OTHER_HOLD);

        $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD);
        $this->tamperJournal(2, ['kind' => 'erasure']);

        [$summary, $findings] = $this->verifyJournal();

        self::assertEquals([new RunFinding(Finding::JOURNAL_MALFORMED, $malformed->id)], $findings);
        self::assertSame(3, $summary->rowsRead);
    }

    /**
     * Each kind of finding is one run finding, with the id it was first found
     * at and how many times it was found, in the order first found: the
     * commitments, read first, before the rows.
     *
     * @return void
     */
    public function testEveryFindingIsARunFindingWithItsFirstId(): void
    {
        $first  = $this->journalHold(self::HOLD);
        $second = $this->journalHold(self::OTHER_HOLD);

        $this->storeEntries(1);
        $this->sealAll();

        $sealId = (string) $this->seals()[0]['id'];

        $this->tamperJournal(1, ['reason' => 'case.forged']);
        $this->tamperJournal(2, ['authority_id' => '8']);
        $this->checkpoints()->where('id', $sealId)->update(['journal_head' => self::OTHER_HMAC]);

        $tally = new VerificationTally;

        app(JournalVerifier::class)->verify($tally);

        self::assertEquals([
            new RunFinding(Finding::JOURNAL_SIGNATURE, $first->id, 2),
            new RunFinding(Finding::JOURNAL_COMMITMENT, $sealId),
        ], $tally->findings());
        self::assertNotSame($first->id, $second->id);
        self::assertSame(Finding::JOURNAL_SIGNATURE, $tally->firstFinding());
        self::assertSame($first->id, $tally->firstBadId());
    }

    /**
     * The journal is read a page at a time after the commitments: one statement
     * for the seals, then one per page of rows, each bounded below by the last
     * sequence read.
     *
     * @return void
     */
    public function testTheJournalIsReadAPageAtATime(): void
    {
        $this->insertJournal(JournalVerifier::PAGE + 1);

        $statements = [];

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        [$summary, $findings] = $this->verifyJournal();

        self::assertSame([], $findings);
        self::assertSame(JournalVerifier::PAGE + 1, $summary->rowsRead);
        self::assertCount(3, $statements);
        self::assertStringContainsString(IntegrityTables::checkpointsTable(), $statements[0]);
        self::assertStringContainsString(LifecycleTables::journalTable(), $statements[1]);
        self::assertStringNotContainsString('sequence" >', $statements[1]);
        self::assertMatchesRegularExpression('/where .?sequence.? > \?/', $statements[2]);
    }

    /**
     * The peak memory of a run over 10,000 rows is that of a run over one page
     * of them: what the run holds grows with the seals, never with the journal.
     *
     * @return void
     */
    public function testMemoryDoesNotGrowWithTheJournal(): void
    {
        $this->insertJournal(JournalVerifier::PAGE);

        $page = $this->peakGrowthOfARun();

        $this->journalTable()->delete();
        $this->insertJournal(10000);

        $many = $this->peakGrowthOfARun();

        self::assertLessThanOrEqual(intdiv(3 * $page, 2) + 262144, $many, sprintf('10,000 rows grew the peak by %d bytes, and one page by %d.', $many, $page));
    }

    /**
     * Every statement reads the writer, so a replica's lag never reads as a
     * missing row: with a reader that refuses to be used, the run passes.
     *
     * @return void
     */
    public function testItReadsTheWriter(): void
    {
        $this->journalHold(self::HOLD);
        $this->storeEntries(1);
        $this->sealAll();

        DB::connection(StorageConnection::name())->setReadPdo(static function (): never {
            throw new \LogicException('The journal\'s verification read the replica.');
        });

        [$summary, $findings] = $this->verifyJournal();

        self::assertSame([], $findings);
        self::assertSame(['rows' => 1, 'head' => 1, 'committed' => 1], $summary->toArray());
    }

    /**
     * Verify the journal into a new tally, returning its summary and the
     * findings it added.
     *
     * @return array{0: \SineMacula\Laravel\AuditLog\Integrity\JournalSummary, 1: list<\SineMacula\Laravel\AuditLog\Integrity\RunFinding>}
     */
    private function verifyJournal(): array
    {
        $tally   = new VerificationTally;
        $summary = app(JournalVerifier::class)->verify($tally);

        self::assertInstanceOf(JournalSummary::class, $summary);

        return [$summary, $tally->findings()];
    }

    /**
     * Two seals, the first committing to the journal's first row and the second
     * to its second, by id.
     *
     * @return array{0: string, 1: string}
     */
    private function twoCommittedSeals(): array
    {
        $this->journalHold(self::HOLD);
        $this->storeEntries(1);
        $this->sealAll();
        $this->journalHold(self::OTHER_HOLD);
        $this->storeEntries(1, '2026-11-01 12:00:01.000000');
        $this->sealAll();

        $seals = $this->seals();

        self::assertSame(1, (int) $seals[0]['journal_sequence']);
        self::assertSame(2, (int) $seals[1]['journal_sequence']);

        return [(string) $seals[0]['id'], (string) $seals[1]['id']];
    }

    /**
     * Store and seal the number of entries, one seal for each, each recorded a
     * second after the one before.
     *
     * @param  int  $count
     * @return void
     */
    private function sealSeparately(int $count): void
    {
        for ($index = 0; $index < $count; $index++) {
            $this->storeEntries(1, sprintf('2026-11-01 12:00:%02d.000000', $index));
            $this->sealAll();
        }

        self::assertCount($count, $this->seals());
    }

    /**
     * Insert the number of policy rows, signed and linked from the head, a
     * chunk of rows to a statement.
     *
     * @param  int  $count
     * @return void
     */
    private function insertJournal(int $count): void
    {
        $signer   = app(JournalSigner::class);
        $logId    = app(SealSettings::class)->logId();
        $rows     = [];
        $previous = null;

        for ($sequence = 1; $sequence <= $count; $sequence++) {
            $draft = JournalRow::draft(
                sprintf('01932b4e-b000-7000-8000-%012d', $sequence),
                $sequence,
                $logId,
                JournalKind::POLICY,
                '01932b4e-c000-7000-8000-000000000001',
                '2026-11-01T12:00:00.000000Z',
                null,
                null,
                null,
                null,
                null,
                ['version' => sprintf('config:%016d', $sequence), 'policy' => 'App\Retention', 'settings' => null],
                $previous,
            );

            $signed   = $signer->sign($draft);
            $rows[]   = $signed->toRow();
            $previous = $signed->hmac;
        }

        foreach (array_chunk($rows, 50) as $chunk) {
            $this->journalTable()->insert($chunk);
        }
    }

    /**
     * How much a run over the journal grows the peak by, in bytes.
     *
     * @return int
     */
    private function peakGrowthOfARun(): int
    {
        $verifier = app(JournalVerifier::class);
        $tally    = new VerificationTally;

        gc_collect_cycles();
        memory_reset_peak_usage();

        $before = memory_get_usage();

        $verifier->verify($tally);

        $growth = memory_get_peak_usage() - $before;

        self::assertSame([], $tally->findings());

        return $growth;
    }

    /**
     * A query of the journal table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function journalTable(): Builder
    {
        return DB::connection(StorageConnection::name())->table(LifecycleTables::journalTable());
    }

    /**
     * A query of the checkpoints table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function checkpoints(): Builder
    {
        return DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable());
    }
}
