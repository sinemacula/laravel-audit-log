<?php

declare(strict_types = 1);

namespace Tests\Integration\Lifecycle;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\CheckpointWriter;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalVerifier;
use SineMacula\Laravel\AuditLog\Integrity\RunFinding;
use SineMacula\Laravel\AuditLog\Integrity\SealChainException;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\VerificationSummary;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalPruneLedger;
use SineMacula\Laravel\AuditLog\Lifecycle\Pruner;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\WritesTheJournal;
use Tests\TestCase;

/**
 * Integration tests for the seals' commitment to the lifecycle journal on
 * whichever engine the suite runs against, SQLite on a file shared with a child
 * process: a journal restored to an older state, below the row a seal committed
 * to, contradicts that seal; a committed tail removed is never sealed over and
 * refuses the prune and a hold; a row edited by a raw statement on the engine
 * is found; and the sequence and HMAC a seal commits to read back as written in
 * each engine's types, so the seal's digest is the one it signed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckpointWriter::class)]
#[CoversClass(JournalVerifier::class)]
final class JournalCommitmentEnginesTest extends TestCase
{
    use RunsKilledChildren, SealsEntries, WritesTheJournal;

    /** @var string A hold id. */
    private const string HOLD = '01932b4e-d000-7000-8000-000000000001';

    /** @var string Another hold id. */
    private const string OTHER_HOLD = '01932b4e-d000-7000-8000-000000000002';

    /**
     * Remove the children's files once the migrations are rolled back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * A seal, a journal of two rows, the second written and sealed by another
     * process, then the journal restored to its first row alone: the second
     * seal committed to a row the journal no longer holds, and verification
     * says so, while what is left of the chain is whole.
     *
     * @return void
     */
    public function testRestoringAnOlderJournalContradictsTheSeals(): void
    {
        $this->storeEntries(1);
        $this->sealAll();
        $this->journalHold(self::HOLD);

        $backup = $this->journalRows();

        $this->runChild(function (): void {
            $this->journalHold(self::OTHER_HOLD);
            $this->storeEntries(1, '2026-11-01 12:00:01.000000');
            $this->sealAll();
        });

        $seals = $this->seals();

        self::assertCount(2, $seals);
        self::assertSame(2, (int) $seals[1]['journal_sequence']);

        $this->journalTable()->delete();
        $this->journalTable()->insert($backup);

        $summary = $this->verifyLog();

        self::assertEquals([new RunFinding(Finding::JOURNAL_COMMITMENT, (string) $seals[1]['id'])], $summary->findings);
        self::assertSame(['rows' => 1, 'head' => 1, 'committed' => 2], $summary->journal?->toArray());
        self::assertTrue($summary->fails(false));
    }

    /**
     * A committed hold removed from the journal's tail is never sealed over:
     * the next seal is refused, and the prune and a new hold each fail closed
     * on the contradicted commitment, so the entry the removed hold kept is
     * never deleted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATruncatedTailIsNeverSealedOverAndRefusesEveryDestructiveOperation(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.after_days', 30);
        app()->bind(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
        app()->bind(PruneLedger::class, JournalPruneLedger::class);

        $held = $this->storeEntryAt('2020-01-01 12:00:00.000000');

        $this->place(self::HOLD);
        $this->sealAll();

        $sealId = (string) $this->seals()[0]['id'];

        $this->journalTable()->where('sequence', 1)->delete();
        $this->storeEntryAt('2020-01-01 12:00:01.000000');

        try {
            $this->sealer()->sweep();

            self::fail('Expected the seal over the truncated journal to be refused.');
        } catch (SealChainException $exception) {
            self::assertSame([Finding::JOURNAL_COMMITMENT, $sealId], [$exception->finding, $exception->sealId]);
        }

        $result = app(Pruner::class)->run();

        self::assertSame(['journal_broken', 0], [$result->failure, $result->deleted]);
        self::assertTrue(DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $held)->exists());

        try {
            $this->place(self::OTHER_HOLD);

            self::fail('Expected the hold to be refused.');
        } catch (JournalBrokenException $exception) {
            self::assertSame([Finding::JOURNAL_COMMITMENT, $sealId], [$exception->finding, $exception->rowId]);
        }

        self::assertCount(1, $this->seals());
    }

    /**
     * A row's reason changed by a raw statement on the engine, its HMAC kept,
     * is a signature finding at that row.
     *
     * @return void
     */
    public function testAJournalRowEditedOnTheEngineIsFound(): void
    {
        $this->journalHold(self::HOLD);

        $edited = $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD);

        $this->storeEntries(1);
        $this->sealAll();

        $connection = DB::connection(StorageConnection::name());
        $table      = $connection->getQueryGrammar()->wrapTable(LifecycleTables::journalTable());

        $connection->update(sprintf('update %s set reason = ? where sequence = ?', $table), ['case.forged', 2]);

        $summary = $this->verifyLog();

        self::assertEquals([new RunFinding(Finding::JOURNAL_SIGNATURE, $edited->id)], $summary->findings);
        self::assertTrue($summary->fails(false));
    }

    /**
     * The sequence and HMAC a seal commits to read back as written in each
     * engine's types, the seal's digest is the one it was stored with, the
     * journal's rows read back as they were signed, and the log verifies.
     *
     * @return void
     */
    public function testTheCommitmentSurvivesEachEnginesTypes(): void
    {
        $this->journalHold(self::HOLD);

        $head = $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD], self::HOLD);

        $this->storeEntries(2);
        $this->sealAll();

        $stored   = $this->seals()[0];
        $envelope = SealEnvelope::fromRow($stored);
        $rows     = array_map(static fn (array $row): JournalRow => JournalRow::fromRow($row, true), $this->journalRows());

        self::assertSame(2, $envelope->journalSequence);
        self::assertSame($head->hmac, $envelope->journalHead);
        self::assertSame($stored['seal_digest'], $envelope->digest());
        self::assertSame($head->signedFields(), $rows[1]->signedFields());
        self::assertSame($head->payload, $rows[1]->payload);
        self::assertSame($head->hmac, $rows[1]->hmac);

        $summary = $this->verifyLog();

        self::assertSame([], $summary->findings);
        self::assertSame(['rows' => 2, 'head' => 2, 'committed' => 2], $summary->journal?->toArray());
        self::assertFalse($summary->fails(false));
    }

    /**
     * Put the default connection on a file when it is SQLite, so a child
     * process shares it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->useFileDatabaseOnSqlite($app);
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
     * Place a hold of everything under the hold id, through the package.
     *
     * @param  string  $holdId
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \Throwable
     */
    private function place(string $holdId): void
    {
        $authority = new Authority(Reference::of('App\Models\User', '7'), 'case.review');

        app(HoldKeeper::class)->place('01932b4e-9000-7000-8000-0000000000a1', HoldScope::all(), $authority, HoldBasis::LEGAL_CLAIM, null, $holdId);
    }

    /**
     * Verify the whole log with the container's verifier, keeping no report.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary
     */
    private function verifyLog(): VerificationSummary
    {
        return app(Verifier::class)->verify(VerificationRange::whole(), static function (): void {
            // Each segment's report is counted by the run; none is kept here
        });
    }
}
