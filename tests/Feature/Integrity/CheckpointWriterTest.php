<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\CheckpointWriter;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\SealBatch;
use SineMacula\Laravel\AuditLog\Integrity\SealChainException;
use SineMacula\Laravel\AuditLog\Integrity\SealCursor;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\WritesTheJournal;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for the checkpoint writer, on whichever engine the suite runs
 * against: one attempt seals the entries no seal holds, in `(recorded_at, id)`
 * order from its position and no later than its bound, chained onto the last
 * seal's recomputed digest; it refuses a last seal whose digest disagrees or
 * that belongs to another log, and one it cannot read; it inserts the
 * checkpoint before its members, the members in chunks, from values and never
 * from a select, without locking what it reads; it leaves out a candidate it
 * cannot seal; and a conflict leaves nothing of the attempt. The sweep's window
 * reads at most its limit of entries, sealed or not, and seals those that are
 * no seal's member. Every seal commits to the lifecycle journal's head, read
 * inside its own transaction after the last seal, or to none, and a head that
 * cannot be read refuses the seal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckpointWriter::class)]
final class CheckpointWriterTest extends TestCase
{
    use SealsEntries, WritesTheJournal;

    /** @var string When the writer seals, in the package's form. */
    private const string SEALED_AT = '2026-11-01T13:00:00.000000Z';

    /** @var string The bound every attempt seals up to, unless a test gives another. */
    private const string UNTIL = '2026-11-01T13:00:00.000000Z';

    /** @var string The id of a hold the journal places. */
    private const string HOLD_ID = '01932b4e-d000-7000-8000-000000000001';

    /** @var string A secret of the first key of an explicit ring. */
    private const string SECRET_2025 = 'audit-log seal test key 2025 0123456789';

    /** @var string A secret of the second key of an explicit ring. */
    private const string SECRET_2026 = 'audit-log seal test key 2026 0123456789';

    /**
     * Roll back any transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(StorageConnection::name());

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        parent::tearDown();
    }

    /**
     * The first seal is the genesis: sequence 1, no previous seal, the
     * configured log, the signing key, the version, the signer and the clock's
     * time, under a lower-case UUID v7 id, with no anchoring.
     *
     * @return void
     */
    public function testTheFirstSealIsTheGenesis(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.log_id', 'app-eu-1');

        $this->storeEntries(3);

        $batch = $this->writer()->write(null, self::UNTIL, 100);
        $seal  = $this->seals()[0];

        self::assertNotNull($batch->seal);
        self::assertSame(1, $batch->seal->sequence);
        self::assertNull($batch->seal->previousId);
        self::assertNull($batch->seal->previousDigest);
        self::assertSame('app-eu-1', $batch->seal->logId);
        self::assertSame(app(SealSigner::class)->signingKeyId(), $batch->seal->keyId);
        self::assertSame(self::SEALED_AT, $batch->seal->sealedAt);
        self::assertSame(1, $batch->seal->algorithmVersion);
        self::assertSame('hmac', $batch->seal->signer);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/', $batch->seal->id);
        self::assertSame($batch->seal->id, $seal['id']);
        self::assertSame(1, (int) $seal['sequence']);
        self::assertNull($seal['previous_id']);
        self::assertNull($seal['previous_digest']);
        self::assertSame(3, (int) $seal['member_count']);
        self::assertNull($seal['anchor']);
        self::assertNull($seal['anchored_at']);
        self::assertCount(1, $this->seals());
    }

    /**
     * The next seal takes the next sequence and chains onto the last seal's id
     * and the digest recomputed from its fields, which is the digest the
     * attempt that wrote it returned.
     *
     * @return void
     */
    public function testTheNextSealChainsOntoTheHeadsRecomputedDigest(): void
    {
        $this->storeEntries(2);

        $first = $this->writer()->write(null, self::UNTIL, 100);

        $this->storeEntries(2, '2026-11-01 12:30:00');

        $second = $this->writer()->write(null, self::UNTIL, 100);
        $stored = $this->seals();

        self::assertNotNull($first->seal);
        self::assertNotNull($second->seal);
        self::assertSame(2, $second->seal->sequence);
        self::assertSame($first->seal->id, $second->seal->previousId);
        self::assertSame($first->digest, $second->seal->previousDigest);
        self::assertSame(SealEnvelope::fromRow($stored[0])->digest(), $second->seal->previousDigest);
        self::assertSame($first->digest, $stored[0]['seal_digest']);
        self::assertSame($second->digest, $stored[1]['seal_digest']);
        self::assertSame($first->seal->id, $stored[1]['previous_id']);
        self::assertSame($first->digest, $stored[1]['previous_digest']);
    }

    /**
     * A last seal whose stored digest is not the digest of its fields is never
     * extended: the attempt is refused naming the seal and the finding, and
     * writes nothing.
     *
     * @return void
     */
    public function testRefusesToExtendAHeadWhoseDigestDisagrees(): void
    {
        $this->storeEntries(2);

        $head = $this->writer()->write(null, self::UNTIL, 100)->seal;

        self::assertNotNull($head);

        $this->checkpoints()->where('id', $head->id)->update(['member_count' => 1]);

        $this->storeEntries(1, '2026-11-01 12:30:00');

        $this->assertRefusedToChain($head->id, Finding::SEAL_DIGEST, SealChainException::forHead($head->id)->getMessage());
    }

    /**
     * A last seal of another log id is never extended, so one chain never mixes
     * two logs: the attempt is refused naming the seal and the finding, and
     * writes nothing.
     *
     * @return void
     */
    public function testRefusesToExtendAHeadOfAnotherLog(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.integrity.log_id', 'app-eu-1');

        $this->storeEntries(2);

        $head = $this->writer()->write(null, self::UNTIL, 100)->seal;

        self::assertNotNull($head);

        $config->set('audit-log.integrity.log_id', 'app-eu-2');

        $this->storeEntries(1, '2026-11-01 12:30:00');

        $this->assertRefusedToChain($head->id, Finding::LOG_MISMATCH, SealChainException::forLog($head->id)->getMessage());
    }

    /**
     * A last seal signed under a key the ring no longer holds is extended: its
     * signature is not checked here, so retiring a key never stops sealing.
     *
     * @return void
     */
    public function testExtendsAHeadSignedUnderARetiredKey(): void
    {
        $this->useRing(['k2025' => self::SECRET_2025, 'k2026' => self::SECRET_2026], 'k2025');

        $this->storeEntries(2);

        $first = $this->writer()->write(null, self::UNTIL, 100);

        $this->useRing(['k2026' => self::SECRET_2026], 'k2026');

        $this->storeEntries(1, '2026-11-01 12:30:00');

        $second = $this->writer()->write(null, self::UNTIL, 100);

        self::assertNotNull($first->seal);
        self::assertNotNull($second->seal);
        self::assertSame('k2025', $first->seal->keyId);
        self::assertSame('k2026', $second->seal->keyId);
        self::assertSame($first->digest, $second->seal->previousDigest);
    }

    /**
     * A last seal that cannot be read as a seal is never extended: the refusal
     * to read it propagates, naming the column, and nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMalformedHeadIsNotExtended(): void
    {
        $this->storeEntries(2);

        $head = $this->writer()->write(null, self::UNTIL, 100)->seal;

        self::assertNotNull($head);

        $this->checkpoints()->where('id', $head->id)->update(['signer' => 'ed25519']);

        $this->storeEntries(1, '2026-11-01 12:30:00');

        try {
            $this->writer()->write(null, self::UNTIL, 100);

            self::fail('Expected the malformed head to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertNotInstanceOf(SealChainException::class, $exception);
            self::assertSame('A stored seal\'s `signer` is malformed.', $exception->getMessage());
        }

        self::assertCount(1, $this->seals());
        self::assertSame(2, $this->members()->count());
    }

    /**
     * A seal commits to the journal's head: the sequence and HMAC of its last
     * row, stored with the seal and covered by its digest and signature.
     *
     * @return void
     */
    public function testASealCommitsToTheJournalHead(): void
    {
        $this->journalHold(self::HOLD_ID);

        $head = $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD_ID], self::HOLD_ID);

        $this->storeEntries(2);

        $batch = $this->writer()->write(null, self::UNTIL, 100);
        $seal  = $this->seals()[0];

        self::assertNotNull($batch->seal);
        self::assertSame(2, $batch->seal->journalSequence);
        self::assertSame($head->hmac, $batch->seal->journalHead);
        self::assertSame(2, (int) $seal['journal_sequence']);
        self::assertSame($head->hmac, $seal['journal_head']);
        self::assertSame($batch->digest, SealEnvelope::fromRow($seal)->digest());
        self::assertTrue(app(SealSigner::class)->verifies(SealEnvelope::fromRow($seal), (string) $seal['signature']));
    }

    /**
     * A seal of an empty journal commits to none: both its journal columns are
     * `null`, and a row stored outside the chain, at a sequence below 1, is
     * never taken for the head.
     *
     * @return void
     */
    public function testASealOfAnEmptyJournalCommitsToNone(): void
    {
        $this->storeEntries(1);

        $first = $this->writer()->write(null, self::UNTIL, 100)->seal;

        self::assertNotNull($first);
        self::assertNull($first->journalSequence);
        self::assertNull($first->journalHead);
        self::assertNull($this->seals()[0]['journal_sequence']);
        self::assertNull($this->seals()[0]['journal_head']);

        $this->journalHold(self::HOLD_ID);
        $this->tamperJournal(1, ['sequence' => 0]);
        $this->storeEntries(1, '2026-11-01 12:30:00');

        $second = $this->writer()->write(null, self::UNTIL, 100)->seal;

        self::assertNotNull($second);
        self::assertNull($second->journalSequence);
        self::assertNull($second->journalHead);
    }

    /**
     * Rows of `[column, malformed value]`: a journal head whose HMAC no key
     * could have made.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideMalformedJournalHeads(): iterable
    {
        yield from [
            'an upper-case HMAC' => ['hmac', str_repeat('A', 64)],
            'a short HMAC'       => ['hmac', str_repeat('a', 63)],
            'an empty HMAC'      => ['hmac', ''],
        ];
    }

    /**
     * A journal head whose HMAC cannot be read refuses the seal, naming no
     * value, and nothing is written: a seal never commits to a row it cannot
     * name.
     *
     * @param  string  $column
     * @param  string  $value
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedJournalHeads')]
    public function testAMalformedJournalHeadRefusesTheSeal(string $column, string $value): void
    {
        $this->journalHold(self::HOLD_ID);
        $this->tamperJournal(1, [$column => $value]);
        $this->storeEntries(2);

        try {
            $this->writer()->write(null, self::UNTIL, 100);

            self::fail('Expected the journal head to be refused.');
        } catch (SealChainException $exception) {
            self::assertNull($exception->sealId);
            self::assertSame(Finding::JOURNAL_MALFORMED, $exception->finding);
            self::assertSame('The lifecycle journal\'s last row has a malformed sequence or HMAC, so no seal commits to it; run audit-log:verify.', $exception->getMessage());
        }

        self::assertSame([], $this->seals());
        self::assertSame(0, $this->members()->count());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
    }

    /**
     * Rows of `[how the journal goes behind the last seal's commitment]`: its
     * committed tail removed, the whole journal emptied, and its committed row
     * replaced by another at the same sequence.
     *
     * @return iterable<string, array{0: \Closure(self): void}>
     */
    public static function provideJournalsBehindTheSeal(): iterable
    {
        yield from [
            'its tail removed' => [static function (self $test): void {
                $test->journalTable()->where('sequence', 2)->delete();
            }],
            'emptied' => [static function (self $test): void {
                $test->journalTable()->delete();
            }],
            'its head replaced' => [static function (self $test): void {
                $test->journalTable()->where('sequence', 2)->delete();
                $test->journalHold('01932b4e-d000-7000-8000-000000000009');
            }],
        ];
    }

    /**
     * A journal behind the last seal's commitment refuses the seal, naming the
     * last seal and the commitment it contradicts, and nothing is written:
     * commitments never run backwards, so a truncated or replaced journal is
     * never sealed over.
     *
     * @param  \Closure(self): void  $behind
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideJournalsBehindTheSeal')]
    public function testAJournalBehindTheLastCommitmentRefusesTheSeal(\Closure $behind): void
    {
        $this->journalHold(self::HOLD_ID);
        $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD_ID], self::HOLD_ID);
        $this->storeEntries(1);
        $this->writer()->write(null, self::UNTIL, 100);
        $this->storeEntries(1, '2026-11-01 12:30:00');

        $sealId = (string) $this->seals()[0]['id'];

        self::assertSame(2, (int) $this->seals()[0]['journal_sequence']);

        $behind($this);

        try {
            $this->writer()->write(null, self::UNTIL, 100);

            self::fail('Expected the journal behind the seal to be refused.');
        } catch (SealChainException $exception) {
            self::assertSame($sealId, $exception->sealId);
            self::assertSame(Finding::JOURNAL_COMMITMENT, $exception->finding);
            self::assertStringStartsWith('The lifecycle journal\'s head is behind the last seal\'s commitment to it', $exception->getMessage());
        }

        self::assertCount(1, $this->seals());
        self::assertSame(1, $this->members()->count());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
    }

    /**
     * A journal that moved on past the last seal's commitment, its committed
     * row kept, is sealed: rows may follow a seal.
     *
     * @return void
     */
    public function testAJournalPastTheLastCommitmentIsSealed(): void
    {
        $this->journalHold(self::HOLD_ID);
        $this->storeEntries(1);
        $this->writer()->write(null, self::UNTIL, 100);

        $head = $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::HOLD_ID], self::HOLD_ID);

        $this->storeEntries(1, '2026-11-01 12:30:00');

        $seal = $this->writer()->write(null, self::UNTIL, 100)->seal;

        self::assertNotNull($seal);
        self::assertSame([2, $head->hmac], [$seal->journalSequence, $seal->journalHead]);
    }

    /**
     * The journal's head is read inside the seal's own transaction, after the
     * last seal, and on the writer.
     *
     * @return void
     */
    public function testTheHeadIsReadInsideTheSealsTransaction(): void
    {
        $this->journalHold(self::HOLD_ID);
        $this->storeEntries(1);

        $reads = [];

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query, array $bindings, Connection $connection) use (&$reads): void {
            $journal = str_contains($query, LifecycleTables::journalTable());
            $seal    = str_contains($query, IntegrityTables::checkpointsTable()) && str_starts_with($query, 'select');
            $reads[] = [$journal, $seal, $connection->transactionLevel()];
        });

        DB::connection(StorageConnection::name())->setReadPdo(static function (): never {
            throw new \LogicException('Sealing read the replica.');
        });

        $this->writer()->write(null, self::UNTIL, 100);

        $journal = array_keys(array_filter($reads, static fn (array $read): bool => $read[0]));
        $seal    = array_keys(array_filter($reads, static fn (array $read): bool => $read[1]));

        self::assertCount(1, $journal);
        self::assertCount(1, $seal);
        self::assertGreaterThan($seal[0], $journal[0]);
        self::assertSame(1, $reads[$journal[0]][2]);
    }

    /**
     * Only entries no seal holds are sealed: a second attempt seals the rows
     * stored since the first, and none the first sealed.
     *
     * @return void
     */
    public function testSealsOnlyUnsealedRows(): void
    {
        $first = $this->storeEntries(3);

        $this->writer()->write(null, self::UNTIL, 100);

        $second = $this->storeEntries(2, '2026-11-01 11:00:00');
        $batch  = $this->writer()->write(null, self::UNTIL, 100);

        self::assertNotNull($batch->seal);
        self::assertSame(2, $batch->read);
        self::assertSame(self::sorted($second), $this->membersOf($batch->seal->id));
        self::assertSame(self::sorted($first), $this->membersOf((string) $this->seals()[0]['id']));
        self::assertSame(5, $this->members()->count());
    }

    /**
     * Candidates are taken in `(recorded_at, id)` order, an equal time broken
     * by the id, so a batch is deterministic; what is sealed is the membership,
     * digested in entry id order whatever order the rows were read in.
     *
     * @return void
     */
    public function testSealsInRecordedOrderThenIdButMembershipIsWhatIsSealed(): void
    {
        $late   = $this->storeEntryAt('2026-11-01 12:00:02', '01932b4e-8a40-7000-8000-000000000001');
        $early  = $this->storeEntryAt('2026-11-01 12:00:01', '01932b4e-8a40-7000-8000-00000000000f');
        $tieLow = $this->storeEntryAt('2026-11-01 12:00:01.5', '01932b4e-8a40-7000-8000-000000000003');
        $tieHi  = $this->storeEntryAt('2026-11-01 12:00:01.5', '01932b4e-8a40-7000-8000-000000000009');

        $batch = $this->writer()->write(null, self::UNTIL, 3);

        self::assertNotNull($batch->seal);
        self::assertSame(self::sorted([$early, $tieLow, $tieHi]), $this->membersOf($batch->seal->id));
        self::assertSame(SealEnvelope::membersDigest($this->memberPairs($batch->seal->id)), $batch->seal->membersDigest);
        self::assertNotNull($batch->last);
        self::assertSame($tieHi, $batch->last->id);
        self::assertSame('2026-11-01T12:00:01.500000Z', StoredTime::fromStorage($batch->last->recordedAt));
        self::assertFalse($batch->exhausted);

        $next = $this->writer()->write($batch->last, self::UNTIL, 3);

        self::assertNotNull($next->seal);
        self::assertSame([$late], $this->membersOf($next->seal->id));
        self::assertTrue($next->exhausted);
    }

    /**
     * The keyset resumes strictly after its position: at an equal time, only
     * the ids after the position's are read, and every later time is. The
     * position's time also bounds the read on its own, so that an engine reads
     * the index from there rather than gathering and sorting every later row.
     *
     * @return void
     */
    public function testTheKeysetResumesAfterTheCursor(): void
    {
        $before = $this->storeEntryAt('2026-11-01 12:00:00.5', '01932b4e-8a40-7000-8000-000000000002');
        $at     = $this->storeEntryAt('2026-11-01 12:00:00.5', '01932b4e-8a40-7000-8000-000000000005');
        $after  = $this->storeEntryAt('2026-11-01 12:00:00.5', '01932b4e-8a40-7000-8000-000000000008');
        $later  = $this->storeEntryAt('2026-11-01 12:00:00.6', '01932b4e-8a40-7000-8000-000000000001');
        $cursor = SealCursor::after(StoredTime::toStorage('2026-11-01T12:00:00.500000Z'), $at);

        $batch      = null;
        $statements = $this->statementsOf(function () use (&$batch, $cursor): SealBatch {
            return $batch = $this->writer()->write($cursor, self::UNTIL, 100);
        });

        self::assertInstanceOf(SealBatch::class, $batch);
        self::assertNotNull($batch->seal);
        self::assertSame(self::sorted([$after, $later]), $this->membersOf($batch->seal->id));
        self::assertNotContains($before, $this->membersOf($batch->seal->id));
        $keyset = '/ e\.recorded_at >= \? and \(e\.recorded_at > \? or \(e\.recorded_at = \? and e\.id > \?\)\)/';

        self::assertCount(1, preg_grep($keyset, $statements) ?: [], 'The keyset is not on the entries\' own columns, bounded below by its time.');
    }

    /**
     * A window after a position reads strictly after it, and the position's
     * time bounds the window's read on its own, as it does the recent pass's.
     *
     * @return void
     */
    public function testAWindowAfterAPositionIsBoundedBelowByItsTime(): void
    {
        $this->storeEntryAt('2026-11-01 12:00:00.5', '01932b4e-8a40-7000-8000-000000000002');

        $at     = $this->storeEntryAt('2026-11-01 12:00:00.5', '01932b4e-8a40-7000-8000-000000000005');
        $after  = $this->storeEntryAt('2026-11-01 12:00:00.5', '01932b4e-8a40-7000-8000-000000000008');
        $cursor = SealCursor::after(StoredTime::toStorage('2026-11-01T12:00:00.500000Z'), $at);

        $batch      = null;
        $statements = $this->statementsOf(function () use (&$batch, $cursor): SealBatch {
            return $batch = $this->writer()->writeWindow($cursor, self::UNTIL, 100);
        });

        self::assertInstanceOf(SealBatch::class, $batch);
        self::assertNotNull($batch->seal);
        self::assertSame([$after], $this->membersOf($batch->seal->id));
        $keyset = '/\(select .* where recorded_at <= \? and recorded_at >= \? and \(recorded_at > \? or \(recorded_at = \? and id > \?\)\) order by/';

        self::assertCount(1, preg_grep($keyset, $statements) ?: [], 'The window is not bounded below by the position\'s time.');
    }

    /**
     * A position that starts at its time reads the rows at that time too,
     * whatever their ids, and none before.
     *
     * @return void
     */
    public function testAStartingPositionIncludesItsInstant(): void
    {
        $this->storeEntryAt('2026-11-01 12:00:00.499999');

        $at    = $this->storeEntryAt('2026-11-01 12:00:00.5', '01932b4e-8a40-7000-8000-000000000000');
        $later = $this->storeEntryAt('2026-11-01 12:00:00.500001');

        $batch      = null;
        $statements = $this->statementsOf(function () use (&$batch): SealBatch {
            return $batch = $this->writer()->write(SealCursor::from('2026-11-01T12:00:00.500000Z'), self::UNTIL, 100);
        });

        self::assertInstanceOf(SealBatch::class, $batch);
        self::assertNotNull($batch->seal);
        self::assertSame(self::sorted([$at, $later]), $this->membersOf($batch->seal->id));
        $from = '/ e\.recorded_at <= \? and e\.recorded_at >= \? and m\.entry_id is null order by/';

        self::assertCount(1, preg_grep($from, $statements) ?: [], 'The position compared an id, which PostgreSQL refuses for an empty one.');
    }

    /**
     * A seal never holds a row recorded after its bound; a row recorded at the
     * bound itself is held.
     *
     * @return void
     */
    public function testASealNeverHoldsARowRecordedAfterTheBound(): void
    {
        $at    = $this->storeEntryAt('2026-11-01 12:00:00');
        $after = $this->storeEntryAt('2026-11-01 12:00:00.000001');

        $batch = $this->writer()->write(null, '2026-11-01T12:00:00.000000Z', 100);

        self::assertNotNull($batch->seal);
        self::assertSame([$at], $this->membersOf($batch->seal->id));
        self::assertSame(0, $this->members()->where('entry_id', $after)->count());
    }

    /**
     * Each member keeps the HMAC its entry had when it was sealed.
     *
     * @return void
     */
    public function testTheMembersHoldTheEntriesHmacs(): void
    {
        $ids   = $this->storeEntries(3);
        $batch = $this->writer()->write(null, self::UNTIL, 100);

        self::assertNotNull($batch->seal);

        $hmacs = $this->entries()->whereIn('id', $ids)->orderBy('id')->pluck('hmac', 'id')->all();

        self::assertSame($hmacs, $this->members()->where('checkpoint_id', $batch->seal->id)->orderBy('entry_id')->pluck('hmac', 'entry_id')->all());
    }

    /**
     * The seal's times are the earliest and latest of its members' times, in
     * the package's form, and the clock's for when it was made.
     *
     * @return void
     */
    public function testTheEnvelopeTimesAreTheCandidatesBounds(): void
    {
        $this->storeEntryAt('2026-11-01 12:00:05.25');
        $this->storeEntryAt('2026-11-01 12:00:01.000001');
        $this->storeEntryAt('2026-11-01 12:00:03');

        $batch = $this->writer()->write(null, self::UNTIL, 100);
        $row   = $this->seals()[0];

        self::assertNotNull($batch->seal);
        self::assertSame('2026-11-01T12:00:01.000001Z', $batch->seal->firstRecordedAt);
        self::assertSame('2026-11-01T12:00:05.250000Z', $batch->seal->lastRecordedAt);
        self::assertSame('2026-11-01T12:00:01.000001Z', StoredTime::fromStorage((string) $row['first_recorded_at']));
        self::assertSame('2026-11-01T12:00:05.250000Z', StoredTime::fromStorage((string) $row['last_recorded_at']));
        self::assertSame(self::SEALED_AT, StoredTime::fromStorage((string) $row['sealed_at']));
    }

    /**
     * The stored signature verifies the stored seal under its key, and its
     * stored digest is the digest of its fields.
     *
     * @return void
     */
    public function testTheSignatureVerifies(): void
    {
        $this->storeEntries(2);

        $batch  = $this->writer()->write(null, self::UNTIL, 100);
        $stored = $this->seals()[0];
        $seal   = SealEnvelope::fromRow($stored);

        self::assertSame($batch->digest, $seal->digest());
        self::assertSame($seal->digest(), $stored['seal_digest']);
        self::assertTrue(app(SealSigner::class)->verifies($seal, (string) $stored['signature']));
        self::assertSame(app(SealSigner::class)->sign($seal), $stored['signature']);
    }

    /**
     * Within the attempt, the last seal is read first, then the candidates,
     * then the journal's head, then the checkpoint is inserted, and only then
     * its members.
     *
     * @return void
     */
    public function testTheCheckpointIsInsertedBeforeItsMembers(): void
    {
        $this->storeEntries(2);

        $statements = $this->statementsOf(fn () => $this->writer()->write(null, self::UNTIL, 100));
        $checkpoint = $this->indexOf($statements, '/^insert into \S*' . IntegrityTables::checkpointsTable() . '\b/');
        $members    = $this->indexOf($statements, '/^insert into \S*' . IntegrityTables::membersTable() . '\b/');

        self::assertCount(5, $statements);
        self::assertMatchesRegularExpression('/^select \* from \S*' . IntegrityTables::checkpointsTable() . '\b/', $statements[0]);
        self::assertMatchesRegularExpression('/^select .* from \S*' . EntrySettings::table() . '\b/', $statements[1]);
        self::assertStringContainsString(' where e.recorded_at <= ? and m.entry_id is null order by e.recorded_at asc, e.id asc limit 100', $statements[1]);
        self::assertMatchesRegularExpression('/^select \S*sequence\S*, \S*hmac\S* from \S*' . LifecycleTables::journalTable() . '\b/', $statements[2]);
        self::assertSame(3, $checkpoint);
        self::assertSame(4, $members);
    }

    /**
     * Members are inserted 300 to a statement, so no statement passes the
     * oldest SQLite limit of placeholders, and every member is inserted.
     *
     * @return void
     */
    public function testMembersAreInsertedInChunksOf300(): void
    {
        $this->storeEntries(601);

        $counts = [];

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query, array $bindings) use (&$counts): void {
            if (preg_match('/^insert into \S*' . IntegrityTables::membersTable() . '\b/', $query) !== 1) {
                return;
            }

            $counts[] = intdiv(count($bindings), 3);
        });

        $this->writer()->write(null, self::UNTIL, 601);

        self::assertSame([300, 300, 1], $counts);
        self::assertSame(CheckpointWriter::MEMBER_CHUNK, 300);
        self::assertSame(601, $this->members()->count());
    }

    /**
     * No statement either selection writes inserts from a select: every row is
     * inserted from values.
     *
     * @return void
     */
    public function testNeverInsertsFromASelect(): void
    {
        $statements = $this->statementsOfBothSelections();

        self::assertNotSame([], preg_grep('/^insert into/i', $statements));
        self::assertSame([], preg_grep('/insert\s+into\s+\S+\s*(\([^)]*\))?\s*select/i', $statements));
    }

    /**
     * No statement either selection runs locks what it reads.
     *
     * @return void
     */
    public function testNeverLocksWhatItSelects(): void
    {
        $statements = $this->statementsOfBothSelections();

        self::assertNotSame([], preg_grep('/^select/i', $statements));
        self::assertSame([], preg_grep('/for update|for share|lock in share mode|for no key update|for key share/i', $statements));
    }

    /**
     * With nothing to seal, the attempt writes nothing and says so: no seal,
     * nothing read, no position, and the selection exhausted.
     *
     * @return void
     */
    public function testNothingToSealWritesNothing(): void
    {
        $statements = $this->statementsOf(fn () => $this->writer()->write(null, self::UNTIL, 100));
        $batch      = $this->writer()->write(null, self::UNTIL, 100);

        self::assertNull($batch->seal);
        self::assertNull($batch->digest);
        self::assertSame(0, $batch->read);
        self::assertSame(0, $batch->skipped);
        self::assertNull($batch->last);
        self::assertTrue($batch->exhausted);
        self::assertSame([], preg_grep('/^insert/i', $statements));
        self::assertSame([], $this->seals());
    }

    /**
     * An entry that became a member between the selection and the insert of the
     * members makes the whole attempt fail with the duplicate: nothing of it
     * remains, the checkpoint included, and no conflict is ignored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMemberConflictFailsTheWholeAttempt(): void
    {
        $ids        = $this->storeEntries(3);
        $connection = DB::connection(StorageConnection::name());
        $armed      = true;

        $connection->beforeExecuting(static function (string $query, array $bindings, Connection $connection) use (&$armed, $ids): void {
            if (!$armed || preg_match('/^insert into \S*' . IntegrityTables::membersTable() . '\b/', $query) !== 1) {
                return;
            }

            $armed = false;

            $member = ['checkpoint_id' => '01932b4e-9000-7000-8000-0000000000ff', 'entry_id' => $ids[1], 'hmac' => str_repeat('c', 64)];

            $connection->table(IntegrityTables::membersTable())->insert($member);
        });

        try {
            $this->writer()->write(null, self::UNTIL, 100);

            self::fail('Expected the member conflict to fail the attempt.');
        } catch (UniqueConstraintViolationException) {
            // The conflict is what the attempt fails with.
        }

        self::assertSame(0, $connection->transactionLevel());
        self::assertSame([], $this->seals());
        self::assertSame(0, $this->members()->count());
    }

    /**
     * Rows of `[column, value, engines it can be stored on]`: a candidate's id,
     * HMAC or time that cannot be sealed. PostgreSQL stores an id as a UUID and
     * a time as a timestamp, so neither can be malformed there, and MySQL
     * stores a time as a datetime.
     *
     * @return iterable<string, array{0: string, 1: string, 2: list<string>}>
     */
    public static function provideMalformedCandidates(): iterable
    {
        yield from [
            'an upper-case id'   => ['id', '01932B4E-8A40-7000-8000-0000000000AA', ['sqlite', 'mysql']],
            'a short HMAC'       => ['hmac', str_repeat('a', 63), ['sqlite', 'mysql', 'pgsql']],
            'a non-hex HMAC'     => ['hmac', str_repeat('g', 64), ['sqlite', 'mysql', 'pgsql']],
            'an upper-case HMAC' => ['hmac', str_repeat('A', 64), ['sqlite', 'mysql', 'pgsql']],
            'a time not stored'  => ['recorded_at', '2026-11-01 12:00:00.0000019', ['sqlite']],
        ];
    }

    /**
     * A candidate that cannot be sealed is left out and counted, never sealed
     * and never fatal: the rest of the batch seals, and the position passes it,
     * so it never stops sealing.
     *
     * @param  string  $column
     * @param  string  $value
     * @param  list<string>  $engines
     * @return void
     */
    #[DataProvider('provideMalformedCandidates')]
    public function testAMalformedCandidateIsSkippedNotSealed(string $column, string $value, array $engines): void
    {
        $driver = DB::connection(StorageConnection::name())->getDriverName();

        if (!in_array($driver, $engines, true)) {
            self::markTestSkipped("The {$driver} engine cannot store this value.");
        }

        $ids = $this->storeEntries(3);

        $this->entries()->where('id', $ids[1])->update([$column => $value]);

        $skipped = $column === 'id' ? $value : $ids[1];
        $batch   = $this->writer()->write(null, self::UNTIL, 100);

        self::assertNotNull($batch->seal);
        self::assertSame(self::sorted([$ids[0], $ids[2]]), $this->membersOf($batch->seal->id));
        self::assertSame(3, $batch->read);
        self::assertSame(1, $batch->skipped);
        self::assertNotNull($batch->last);
        self::assertSame($ids[2], $batch->last->id);
        self::assertSame(0, $this->members()->where('entry_id', $skipped)->count());
    }

    /**
     * A seal row stored at a sequence below 1 is outside the chain and never
     * the head the writer extends: with no seal in the chain, the next seal is
     * genesis.
     *
     * @return void
     */
    public function testARowOutsideTheChainIsNeverExtended(): void
    {
        $this->storeEntries(1);
        $this->writer()->write(null, self::UNTIL, 100);
        $this->checkpoints()->update(['sequence' => 0]);
        $this->storeEntryAt('2026-11-01 12:30:00');

        $batch = $this->writer()->write(null, self::UNTIL, 100);

        self::assertNotNull($batch->seal);
        self::assertSame(1, $batch->seal->sequence);
        self::assertNull($batch->seal->previousId);
    }

    /**
     * Rows of `[column, value, limit]`: on SQLite, which keeps any text, a key
     * that no position could name before, an id longer than a UUID or an empty
     * time, or a time that is no instant, left as the last row of a batch of
     * the limit given.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideMalformedKeysAtABatchsEnd(): iterable
    {
        yield from [
            'an id longer than a UUID'  => ['id', '01932b4e-8a40-7000-8000-0000000000aa1', 2],
            'an empty time'             => ['recorded_at', '', 1],
            'a time that is no instant' => ['recorded_at', '2026-11-01 12:00:00.0000029', 3],
        ];
    }

    /**
     * A malformed key at the end of a batch never stops sealing: the batch
     * still seals the rows before it, the position passes it exactly as stored,
     * and the next batch reads on and seals the rest, so sealing never stalls
     * on it.
     *
     * @param  string  $column
     * @param  string  $value
     * @param  int  $limit
     * @return void
     */
    #[DataProvider('provideMalformedKeysAtABatchsEnd')]
    public function testAMalformedKeyAtTheEndOfABatchNeverStopsSealing(string $column, string $value, int $limit): void
    {
        if (DB::connection(StorageConnection::name())->getDriverName() !== 'sqlite') {
            self::markTestSkipped('Only SQLite stores a key of any length or form.');
        }

        $ids    = $this->storeEntries(3);
        $target = $column === 'recorded_at' && $value === '' ? $ids[0] : ($column === 'id' ? $ids[1] : $ids[2]);

        $this->entries()->where('id', $target)->update([$column => $value]);

        $first = $this->writer()->write(null, self::UNTIL, $limit);

        self::assertSame(1, $first->skipped);
        self::assertNotNull($first->last);
        self::assertSame($column === 'id' ? $value : $target, $first->last->id);
        self::assertSame($column === 'recorded_at' ? $value : $this->storedTimeOf($value), $first->last->recordedAt);

        $sealed = $first->seal === null ? [] : $this->membersOf($first->seal->id);
        $second = $this->writer()->write($first->last, self::UNTIL, 100);

        if ($second->seal !== null) {
            $sealed = [...$sealed, ...$this->membersOf($second->seal->id)];
        }

        self::assertSame(self::sorted(array_values(array_diff($ids, [$target]))), self::sorted($sealed));
    }

    /**
     * On SQLite, which keeps a number stored in a time column as a number, a
     * candidate whose time is an integer or a real is skipped, and the position
     * past it is its time as digits, so the next batch reads on after it.
     *
     * @return void
     */
    public function testAPositionPastANumericTimeReadsOnAfterIt(): void
    {
        if (DB::connection(StorageConnection::name())->getDriverName() !== 'sqlite') {
            self::markTestSkipped('Only SQLite stores a number in a time column.');
        }

        $ids = $this->storeEntries(3);

        $this->entries()->where('id', $ids[0])->update(['recorded_at' => 5]);
        $this->entries()->where('id', $ids[1])->update(['recorded_at' => 5.5]);

        $first = $this->writer()->write(null, self::UNTIL, 1);

        self::assertNull($first->seal);
        self::assertSame(1, $first->skipped);
        self::assertSame('5', $first->last?->recordedAt);
        self::assertSame($ids[0], $first->last->id);

        $second = $this->writer()->write($first->last, self::UNTIL, 1);

        self::assertNull($second->seal);
        self::assertSame('5.5', $second->last?->recordedAt);
        self::assertSame($ids[1], $second->last->id);

        $next = $this->writer()->write($second->last, self::UNTIL, 100);

        self::assertNotNull($next->seal);
        self::assertSame(1, $next->read);
        self::assertSame([$ids[2]], $this->membersOf($next->seal->id));
    }

    /**
     * The attempt is made once: a concurrency failure is rolled back whole and
     * raised to the caller, never retried inside the attempt, so the caller
     * decides whether to try again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConcurrencyFailureIsRaisedNotRetried(): void
    {
        $this->storeEntries(1);

        $connection = DB::connection(StorageConnection::name());
        $failure    = new QueryException(self::CONNECTION, 'select 1', [], new \PDOException('SQLSTATE[HY000]: General error: 5 database is locked'));
        $selects    = 0;

        $connection->beforeExecuting(static function (string $query) use ($failure, &$selects): void {
            if (preg_match('/^select .* from \S*' . EntrySettings::table() . '\b/', str_replace(['"', '`'], '', $query)) !== 1) {
                return;
            }

            $selects++;

            throw $failure;
        });

        try {
            $this->writer()->write(null, self::UNTIL, 100);

            self::fail('Expected the concurrency failure to be raised.');
        } catch (QueryException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame(1, $selects);
        self::assertSame(0, $connection->transactionLevel());
    }

    /**
     * A batch whose every candidate cannot be sealed writes no seal, counts
     * them all, and still moves past them.
     *
     * @return void
     */
    public function testABatchOfMalformedCandidatesWritesNothingAndMovesOn(): void
    {
        $ids = $this->storeEntries(2);

        $this->entries()->update(['hmac' => str_repeat('z', 64)]);

        $batch = $this->writer()->write(null, self::UNTIL, 2);

        self::assertNull($batch->seal);
        self::assertSame(2, $batch->read);
        self::assertSame(2, $batch->skipped);
        self::assertNotNull($batch->last);
        self::assertSame($ids[1], $batch->last->id);
        self::assertFalse($batch->exhausted);
        self::assertSame([], $this->seals());
    }

    /**
     * A window reads at most its limit of entries whatever is sealed: the
     * statement returns no more rows than the limit, and the rows it read are
     * all counted.
     *
     * @return void
     */
    public function testAWindowReadsAtMostItsLimitWhateverIsSealed(): void
    {
        $ids = $this->storeEntries(10);

        $this->writer()->write(null, self::UNTIL, 5);

        $batch      = null;
        $statements = $this->statementsOf(function () use (&$batch): SealBatch {
            return $batch = $this->writer()->writeWindow(null, self::UNTIL, 4);
        });

        self::assertInstanceOf(SealBatch::class, $batch);
        self::assertSame(4, $batch->read);
        self::assertNull($batch->seal);
        self::assertNotNull($batch->last);
        self::assertSame($ids[3], $batch->last->id);
        self::assertFalse($batch->exhausted);
        self::assertCount(1, preg_grep('/^select .* from \(select .* from \S*' . EntrySettings::table() . '\b.* limit 4\) as w left join/', $statements) ?: []);
    }

    /**
     * A window seals the entries in it that are no seal's member, and none
     * outside it.
     *
     * @return void
     */
    public function testAWindowSealsOnlyItsUnsealedRows(): void
    {
        $ids = $this->storeEntries(6);

        $this->writer()->write(null, self::UNTIL, 2);

        $batch = $this->writer()->writeWindow(null, self::UNTIL, 4);

        self::assertNotNull($batch->seal);
        self::assertSame(2, $batch->seal->sequence);
        self::assertSame(self::sorted([$ids[2], $ids[3]]), $this->membersOf($batch->seal->id));
        self::assertSame(4, $batch->read);
        self::assertSame(0, $batch->skipped);
        self::assertSame($ids[3], $batch->last?->id);

        $rest = $this->writer()->writeWindow($batch->last, self::UNTIL, 4);

        self::assertNotNull($rest->seal);
        self::assertSame(self::sorted([$ids[4], $ids[5]]), $this->membersOf($rest->seal->id));
        self::assertSame(2, $rest->read);
        self::assertTrue($rest->exhausted);
    }

    /**
     * A window of sealed entries writes nothing and moves on: no seal, every
     * row counted as read, and the position at its last row.
     *
     * @return void
     */
    public function testAWindowOfSealedRowsWritesNothingAndMovesOn(): void
    {
        $ids = $this->storeEntries(5);

        $this->writer()->write(null, self::UNTIL, 100);

        $batch = $this->writer()->writeWindow(SealCursor::after($this->storedTimeOf($ids[0]), $ids[0]), self::UNTIL, 3);

        self::assertNull($batch->seal);
        self::assertNull($batch->digest);
        self::assertSame(3, $batch->read);
        self::assertSame(0, $batch->skipped);
        self::assertSame($ids[3], $batch->last?->id);
        self::assertFalse($batch->exhausted);
        self::assertCount(1, $this->seals());
    }

    /**
     * A window never reads a row recorded after its bound.
     *
     * @return void
     */
    public function testAWindowNeverReadsARowRecordedAfterTheBound(): void
    {
        $at = $this->storeEntryAt('2026-11-01 12:00:00');

        $this->storeEntryAt('2026-11-01 12:00:00.000001');

        $batch = $this->writer()->writeWindow(null, '2026-11-01T12:00:00.000000Z', 100);

        self::assertNotNull($batch->seal);
        self::assertSame(1, $batch->read);
        self::assertSame([$at], $this->membersOf($batch->seal->id));
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
     * Assert the next attempt is refused for the last seal with the finding and
     * message, and leaves the one seal and its two members as they were.
     *
     * @param  string  $sealId
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    private function assertRefusedToChain(string $sealId, Finding $finding, string $message): void
    {
        try {
            $this->writer()->write(null, self::UNTIL, 100);

            self::fail('Expected the head to be refused.');
        } catch (SealChainException $exception) {
            self::assertSame($sealId, $exception->sealId);
            self::assertSame($finding, $exception->finding);
            self::assertSame($message, $exception->getMessage());
        }

        self::assertCount(1, $this->seals());
        self::assertSame(2, $this->members()->count());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
    }

    /**
     * The statements an attempt of each selection runs, each with one entry to
     * seal.
     *
     * @return list<string>
     */
    private function statementsOfBothSelections(): array
    {
        $this->storeEntries(1);

        $recent = $this->statementsOf(fn () => $this->writer()->write(null, self::UNTIL, 100));

        $this->storeEntries(1, '2026-11-01 12:30:00');

        $window = $this->statementsOf(fn () => $this->writer()->writeWindow(null, self::UNTIL, 100));

        return [...$recent, ...$window];
    }

    /**
     * The statements the work runs on the storage connection, in order and in
     * lower case.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Integrity\SealBatch  $work
     * @return list<string>
     */
    private function statementsOf(\Closure $work): array
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use ($statements): void {
            $statements->append(strtolower(str_replace(['"', '`'], '', $query)));
        });

        $work();

        $recorded = $statements->getArrayCopy();

        $statements->exchangeArray([]);

        return array_values($recorded);
    }

    /**
     * The index of the one statement that matches the pattern.
     *
     * @param  list<string>  $statements
     * @param  string  $pattern
     * @return int
     */
    private function indexOf(array $statements, string $pattern): int
    {
        $matches = array_keys(preg_grep($pattern, $statements) ?: []);

        self::assertCount(1, $matches, 'Expected one statement to match ' . $pattern . '.');

        return $matches[0];
    }

    /**
     * The members of the seal as entry id and HMAC pairs, in no chosen order.
     *
     * @param  string  $sealId
     * @return list<array{0: string, 1: string}>
     */
    private function memberPairs(string $sealId): array
    {
        $pairs = [];

        foreach ($this->members()->where('checkpoint_id', $sealId)->orderByDesc('entry_id')->get() as $member) {
            $pairs[] = [(string) $member->entry_id, (string) $member->hmac];
        }

        return $pairs;
    }

    /**
     * The entry's time as the database returns it.
     *
     * @param  string  $id
     * @return string
     */
    private function storedTimeOf(string $id): string
    {
        $time = $this->entries()->where('id', $id)->value('recorded_at');

        self::assertIsString($time);

        return $time;
    }

    /**
     * A writer on the storage connection, as the container builds its
     * collaborators, on a clock frozen at the sealing time.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\CheckpointWriter
     */
    private function writer(): CheckpointWriter
    {
        return new CheckpointWriter(app(DatabaseManager::class), app(SealSigner::class), app(SealSettings::class), FrozenClock::at(self::SEALED_AT));
    }

    /**
     * A query of the entries table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function entries(): Builder
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table());
    }

    /**
     * A query of the checkpoints table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function checkpoints(): Builder
    {
        return DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable());
    }

    /**
     * A query of the members table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function members(): Builder
    {
        return DB::connection(StorageConnection::name())->table(IntegrityTables::membersTable());
    }

    /**
     * The ids in byte order, as the members are read back.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private static function sorted(array $ids): array
    {
        usort($ids, strcmp(...));

        return $ids;
    }
}
