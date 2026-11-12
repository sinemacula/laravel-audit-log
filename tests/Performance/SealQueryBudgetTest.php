<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Sleep;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Integrity\Anchorer;
use SineMacula\Laravel\AuditLog\Integrity\AnchorResult;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorSettings;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\CheckpointWriter;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\Sealer;
use SineMacula\Laravel\AuditLog\Integrity\SealResult;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Integrity\RecordingAnchor;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;

/**
 * Statement budget for sealing and anchoring: each batch, sweep window and
 * anchored seal has a fixed cost, nothing is read per entry, and candidates are
 * read without their payload.
 *
 * Every batch is at least 100, the least the settings accept, and each test
 * starts with the installation's id written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Sealer::class)]
#[CoversClass(CheckpointWriter::class)]
#[CoversClass(Anchorer::class)]
final class SealQueryBudgetTest extends PerformanceContractTestCase
{
    use SealsEntries;

    /** @var int The batch most tests seal in: the least the settings accept. */
    private const int BATCH = 100;

    /** @var int The reads each batch of the recent pass that seals makes: the head, its candidates and the journal's head. */
    private const int BATCH_READS = 3;

    /** @var int The reads each batch that seals nothing makes: the head and its candidates. */
    private const int EMPTY_BATCH_READS = 2;

    /** @var int The writes each recent-pass batch smaller than a chunk makes: checkpoint, members, last seal and high-water mark. */
    private const int BATCH_WRITES = 4;

    /** @var int The reads a recent pass makes once with no high-water mark yet: the installation id, the mark and the head's start. */
    private const int RUN_READS = 3;

    /** @var int The writes a run makes once, whatever it seals: its last run. */
    private const int RUN_WRITES = 1;

    /** @var string What the recent pass selects of each candidate. */
    private const string RECENT_COLUMNS = 'e.id, e.hmac, e.recorded_at';

    /** @var string What the sweep selects of each row of its window. */
    private const string WINDOW_COLUMNS = 'w.id, w.hmac, w.recorded_at, m.entry_id as member_entry_id';

    /** @var string What the sweep's window selects of each entry. */
    private const string WINDOWED_COLUMNS = 'id, hmac, recorded_at';

    /** @var string A write statement and the table it names, quotes removed. */
    private const string WRITE_PATTERN = '/^(?:insert\s+into|update|delete\s+from|replace\s+into)\s+(\S+)/i';

    /** @var int Entries inserted by one statement, well under every engine's placeholder limit. */
    private const int INSERT_CHUNK = 20;

    /** @var string A digest no entry can hold, since it is not hex. */
    private const string MALFORMED_HMAC = 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz';

    /**
     * Stop faking sleep, in case a test faked it.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Sleep::fake(false);

        parent::tearDown();
    }

    /**
     * An empty recent pass with no high-water mark makes five reads and writes
     * only its last run, in one transaction.
     *
     * @return void
     */
    public function testAnEmptyRunIsFiveReadsAndOneWrite(): void
    {
        $reads  = self::RUN_READS + self::EMPTY_BATCH_READS;
        $result = $this->assertTransactionBudget(1, 1, fn (): SealResult => $this->assertStatementBudget($reads, 1, 0, 0, fn (): SealResult => $this->sealer()->seal()));

        self::assertSame(0, $result->seals());
        self::assertSame([IntegrityTables::stateTable()], self::tablesWritten($this->capturedWrites()));
    }

    /**
     * An empty sweep makes four reads, then writes its completion, forgets its
     * cursor and writes its last run.
     *
     * @return void
     */
    public function testAnEmptySweepIsPinned(): void
    {
        $result = $this->assertTransactionBudget(1, 1, fn (): SealResult => $this->assertStatementBudget(4, 3, 0, 0, fn (): SealResult => $this->sealer()->sweep()));

        self::assertTrue($result->isSweepComplete());
        self::assertSame([IntegrityTables::stateTable()], self::tablesWritten($this->capturedWrites()));
    }

    /**
     * Five rows in a batch of a hundred are one seal: six reads and five
     * writes, in one transaction with no savepoint.
     *
     * @return void
     */
    public function testOneBatchIsPinned(): void
    {
        $this->useBatch(self::BATCH);
        $this->storeEntries(5);

        $result = $this->assertTransactionBudget(1, 1, fn (): SealResult => $this->assertStatementBudget(6, 5, 0, 0, fn (): SealResult => $this->sealer()->seal()));

        self::assertSame(1, $result->seals());
        self::assertSame(5, $result->entries());
        self::assertSame([IntegrityTables::checkpointsTable(), IntegrityTables::membersTable(), IntegrityTables::stateTable()], self::tablesWritten($this->capturedWrites()));
    }

    /**
     * A batch that fills the limit cannot know it reached the end, so it asks
     * once more: two reads in one more transaction.
     *
     * @return void
     */
    public function testAFullBatchAsksOnceMore(): void
    {
        $this->useBatch(self::BATCH);
        $this->insertEntries(self::BATCH);

        $result = $this->assertTransactionBudget(2, 2, fn (): SealResult => $this->assertStatementBudget(8, 5, 0, 0, fn (): SealResult => $this->sealer()->seal()));

        self::assertSame(1, $result->seals());
        self::assertSame(self::BATCH, $result->entries());
    }

    /**
     * Members are inserted one statement per chunk: 301 members are two
     * inserts.
     *
     * @return void
     */
    public function testMembersCostOneStatementPerChunk(): void
    {
        $this->insertEntries(CheckpointWriter::MEMBER_CHUNK + 1);

        $this->assertStatementBudget(6, 6, 0, 0, fn (): SealResult => $this->sealer()->seal());

        $members = array_filter(self::tablesWritten($this->capturedWrites(), false), static fn (string $table): bool => $table === IntegrityTables::membersTable());

        self::assertCount(2, $members);
        self::assertSame(300, CheckpointWriter::MEMBER_CHUNK);
    }

    /**
     * Ten batches cost ten times one, each in its own transaction, plus the
     * run's constant once.
     *
     * @return void
     */
    public function testTenBatchesCostTenTimesOne(): void
    {
        $this->useBatch(self::BATCH);
        $this->insertEntries(9 * self::BATCH + intdiv(self::BATCH, 2));

        $reads  = 10 * self::BATCH_READS  + self::RUN_READS;
        $writes = 10 * self::BATCH_WRITES + self::RUN_WRITES;

        $result = $this->assertTransactionBudget(10, 10, fn (): SealResult => $this->assertStatementBudget($reads, $writes, 0, 0, fn (): SealResult => $this->sealer()->seal()));

        self::assertSame(10, $result->seals());
        self::assertSame(950, $result->entries());
    }

    /**
     * An attempt lost to a concurrent writer costs one transaction rollback,
     * never a savepoint, and the whole attempt again.
     *
     * @return void
     */
    public function testAConflictCostsARollbackAndAFullReattempt(): void
    {
        Sleep::fake();

        $this->storeEntries(5);
        $this->loseTheFirstCheckpointInsert();

        $reads  = self::RUN_READS  + 2 * self::BATCH_READS;
        $writes = self::RUN_WRITES + 1 + self::BATCH_WRITES;

        $result = $this->assertTransactionBudget(2, 1, fn (): SealResult => $this->assertStatementBudget($reads, $writes, 0, 1, fn (): SealResult => $this->sealer()->seal()));

        self::assertSame(1, $result->retries());
        self::assertSame(1, $result->seals());
        self::assertSame(5, $result->entries());
    }

    /**
     * With no anchor configured, a pass over never-anchored seals costs no
     * statement.
     *
     * @return void
     */
    public function testTheNullAnchorCostsNothing(): void
    {
        $this->storeEntries(2);
        $this->sealer()->seal();

        $result = $this->assertStatementBudget(0, 0, 0, 0, fn (): AnchorResult => $this->anchorer(new NullAnchor)->anchorPending());

        self::assertFalse($result->isConfigured());
    }

    /**
     * Anchoring a seal reads the seals after its head and outside the chain
     * once each, updates the seal and writes the last anchoring.
     *
     * @return void
     */
    public function testAnchoringASealIsTwoReadsOneUpdateAndItsProgress(): void
    {
        $this->storeSeals(1);

        $result = $this->assertStatementBudget(2, 2, 0, 0, fn (): AnchorResult => $this->anchorer(new RecordingAnchor)->anchorPending());

        self::assertSame(1, $result->lastAnchored());
        self::assertSame([IntegrityTables::checkpointsTable(), IntegrityTables::stateTable()], self::tablesWritten($this->capturedWrites()));
    }

    /**
     * Each further seal a pass anchors costs one update, never another read or
     * another write of the progress.
     *
     * @return void
     */
    public function testEachFurtherSealAnchoredCostsOneUpdate(): void
    {
        $this->storeSeals(3);

        $result = $this->assertStatementBudget(2, 4, 0, 0, fn (): AnchorResult => $this->anchorer(new RecordingAnchor)->anchorPending());

        self::assertSame(3, $result->lastAnchored());
    }

    /**
     * A pass over an anchored log makes three indexed reads whatever its size,
     * and writes nothing.
     *
     * @return void
     */
    public function testAnAnchoredLogCostsThreeReads(): void
    {
        $this->storeSeals(2);

        $anchor = new RecordingAnchor;

        $this->anchorer($anchor)->anchorPending();

        $result = $this->assertStatementBudget(3, 0, 0, 0, fn (): AnchorResult => $this->anchorer($anchor)->anchorPending());

        self::assertNull($result->lastAnchored());
    }

    /**
     * An anchor that fails, discovery included, costs its fallback reads and
     * its failure writes, and records no anchoring progress.
     *
     * @return void
     */
    public function testAnUnavailableAnchorCostsItsFailureAndNoProgress(): void
    {
        $this->storeSeals(3);

        $result = $this->assertStatementBudget(3, 2, 0, 0, fn (): AnchorResult => $this->anchorer((new RecordingAnchor)->failing())->anchorPending());

        self::assertTrue($result->isStopped());
        self::assertNull($result->lastAnchored());
    }

    /**
     * Rows of `[run, the select lists of the candidate statement, outer
     * first]`: the recent pass, and the sweep, whose window is a derived table.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Integrity\Sealer): \SineMacula\Laravel\AuditLog\Integrity\SealResult, 1: list<string>}>
     */
    public static function provideCandidateSelections(): iterable
    {
        yield from [
            'the recent pass' => [static fn (Sealer $sealer): SealResult => $sealer->seal(), [self::RECENT_COLUMNS]],
            'the sweep'       => [static fn (Sealer $sealer): SealResult => $sealer->sweep(), [self::WINDOW_COLUMNS, self::WINDOWED_COLUMNS]],
        ];
    }

    /**
     * The candidates are read by id, HMAC and time alone, in one statement per
     * batch.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Integrity\Sealer): \SineMacula\Laravel\AuditLog\Integrity\SealResult  $run
     * @param  list<string>  $columns
     * @return void
     */
    #[DataProvider('provideCandidateSelections')]
    public function testTheCandidateQueryReadsNoPayload(\Closure $run, array $columns): void
    {
        $this->storeEntries(3);

        $result = $this->capture(fn (): SealResult => $run($this->sealer()));

        $table      = preg_quote(EntrySettings::table(), '/');
        $pattern    = '/^select (.+?) from (?:\S*' . $table . '\S* as e\b|\(select (.+?) from \S*' . $table . '\b)/';
        $selections = [];

        foreach ($this->capturedStatements() as $statement) {
            if (preg_match($pattern, str_replace(['"', '`'], '', $statement), $matches) !== 1) {
                continue;
            }

            $selections[] = array_values(array_filter(array_slice($matches, 1), static fn (string $list): bool => $list !== ''));
        }

        self::assertSame([$columns], $selections);
        self::assertSame(3, $result->entries());
    }

    /**
     * A sweep reads each of five windows once, at most its batch, and writes
     * only its cursor, completion and last run.
     *
     * @return void
     */
    public function testASweepWindowReadsAtMostItsBatch(): void
    {
        $this->useBatch(self::BATCH);
        $this->insertEntries(4 * self::BATCH + intdiv(self::BATCH, 2));
        $this->sealAll();

        $windows = $this->recordWindows();
        $result  = $this->assertStatementBudget(2 + 5 * self::EMPTY_BATCH_READS, 4 + 3, 0, 0, fn (): SealResult => $this->sealer()->sweep());

        self::assertSame(0, $result->seals());
        self::assertTrue($result->isSweepComplete());
        self::assertSame([IntegrityTables::stateTable()], self::tablesWritten($this->capturedWrites()));

        $read = array_map(static fn (array $window): int => count(DB::connection()->select($window[0], $window[1])), $windows->getArrayCopy());

        self::assertSame([100, 100, 100, 100, 50], $read);
    }

    /**
     * A candidate that cannot be sealed is left out at no cost.
     *
     * @return void
     */
    public function testASkippedCandidateCostsNoStatement(): void
    {
        $ids = $this->storeEntries(3);

        DB::connection()->table(EntrySettings::table())->where('id', $ids[0])->update(['hmac' => self::MALFORMED_HMAC]);

        $result = $this->assertStatementBudget(6, 5, 0, 0, fn (): SealResult => $this->sealer()->seal());

        self::assertSame(1, $result->skippedEntries());
        self::assertSame(2, $result->entries());
        self::assertSame(0, $this->countMembersOf($ids[0]));
    }

    /**
     * A batch of only skipped candidates writes no seal: it costs an empty
     * batch's reads and the last run.
     *
     * @return void
     */
    public function testABatchOfOnlySkippedCandidatesWritesNoSeal(): void
    {
        $ids = $this->storeEntries(1);

        DB::connection()->table(EntrySettings::table())->where('id', $ids[0])->update(['hmac' => self::MALFORMED_HMAC]);

        $result = $this->assertStatementBudget(5, 1, 0, 0, fn (): SealResult => $this->sealer()->seal());

        self::assertSame(1, $result->skippedEntries());
        self::assertSame(0, $result->seals());
    }

    /**
     * Each seal reads the journal's head once in its own transaction, an empty
     * one never, and each run reads the installation id once.
     *
     * @return void
     */
    public function testEachSealReadsTheJournalHeadOnceAndEachRunTheIdentityOnce(): void
    {
        $this->useBatch(self::BATCH);
        $this->insertEntries(3 * self::BATCH);

        $reads      = 3 * self::BATCH_READS  + self::EMPTY_BATCH_READS + self::RUN_READS;
        $writes     = 3 * self::BATCH_WRITES + self::RUN_WRITES;
        $result     = $this->assertStatementBudget($reads, $writes, 0, 0, fn (): SealResult => $this->sealer()->seal());
        $statements = $this->capturedStatements();
        $journal    = array_filter($statements, static fn (string $statement): bool => str_contains($statement, LifecycleTables::journalTable()));
        $state      = array_filter($statements, static fn (string $statement): bool => self::readsTheState($statement));

        // The run reads the state table twice: the installation id first, then
        // the high-water mark
        self::assertSame(3, $result->seals());
        self::assertCount(3, $journal);
        self::assertCount(2, $state);
        self::assertStringContainsString(IntegrityTables::stateTable(), $statements[0] ?? '');
    }

    /**
     * Whether the statement reads the integrity state table.
     *
     * @param  string  $statement
     * @return bool
     */
    private static function readsTheState(string $statement): bool
    {
        return str_contains($statement, IntegrityTables::stateTable()) && str_starts_with(strtolower($statement), 'select');
    }

    /**
     * Seal in batches of the size given.
     *
     * @param  int  $batch
     * @return void
     */
    private function useBatch(int $batch): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.seal.batch', $batch);
    }

    /**
     * Insert finalised records as entries a chunk at a time, each a microsecond
     * after the last: what storing them one by one would leave, far faster.
     *
     * @param  int  $count
     * @return void
     */
    private function insertEntries(int $count): void
    {
        $first = new CarbonImmutable(self::ENTRIES_RECORDED_AT, 'UTC');
        $codec = app(RowCodec::class);

        foreach (array_chunk(range(0, $count - 1), self::INSERT_CHUNK) as $chunk) {
            $rows = array_map(static function (int $index) use ($first, $codec): array {
                $instant = StoredTime::format($first->addMicroseconds($index));

                return $codec->encode((new RecordFinaliser(FrozenClock::at($instant), app(RecordSigner::class)))->finalise(RecordFactory::captured(occurredAt: $instant)));
            }, $chunk);

            DB::connection()->table(EntrySettings::table())->insert($rows);
        }
    }

    /**
     * Store and seal the number of seals, two entries each, recorded a minute
     * apart, so each recent pass seals the entries stored before it.
     *
     * @param  int  $count
     * @return void
     */
    private function storeSeals(int $count): void
    {
        $first = new CarbonImmutable('2026-11-01 11:00:00', 'UTC');

        for ($seal = 0; $seal < $count; $seal++) {
            $this->storeEntries(2, $first->addMinutes($seal)->format('Y-m-d H:i:s.u'));
            $this->sealer()->seal();
        }
    }

    /**
     * An anchorer of the anchor given, built from the container's
     * collaborators.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @return \SineMacula\Laravel\AuditLog\Integrity\Anchorer
     */
    private function anchorer(CheckpointAnchor $anchor): Anchorer
    {
        return new Anchorer($anchor, app(SealSigner::class), app(AnchorSettings::class), app(IntegrityProgress::class), app(Clock::class), app(DatabaseManager::class));
    }

    /**
     * Make the next checkpoint insert fail as one a concurrent sealer won
     * would, once, before it runs.
     *
     * @return void
     */
    private function loseTheFirstCheckpointInsert(): void
    {
        $armed = true;

        DB::connection()->beforeExecuting(static function (string $query) use (&$armed): void {
            if (!$armed || preg_match('/^insert into \S*' . IntegrityTables::checkpointsTable() . '\b/', str_replace(['"', '`'], '', $query)) !== 1) {
                return;
            }

            $armed  = false;
            $driver = new \PDOException('SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry');

            $driver->errorInfo = ['23000', 1062, ''];

            throw new UniqueConstraintViolationException(self::CONNECTION, $query, [], $driver);
        });
    }

    /**
     * Record the statement and bindings of every sweep window read from now on,
     * so each can be run again to count its rows.
     *
     * @return \ArrayObject<int, array{0: string, 1: list<scalar|null>}>
     */
    private function recordWindows(): \ArrayObject
    {
        /** @var \ArrayObject<int, array{0: string, 1: list<scalar|null>}> $windows */
        $windows = new \ArrayObject;
        $pattern = '/^select .* from \(select .* from \S*' . preg_quote(EntrySettings::table(), '/') . '\b/';

        DB::connection()->beforeExecuting(static function (string $query, array $bindings) use ($windows, $pattern): void {
            if (preg_match($pattern, str_replace(['"', '`'], '', $query)) !== 1) {
                return;
            }

            $windows->append([$query, array_values(array_map(static fn (mixed $value): bool|float|int|string|null => is_scalar($value) ? $value : null, $bindings))]);
        });

        return $windows;
    }

    /**
     * How many member rows hold the entry.
     *
     * @param  string  $entryId
     * @return int
     */
    private function countMembersOf(string $entryId): int
    {
        return DB::connection()->table(IntegrityTables::membersTable())->where('entry_id', $entryId)->count();
    }

    /**
     * The tables the writes name, in the order first written, each once unless
     * every write is asked for.
     *
     * @param  list<string>  $writes
     * @param  bool  $unique
     * @return list<string>
     */
    private static function tablesWritten(array $writes, bool $unique = true): array
    {
        $tables = array_map(static fn (string $write): string => preg_match(self::WRITE_PATTERN, str_replace(['"', '`'], '', $write), $matches) === 1 ? $matches[1] : '', $writes);

        return $unique ? array_values(array_unique($tables)) : $tables;
    }
}
