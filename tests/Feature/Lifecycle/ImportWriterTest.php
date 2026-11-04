<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Sleep;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportBatches;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportClassifier;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLine;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportRecordBuilder;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportTally;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportWriter;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\ImportedSource;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\TestCase;

/**
 * Feature tests for writing a chunk of an import, on whichever engine the suite
 * runs against: one transaction of its own and no savepoint, refused inside a
 * host's; every line built before any is classified; the rows per insert of
 * each engine; a unique violation classified again once, a second making the
 * new lines conflicts; the counts committed with the rows; and a dry run that
 * writes nothing.
 *
 * A concurrent import is stood in for by a row of the same source identity
 * inserted, on the chunk's own connection, just after it classifies: the
 * chunk's insert violates the unique index exactly as it would on a concurrent
 * commit, and the rollback removes that row with the chunk's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportWriter::class)]
final class ImportWriterTest extends TestCase
{
    /** @var string The batch every chunk is of. */
    private const string BATCH = '01932b4e-a000-7000-8000-0000000000b1';

    /** @var string When every chunk is imported. */
    private const string NOW = '2026-11-02 09:00:00.000000';

    /**
     * Freeze the clock and start the batch.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        app(ImportBatches::class)->start([
            'id'                  => self::BATCH,
            'source_id'           => 'crm-eu',
            'source_region'       => null,
            'input_format'        => 'audit-log-import/v1',
            'importer_type'       => 'App\Models\User',
            'importer_id'         => '7',
            'reason'              => 'case.review',
            'external_reference'  => null,
            'file_sha256'         => str_repeat('f', 64),
            'externally_verified' => false,
            'hold_id'             => null,
        ]);
    }

    /**
     * Roll back a transaction a test left open and put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = $this->connection();

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        CarbonImmutable::setTestNow();
        Sleep::fake(false);

        parent::tearDown();
    }

    /**
     * A chunk is one transaction of its own, begun and committed once, whose
     * statements are the batch's claim, the classification, the inserts and the
     * counts, in that order, with no savepoint.
     *
     * @return void
     */
    public function testAChunkIsOneTransactionWithNoSavepoint(): void
    {
        $log   = $this->statements();
        $tally = self::read(3);

        $this->writer()->write(self::BATCH, self::lines(3), $tally, CarbonImmutable::now());

        self::assertSame(['begin', 'claim', 'classify', 'insert', 'counts', 'commit'], $log->getArrayCopy());
        self::assertSame(3, $tally->imported());
        self::assertSame(3, $this->entries());
    }

    /**
     * A chunk refuses to run inside a transaction on the storage connection,
     * writing nothing, since it would become a savepoint of the host's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testItRefusesInsideATransaction(): void
    {
        $connection = $this->connection();

        $connection->beginTransaction();

        try {
            $this->writer()->write(self::BATCH, self::lines(1), self::read(1), CarbonImmutable::now());
            self::fail('Expected the chunk to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('An import chunk runs in a transaction of its own on the storage connection, and refuses to run inside one.', $exception->getMessage());
        }

        $connection->rollBack();

        self::assertSame(0, $this->entries());
    }

    /**
     * Every line is built before any is classified: a first line of a pair that
     * does not build is rejected and never the candidate, so the later valid
     * line is new, not a duplicate of nothing.
     *
     * @return void
     */
    public function testARejectedLineIsNeverTheCandidateOfItsPair(): void
    {
        $tally = self::read(2);

        $this->writer()->write(self::BATCH, [self::line(1, 'rec-1', 'not namespaced'), self::line(2, 'rec-1')], $tally, CarbonImmutable::now());

        self::assertSame([1, 0, 0, 1], [$tally->imported(), $tally->duplicates(), $tally->conflicts(), $tally->rejected()]);
        self::assertSame(['invalid_field' => 1], $tally->rejections());
        self::assertSame(1, $this->entries());
    }

    /**
     * A chunk of 100 new lines is inserted 24 rows to a statement on SQLite,
     * five inserts, and in one insert on MySQL and PostgreSQL.
     *
     * @return void
     */
    public function testRowsPerInsertFollowTheEngine(): void
    {
        $inserts = [];

        DB::listen(static function (QueryExecuted $query) use (&$inserts): void {
            if (!str_starts_with(strtolower($query->sql), 'insert') || !str_contains($query->sql, EntrySettings::table())) {
                return;
            }

            $inserts[] = intdiv(count($query->bindings), count(RowCodec::COLUMNS));
        });

        $this->writer()->write(self::BATCH, self::lines(100), self::read(100), CarbonImmutable::now());

        $expected = $this->connection()->getDriverName() === 'sqlite' ? [24, 24, 24, 24, 4] : [100];

        self::assertSame($expected, $inserts);
        self::assertSame(100, $this->entries());
    }

    /**
     * A unique violation rolls the whole chunk back and classifies it once
     * more: the row that caused it went with the rollback, so the lines are new
     * again and each is stored once.
     *
     * @return void
     */
    public function testAUniqueViolationReclassifiesOnce(): void
    {
        $classified = $this->interfere(1);
        $tally      = self::read(3);

        $this->writer()->write(self::BATCH, self::lines(3), $tally, CarbonImmutable::now());

        self::assertCount(2, $classified);
        self::assertSame([3, 0, 0], [$tally->imported(), $tally->duplicates(), $tally->conflicts()]);
        self::assertSame(3, $this->entries());
        self::assertSame('3', (string) (app(ImportBatches::class)->find(self::BATCH)['imported'] ?? null));
    }

    /**
     * Rows of `[the driver's message, whether a chunk that meets it is tried
     * again]`: a deadlock, a serialisation failure and a lock wait timeout are
     * lost to a concurrent chunk; a lost connection never is, since its commit
     * may have happened.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideConcurrentFailures(): iterable
    {
        yield from [
            'a deadlock'              => ['SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction', true],
            'a serialisation failure' => ['SQLSTATE[40P01]: Deadlock detected: 7 ERROR:  deadlock detected', true],
            'a lock wait timeout'     => ['SQLSTATE[HY000]: General error: 1205 Lock wait timeout exceeded; try restarting transaction', true],
            'a lost connection'       => ['SQLSTATE[HY000]: General error: 2006 MySQL server has gone away', false],
        ];
    }

    /**
     * A chunk lost to a concurrent one rolls back whole and is classified and
     * written again after a short wait, so every line is stored once; a lost
     * connection is rethrown and nothing is stored.
     *
     * @param  string  $message
     * @param  bool  $retried
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideConcurrentFailures')]
    public function testAChunkLostToAConcurrentOneIsTriedAgain(string $message, bool $retried): void
    {
        Sleep::fake();

        $this->failInserts(1, $message);

        $log   = $this->statements();
        $tally = self::read(3);

        try {
            $this->writer()->write(self::BATCH, self::lines(3), $tally, CarbonImmutable::now());
            self::assertTrue($retried, 'Expected the chunk to be rethrown.');
        } catch (QueryException $exception) {
            self::assertFalse($retried, 'Expected the chunk to be tried again.');
            self::assertSame([], $exception->getBindings());
        }

        self::assertCount($retried ? 2 : 1, array_keys($log->getArrayCopy(), 'classify', true));
        self::assertSame($retried ? 3 : 0, $this->entries());
        Sleep::assertSleptTimes($retried ? 1 : 0);
    }

    /**
     * A chunk that keeps losing to concurrent ones stops after its most
     * attempts and is rethrown masked, with nothing stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChunkStopsAfterItsMostAttempts(): void
    {
        Sleep::fake();

        $this->failInserts(PHP_INT_MAX, 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction');

        try {
            $this->writer()->write(self::BATCH, self::lines(2), self::read(2), CarbonImmutable::now());
            self::fail('Expected the chunk to be rethrown.');
        } catch (QueryException $exception) {
            self::assertSame([], $exception->getBindings());
            self::assertStringNotContainsString('rec-1', $exception->getMessage());
        }

        self::assertSame(0, $this->entries());
        Sleep::assertSleptTimes(ImportWriter::MAX_ATTEMPTS - 1);
    }

    /**
     * A second violation makes the chunk's new lines conflicts, listed with the
     * rest, inserts nothing, and writes the batch's counts alone.
     *
     * @return void
     */
    public function testASecondViolationMakesTheNewLinesConflicts(): void
    {
        $classified = $this->interfere(2);
        $tally      = self::read(3);

        $this->writer()->write(self::BATCH, [...self::lines(2), self::line(3, 'rec-1')], $tally, CarbonImmutable::now());

        $batch = app(ImportBatches::class)->find(self::BATCH);

        self::assertCount(2, $classified);
        self::assertSame([0, 1, 2], [$tally->imported(), $tally->duplicates(), $tally->conflicts()]);
        self::assertSame(['rec-1', 'rec-2'], $tally->conflictIds());
        self::assertSame(0, $this->entries());
        self::assertSame(['2', '["rec-1","rec-2"]', '1'], [(string) ($batch['conflicts'] ?? null), $batch['conflict_ids'] ?? null, (string) ($batch['duplicates'] ?? null)]);
    }

    /**
     * The counts commit with the rows: a chunk whose batch is no longer running
     * fails at its counts, and its rows roll back with them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCountsCommitWithTheRows(): void
    {
        app(ImportBatches::class)->close(self::BATCH);

        $log = $this->statements();

        try {
            $this->writer()->write(self::BATCH, self::lines(2), self::read(2), CarbonImmutable::now());
            self::fail('Expected the chunk of a closed batch to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('The import batch is no longer running, and is not written to.', $exception->getMessage());
        }

        self::assertSame(['begin', 'claim', 'classify', 'insert', 'counts', 'rollback'], $log->getArrayCopy());
        self::assertSame(0, $this->entries());
        self::assertSame(ImportStatus::INTERRUPTED->value, app(ImportBatches::class)->find(self::BATCH)['status'] ?? null);
    }

    /**
     * A chunk none of whose lines builds opens no transaction and writes
     * nothing; its lines are rejected.
     *
     * @return void
     */
    public function testAChunkOfRejectedLinesWritesNothing(): void
    {
        $log   = $this->statements();
        $tally = self::read(2);

        $this->writer()->write(self::BATCH, [self::line(1, 'rec-1', 'bad'), self::line(2, 'rec-2', 'worse')], $tally, CarbonImmutable::now());

        self::assertSame([], $log->getArrayCopy());
        self::assertSame(2, $tally->rejected());
    }

    /**
     * A dry run builds and classifies a chunk, counting it as an import would,
     * and issues no statement but reads.
     *
     * @return void
     */
    public function testADryRunWritesNothing(): void
    {
        $this->writer()->write(self::BATCH, [self::line(1, 'rec-1')], self::read(1), CarbonImmutable::now());

        $log   = $this->statements();
        $tally = new ImportTally;

        $this->writer()->plan([self::line(2, 'rec-1'), self::line(3, 'rec-2'), self::line(4, 'rec-2', 'bad')], $tally, CarbonImmutable::now());

        self::assertSame(['classify'], $log->getArrayCopy());
        self::assertSame([1, 1, 0, 1], [$tally->imported(), $tally->duplicates(), $tally->conflicts(), $tally->rejected()]);
        self::assertSame(1, $this->entries());
    }

    /**
     * Given the run's retention decisions, each built record already past its
     * retention on arrival is counted.
     *
     * @return void
     */
    public function testLinesPastRetentionAreCounted(): void
    {
        app(ConfigRepository::class)->set('audit-log.retention.categories', ['finance' => 30]);

        $retention = new RetentionDecisions(app(ConfiguredRetentionPolicy::class), CarbonImmutable::now());
        $tally     = self::read(2);
        $recent    = new ImportLine(
            2,
            'crm-eu',
            null,
            'rec-2',
            'invoice.approved',
            '2026-11-01T00:00:00.000000Z',
            Outcome::SUCCESS,
            null,
            null,
            null,
            null,
            null,
            'finance',
            null,
            null,
            null,
            null,
            null,
        );

        $this->writer()->write(self::BATCH, [self::line(1, 'rec-1'), $recent], $tally, CarbonImmutable::now(), $retention);

        self::assertSame(1, $tally->pastRetention());
        self::assertSame(2, $tally->imported());
    }

    /**
     * Insert a row of the first line's source identity after each of the first
     * classifications, on the chunk's own connection, and return the count of
     * classifications.
     *
     * @param  int  $times
     * @return \ArrayObject<int, string>
     */
    private function interfere(int $times): \ArrayObject
    {
        $row = $this->rowOf(self::line(1, 'rec-1', event: 'invoice.voided'));

        /** @var \ArrayObject<int, string> $classified */
        $classified = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($classified, $times, $row): void {
            if (!str_starts_with(strtolower($query->sql), 'select') || !str_contains($query->sql, EntrySettings::table())) {
                return;
            }

            $classified->append($query->sql);

            if ($classified->count() > $times) {
                return;
            }

            DB::connection($query->connectionName)->table(EntrySettings::table())->insert($row);
        });

        return $classified;
    }

    /**
     * Make the first inserts of entries, up to the number given, fail before
     * they run, as the driver reports the message given.
     *
     * @param  int  $times
     * @param  string  $message
     * @return void
     */
    private function failInserts(int $times, string $message): void
    {
        $failed = 0;

        $this->connection()->beforeExecuting(static function (string $sql, array $bindings, Connection $connection) use (&$failed, $times, $message): void {
            if ($failed >= $times || !str_starts_with(strtolower($sql), 'insert') || !str_contains($sql, EntrySettings::table())) {
                return;
            }

            $failed++;

            throw new QueryException((string) $connection->getName(), $sql, $bindings, new \PDOException($message));
        });
    }

    /**
     * The row an import of the line would store.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine  $line
     * @return array<string, int|string|null>
     */
    private function rowOf(ImportLine $line): array
    {
        $digest = app(ImportClassifier::class)->digestOf($line);
        $source = new ImportedSource($line->sourceId, null, $line->sourceRecordId, self::BATCH, $digest);
        $record = app(ImportRecordBuilder::class)->build($line, $source, CarbonImmutable::now(), false);

        self::assertInstanceOf(AuditRecord::class, $record);

        return app(RowCodec::class)->encode(app(RecordFinaliser::class)->finalise($record));
    }

    /**
     * Log the chunk's transaction events and statements by what each is: the
     * claim and the counts on the batch, the classification, the inserts.
     *
     * @return \ArrayObject<int, string>
     */
    private function statements(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $log */
        $log     = new \ArrayObject;
        $batches = LifecycleTables::importBatchesTable();
        $entries = EntrySettings::table();

        Event::listen(TransactionBeginning::class, static fn () => $log->append('begin'));
        Event::listen(TransactionCommitted::class, static fn () => $log->append('commit'));
        Event::listen(TransactionRolledBack::class, static fn () => $log->append('rollback'));

        DB::listen(static function (QueryExecuted $query) use ($log, $batches, $entries): void {
            $sql  = strtolower($query->sql);
            $verb = (string) strtok($sql, ' ');

            $label = match (true) {
                str_contains($sql, 'savepoint')                                                        => 'savepoint',
                $verb === 'update' && str_contains($sql, $batches) && str_contains($sql, 'lines_read') => 'counts',
                $verb === 'update' && str_contains($sql, $batches)                                     => 'claim',
                $verb === 'select' && str_contains($sql, $entries)                                     => 'classify',
                $verb === 'insert' && str_contains($sql, $entries)                                     => 'insert',
                default                                                                                => null,
            };

            if ($label === null || ($label === 'insert' && $log->getArrayCopy() !== [] && $log[$log->count() - 1] === 'insert')) {
                return;
            }

            $log->append($label);
        });

        return $log;
    }

    /**
     * The count of stored entries.
     *
     * @return int
     */
    private function entries(): int
    {
        return $this->connection()->table(EntrySettings::table())->count();
    }

    /**
     * A tally that has read the number of lines given.
     *
     * @param  int  $count
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally
     */
    private static function read(int $count): ImportTally
    {
        $tally = new ImportTally;

        for ($index = 0; $index < $count; $index++) {
            $tally->countRead();
        }

        return $tally;
    }

    /**
     * Lines `rec-1` to `rec-<count>`.
     *
     * @param  int  $count
     * @return list<\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine>
     */
    private static function lines(int $count): array
    {
        return array_map(static fn (int $number): ImportLine => self::line($number, 'rec-' . $number), range(1, $count));
    }

    /**
     * A line of the number and record id given, with the correlation id and
     * code given.
     *
     * @param  int  $number
     * @param  string  $recordId
     * @param  ?string  $correlationId
     * @param  string  $event
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     */
    private static function line(int $number, string $recordId, ?string $correlationId = null, string $event = 'invoice.approved'): ImportLine
    {
        return new ImportLine(
            $number,
            'crm-eu',
            null,
            $recordId,
            $event,
            '2026-10-01T09:00:00.000001Z',
            Outcome::SUCCESS,
            null,
            null,
            null,
            null,
            null,
            'finance',
            $correlationId,
            ['amount' => '1200.00'],
            null,
            null,
            null,
        );
    }

    /**
     * The writer the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportWriter
     */
    private function writer(): ImportWriter
    {
        return app(ImportWriter::class);
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function connection(): Connection
    {
        return DB::connection(StorageConnection::name());
    }
}
