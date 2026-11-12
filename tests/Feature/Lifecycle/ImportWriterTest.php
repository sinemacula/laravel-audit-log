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
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportBatches;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportClassifier;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLine;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportRecordBuilder;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportTally;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportWriter;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\ImportedSource;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Concerns\MakesSubjectKeys;
use Tests\TestCase;

/**
 * Feature tests for writing a chunk of an import.
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
    use MakesSubjectKeys;

    /** @var string The code whose card is encrypted for its actor. */
    private const string ENCRYPTED_CODE = 'billing.card_charged';

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
     * A chunk is one transaction of its own, with no savepoint, its statements
     * in order.
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
     * Each chunk inserts its new rows' key uses after the rows, in its one
     * transaction.
     *
     * @return void
     */
    public function testEachChunkInsertsItsKeyUses(): void
    {
        $first  = Reference::of('App\Models\User', '7');
        $second = Reference::of('App\Models\User', '8');

        $this->encryptCardsFor($first, $second);

        $log   = $this->statements();
        $tally = self::read(3);

        $this->writer()->write(self::BATCH, [self::encryptedLine(1, $first), self::encryptedLine(2, $second), self::encryptedLine(3, $first)], $tally, CarbonImmutable::now());

        self::assertSame(['begin', 'claim', 'classify', 'insert', 'key uses', 'counts', 'commit'], $log->getArrayCopy());
        self::assertSame(3, $tally->imported());

        $entries = self::strings($this->connection()->table(EntrySettings::table())->orderBy('source_record_id')->pluck('id')->all());
        $keys    = array_map(fn (Reference $actor): string => $this->makeSubjectKey($actor, null, 'finance')[0]->id, [$first, $second, $first]);

        self::assertSame(self::sortedUses(array_map(static fn (string $key, string $entry): array => [$key, $entry], $keys, $entries)), $this->keyUses());
    }

    /**
     * A duplicate line inserts neither a row nor a key use.
     *
     * @return void
     */
    public function testADuplicateLineInsertsNoKeyUse(): void
    {
        $actor = Reference::of('App\Models\User', '7');

        $this->encryptCardsFor($actor);

        $this->writer()->write(self::BATCH, [self::encryptedLine(1, $actor)], self::read(1), CarbonImmutable::now());

        $uses  = $this->keyUses();
        $tally = self::read(1);

        $this->writer()->write(self::BATCH, [self::encryptedLine(1, $actor)], $tally, CarbonImmutable::now());

        self::assertSame(1, $tally->duplicates());
        self::assertCount(1, $uses);
        self::assertSame($uses, $this->keyUses());
        self::assertSame(1, $this->entries());
    }

    /**
     * A chunk whose key uses fail is rolled back whole.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChunkWhoseKeyUsesFailKeepsNoRow(): void
    {
        $actor = Reference::of('App\Models\User', '7');

        $this->encryptCardsFor($actor);

        app(ConfigRepository::class)->set('audit-log.privacy.key_uses_table', 'audit_missing_key_uses');

        try {
            $this->writer()->write(self::BATCH, [self::encryptedLine(1, $actor)], self::read(1), CarbonImmutable::now());

            self::fail('Expected the chunk to fail.');
        } catch (QueryException $exception) {
            self::assertStringContainsString('audit_missing_key_uses', $exception->getMessage());
        }

        self::assertSame(0, $this->entries());
        self::assertSame(0, $this->connection()->table(LifecycleTables::importBatchesTable())->where('id', self::BATCH)->where('imported', '>', 0)->count());
    }

    /**
     * A chunk refuses to run inside a transaction on the storage connection.
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
     * Every line is built before any is classified, so a rejected line is never
     * a candidate.
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
     * A chunk of 100 lines is inserted 24 rows to a statement on SQLite and in
     * one insert elsewhere.
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
     * A unique violation rolls the chunk back and classifies it once more.
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
     * again]`.
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
     * A chunk lost to a concurrent one is written again; a lost connection is
     * rethrown.
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
     * A chunk that keeps losing stops after its most attempts and is rethrown
     * masked.
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
     * A second violation makes the chunk's new lines conflicts and inserts
     * nothing.
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
     * The counts commit with the rows.
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
     * A chunk of rejected lines opens no transaction.
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
     * A dry run builds and classifies a chunk but issues no statement but
     * reads.
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
     * Each built record already past its retention on arrival is counted.
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
     * Insert a row of the first line's identity after each of the first
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
     * Make the first inserts of entries fail as the driver reports the message
     * given.
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
     * Log the chunk's transaction events and statements by what each is.
     *
     * @return \ArrayObject<int, string>
     */
    private function statements(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $log */
        $log     = new \ArrayObject;
        $batches = LifecycleTables::importBatchesTable();
        $entries = EntrySettings::table();
        $uses    = KeyTables::keyUsesTable();

        Event::listen(TransactionBeginning::class, static fn () => $log->append('begin'));
        Event::listen(TransactionCommitted::class, static fn () => $log->append('commit'));
        Event::listen(TransactionRolledBack::class, static fn () => $log->append('rollback'));

        DB::listen(static function (QueryExecuted $query) use ($log, $batches, $entries, $uses): void {
            $label = self::labelOf(strtolower($query->sql), $batches, $entries, $uses);

            if ($label === null || ($label === 'insert' && $log->getArrayCopy() !== [] && $log[$log->count() - 1] === 'insert')) {
                return;
            }

            $log->append($label);
        });

        return $log;
    }

    /**
     * What the statement is to the chunk, or `null` for anything else.
     *
     * @param  string  $sql
     * @param  string  $batches
     * @param  string  $entries
     * @param  string  $uses
     * @return ?string
     */
    private static function labelOf(string $sql, string $batches, string $entries, string $uses): ?string
    {
        $verb = (string) strtok($sql, ' ');

        return match (true) {
            str_contains($sql, 'savepoint')                                                        => 'savepoint',
            $verb === 'update' && str_contains($sql, $batches) && str_contains($sql, 'lines_read') => 'counts',
            $verb === 'update' && str_contains($sql, $batches)                                     => 'claim',
            $verb === 'select' && str_contains($sql, $entries)                                     => 'classify',
            $verb === 'insert' && str_contains($sql, $entries)                                     => 'insert',
            $verb === 'insert' && str_contains($sql, $uses)                                        => 'key uses',
            default                                                                                => null,
        };
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
     * Encrypt the card for each actor and make each actor's key first, so a
     * chunk only looks them up.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  ...$actors
     * @return void
     */
    private function encryptCardsFor(Reference ...$actors): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define(EventDefinition::for(self::ENCRYPTED_CODE)->category('finance')->retain('amount')->encrypt('card', KeyOwner::ACTOR));

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, new Recorder($catalogue, new ContributorRegistry));
        app()->bind(FieldEncrypter::class, SubjectKeyEncrypter::class);

        foreach ($actors as $actor) {
            $this->makeSubjectKey($actor, null, 'finance');
        }
    }

    /**
     * Every stored key use, as its key and entry, sorted.
     *
     * @return list<array{0: string, 1: string}>
     */
    private function keyUses(): array
    {
        $rows = $this->connection()->table(KeyTables::keyUsesTable())->orderBy('key_id')->orderBy('entry_id')->get();

        return array_values(array_map(static fn (object $row): array => [(string) $row->key_id, (string) $row->entry_id], $rows->all()));
    }

    /**
     * The key uses, sorted by key and then entry, as the store reads them.
     *
     * @param  list<array{0: string, 1: string}>  $uses
     * @return list<array{0: string, 1: string}>
     */
    private static function sortedUses(array $uses): array
    {
        usort($uses, static fn (array $left, array $right): int => strcmp($left[0], $right[0]) ?: strcmp($left[1], $right[1]));

        return $uses;
    }

    /**
     * A line of the encrypted code, `rec-<number>`, by the actor, its card to
     * be encrypted for them.
     *
     * @param  int  $number
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     */
    private static function encryptedLine(int $number, Reference $actor): ImportLine
    {
        return new ImportLine(
            $number,
            'crm-eu',
            null,
            'rec-' . $number,
            self::ENCRYPTED_CODE,
            '2026-10-01T09:00:00.000001Z',
            Outcome::SUCCESS,
            null,
            $actor,
            null,
            null,
            null,
            'finance',
            null,
            ['amount' => '12.00', 'card' => '4242'],
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
