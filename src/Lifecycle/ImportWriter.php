<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Sleep;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\ImportedSource;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;

/**
 * Writes one chunk of an import: its lines built, classified and inserted, and
 * its batch's counts written with them, in one transaction of its own on the
 * storage connection's writer.
 *
 * Every line is built and finalised first, and a line that does not build is
 * counted rejected, so only the lines that built are classified and a rejected
 * line is never the candidate of a later one. The chunk's transaction then
 * writes the batch's time, its first statement, which on SQLite takes the
 * database's write lock before anything is read; classifies the lines against
 * the stored rows and each other; inserts the new ones, 24 rows to a statement
 * on SQLite, whose oldest builds allow 999 placeholders, and up to 1,000 on
 * MySQL and PostgreSQL, under their 65,535; writes the batch's counts; and
 * commits, so the counts never run ahead of or behind the rows. The transaction
 * makes one attempt and is refused inside another, so it is never a savepoint
 * and never a subtransaction of the host's, whatever the chunk's size; a row's
 * failure fails its chunk.
 *
 * A concurrent import of the same source records can insert one between the
 * classification and the insert: the source's unique index refuses the insert,
 * the whole chunk rolls back, and it is classified and written again once, when
 * the rows stored meanwhile are duplicates or conflicts. A second violation
 * makes the chunk's new lines conflicts, listed with the rest, and only the
 * batch's counts are written; a later import of the same file imports them, or
 * finds them duplicates. Two imports whose files share records in different
 * orders can deadlock, or fail to serialise, or time out waiting on each
 * other's locks: the chunk that lost rolled back whole and is tried again after
 * a short random wait, up to four attempts in all, reclassified as after a
 * violation; a lost connection is never tried again, since its commit may have
 * happened. A batch closed while its import ran is not written to, and the
 * chunk is rolled back and refused. A failed statement is rethrown masked, its
 * class and SQLSTATE kept and no binding of an imported record in its message.
 *
 * The lines already past their retention on arrival are counted through the
 * run's retention decisions as best it can: a policy or setting that fails to
 * answer gives the count up for the rest of the import, reported once by its
 * class, and never rejects a line or fails a chunk.
 *
 * A dry run builds the lines encrypting nothing and classifies them against the
 * stored rows outside any transaction, writing nothing; lines repeated in
 * different chunks of one file are not compared, since nothing of an earlier
 * chunk is stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ImportWriter
{
    /** @var int Rows one insert writes on SQLite: 24 rows of 37 columns is 888 placeholders, under the oldest limit of 999. */
    public const int SQLITE_ROWS_PER_INSERT = 24;

    /** @var int Rows one insert writes on MySQL and PostgreSQL: 37,000 placeholders, under their limit of 65,535; a chunk of the default 500 is one insert. */
    public const int ROWS_PER_INSERT = 1000;

    /** @var int The attempts a chunk makes at its rows: the first, and one after a unique violation. */
    public const int ATTEMPTS = 2;

    /** @var int The most attempts a chunk makes in all, those after it lost to a concurrent chunk included. */
    public const int MAX_ATTEMPTS = 4;

    /** @var int The bound of the wait after the first attempt lost to a concurrent chunk, in milliseconds; it doubles after each. */
    public const int JITTER_BASE_MS = 20;

    /** @var int The longest wait between two attempts, in milliseconds. */
    public const int JITTER_MAX_MS = 1000;

    /** @var string The report of a policy that failed to count the lines past retention, by the failure's class. */
    private const string PAST_RETENTION_GIVEN_UP = 'Counting an import\'s lines past retention did not complete: %s; the import goes on without the count.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportClassifier  $classifier
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportRecordBuilder  $builder
     * @param  \SineMacula\Laravel\AuditLog\Records\RecordFinaliser  $finaliser
     * @param  \SineMacula\Laravel\AuditLog\Stores\RowCodec  $codec
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportBatches  $batches
     * @param  \SineMacula\Laravel\AuditLog\Database\FailureClassifier  $failures
     * @param  \Illuminate\Contracts\Debug\ExceptionHandler  $reporter
     */
    public function __construct(

        /** The connections the storage connection is resolved from on every chunk. */
        private DatabaseManager $database,

        /** Classifies the built lines as new, duplicates or conflicts. */
        private ImportClassifier $classifier,

        /** Builds each line's record. */
        private ImportRecordBuilder $builder,

        /** Signs each record under the ring's signing key. */
        private RecordFinaliser $finaliser,

        /** Turns each record into its row. */
        private RowCodec $codec,

        /** Writes the batch's time and counts in each chunk's transaction. */
        private ImportBatches $batches,

        /** Tells a chunk lost to a concurrent one from any other failure. */
        private FailureClassifier $failures,

        /** What a policy's failure to count the lines past retention is reported to. */
        private ExceptionHandler $reporter,
    ) {}

    /**
     * Write the chunk of lines of the batch, imported at the time given, in one
     * transaction, and count it; each record past its retention on arrival is
     * counted too when the run's decisions are given.
     *
     * @param  string  $batchId
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine>  $lines
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @param  \DateTimeInterface  $importedAt
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $retention
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \Illuminate\Database\QueryException
     * @throws \Throwable
     */
    public function write(string $batchId, #[\SensitiveParameter] array $lines, ImportTally $tally, \DateTimeInterface $importedAt, ?RetentionDecisions $retention = null): void
    {
        $connection = $this->connection();

        self::refuseInsideATransaction($connection);

        [$built, $records] = $this->built($batchId, $lines, $tally, $importedAt, $retention);

        if ($built === []) {
            return;
        }

        $rows = array_map(fn (#[\SensitiveParameter] AuditRecord $record): array => $this->codec->encode($this->finaliser->finalise($record)), $records);

        try {
            $tally->countPlan($this->attempts($connection, $batchId, $built, $rows, $tally));
        } catch (QueryException $failure) {
            FailureClassifier::rethrowMasked($failure);
        }
    }

    /**
     * Plan the chunk of lines as a dry run, imported at the time given, and
     * count it: built encrypting nothing, classified against the stored rows
     * outside any transaction, and nothing written.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine>  $lines
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @param  \DateTimeInterface  $importedAt
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $retention
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    public function plan(#[\SensitiveParameter] array $lines, ImportTally $tally, \DateTimeInterface $importedAt, ?RetentionDecisions $retention = null): void
    {
        [$built] = $this->built(Str::uuid7($importedAt)->toString(), $lines, $tally, $importedAt, $retention, true);

        if ($built === []) {
            return;
        }

        try {
            $tally->countPlan($this->classifier->classify($this->connection(), $built));
        } catch (QueryException $failure) { // @phpstan-ignore catch.neverThrown
            FailureClassifier::rethrowMasked($failure);
        }
    }

    /**
     * Make the chunk's attempts until one commits, and return its plan: after a
     * unique violation the chunk is classified again once, after a second only
     * its counts are written, its new lines conflicts; after losing to a
     * concurrent chunk it waits and is tried again, up to the most attempts.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $batchId
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine>  $lines
     * @param  array<int, array<string, int|string|null>>  $rows
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportPlan
     *
     * @throws \Illuminate\Database\QueryException
     * @throws \Throwable
     */
    private function attempts(Connection $connection, string $batchId, #[\SensitiveParameter] array $lines, #[\SensitiveParameter] array $rows, ImportTally $tally): ImportPlan
    {
        $planned    = null;
        $violations = 0;
        $attempt    = 0;

        while ($violations < self::ATTEMPTS) {
            $attempt++;

            try {
                return $this->attempt($connection, $batchId, $lines, $rows, $tally, $planned);
            } catch (UniqueConstraintViolationException) {
                // The chunk rolled back whole: classified again once, and after
                // that its new lines are conflicts
                $violations++;
            } catch (QueryException $failure) {
                $this->waitOrRethrow($failure, $attempt);
            }
        }

        assert($planned instanceof ImportPlan);

        return $this->conflicted($connection, $batchId, $planned->withNewLinesAsConflicts(), $tally);
    }

    /**
     * Wait before the next attempt when the failed one lost to a concurrent
     * chunk, a deadlock, a serialisation failure or a lock timeout, and more
     * attempts remain; rethrow anything else, a lost connection included.
     *
     * @param  \Illuminate\Database\QueryException  $failure
     * @param  int  $attempt
     * @return void
     *
     * @throws \Illuminate\Database\QueryException
     * @throws \Random\RandomException
     */
    private function waitOrRethrow(#[\SensitiveParameter] QueryException $failure, int $attempt): void
    {
        $lost = !$this->failures->isLostConnection($failure)
            && ($this->failures->isConcurrencyError($failure) || $this->failures->isLockTimeout($failure));

        if (!$lost || $attempt >= self::MAX_ATTEMPTS) {
            throw $failure;
        }

        Sleep::for(random_int(0, min(self::JITTER_MAX_MS, self::JITTER_BASE_MS * 2 ** ($attempt - 1))))->milliseconds();
    }

    /**
     * Make one attempt at the chunk, in one transaction of one attempt: the
     * batch's time written first, the lines classified, the new ones inserted
     * and the counts written, and return the plan once it has committed. The
     * plan is kept as made, whether or not the attempt commits.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $batchId
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine>  $lines
     * @param  array<int, array<string, int|string|null>>  $rows
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\ImportPlan  $planned
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportPlan
     *
     * @throws \Illuminate\Database\UniqueConstraintViolationException
     * @throws \Throwable
     */
    private function attempt(
        Connection $connection,
        string $batchId,
        #[\SensitiveParameter]
        array $lines,
        #[\SensitiveParameter]
        array $rows,
        ImportTally $tally,
        ?ImportPlan &$planned,
    ): ImportPlan {
        return $connection->transaction(function (Connection $connection) use ($batchId, $lines, $rows, $tally, &$planned): ImportPlan {
            $this->batches->claim($connection, $batchId);

            $plan    = $this->classifier->classify($connection, $lines);
            $planned = $plan;

            self::insert($connection, array_map(static fn (#[\SensitiveParameter] ImportLine $line): array => $rows[$line->number], $plan->lines));

            $this->batches->progress($connection, $batchId, $tally->with($plan));

            return $plan;
        }, 1);
    }

    /**
     * Write only the counts of the plan of a chunk whose inserts were refused
     * twice, in one transaction, and return it once it has committed.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $batchId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportPlan  $plan
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportPlan
     *
     * @throws \Throwable
     */
    private function conflicted(Connection $connection, string $batchId, ImportPlan $plan, ImportTally $tally): ImportPlan
    {
        return $connection->transaction(function (Connection $connection) use ($batchId, $plan, $tally): ImportPlan {
            $this->batches->claim($connection, $batchId);

            $this->batches->progress($connection, $batchId, $tally->with($plan));

            return $plan;
        }, 1);
    }

    /**
     * Build each line of the batch, rejecting those that do not, and count
     * those whose record is past its retention on arrival, when the run's
     * decisions are given: the lines that built, in file order, and their
     * records, by line number.
     *
     * @param  string  $batchId
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine>  $lines
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @param  \DateTimeInterface  $importedAt
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $retention
     * @param  bool  $dryRun
     * @return array{0: list<\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine>, 1: array<int, \SineMacula\Laravel\AuditLog\Records\AuditRecord>}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    private function built(
        string $batchId,
        #[\SensitiveParameter]
        array $lines,
        ImportTally $tally,
        \DateTimeInterface $importedAt,
        ?RetentionDecisions $retention,
        bool $dryRun = false,
    ): array {
        $built   = [];
        $records = [];

        foreach ($lines as $line) {
            $record = $this->recordOf($line, $batchId, $importedAt, $dryRun);

            if ($record instanceof ImportRejection) {
                $tally->countRejected($record);

                continue;
            }

            if ($retention !== null && $this->isPastRetention($retention, $record, $line->tenant, $tally)) {
                $tally->countPastRetention();
            }

            $built[]                = $line;
            $records[$line->number] = $record;
        }

        return [$built, $records];
    }

    /**
     * Whether the record was already past its retention when it arrived, as
     * best the run's decisions can say: once they fail to answer, the count is
     * given up for the import, the failure reported once by its class, and no
     * record is past retention.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $retention
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @return bool
     */
    private function isPastRetention(RetentionDecisions $retention, #[\SensitiveParameter] AuditRecord $record, ?Reference $tenant, ImportTally $tally): bool
    {
        if (!$tally->countsPastRetention()) {
            return false;
        }

        try {
            return $retention->for($record->category, $tenant)->admits($record->occurredAt);
        } catch (\Throwable $failure) {
            $tally->givePastRetentionUp();

            $this->reporter->report(new \RuntimeException(sprintf(self::PAST_RETENTION_GIVEN_UP, $failure::class)));

            return false;
        }
    }

    /**
     * The line's record, of the batch and with its digest under the ring's
     * signing key, or why it is rejected: a source the record refuses is
     * `INVALID_FIELD`.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine  $line
     * @param  string  $batchId
     * @param  \DateTimeInterface  $importedAt
     * @param  bool  $dryRun
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection|\SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    private function recordOf(#[\SensitiveParameter] ImportLine $line, string $batchId, \DateTimeInterface $importedAt, bool $dryRun): AuditRecord|ImportRejection
    {
        $digest = $this->classifier->digestOf($line);

        try {
            $source = new ImportedSource($line->sourceId, $line->sourceRegion, $line->sourceRecordId, $batchId, $digest);
        } catch (\InvalidArgumentException) {
            return ImportRejection::INVALID_FIELD;
        }

        return $this->builder->build($line, $source, $importedAt, $dryRun);
    }

    /**
     * Refuse a chunk inside a transaction on the storage connection: it would
     * become a savepoint of the host's, and a subtransaction on PostgreSQL.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     *
     * @throws \LogicException
     */
    private static function refuseInsideATransaction(Connection $connection): void
    {
        if ($connection->transactionLevel() === 0) {
            return;
        }

        throw new \LogicException('An import chunk runs in a transaction of its own on the storage connection, and refuses to run inside one.');
    }

    /**
     * Insert the rows, as many to a statement as the engine allows placeholders
     * for.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  list<array<string, int|string|null>>  $rows
     * @return void
     */
    private static function insert(Connection $connection, #[\SensitiveParameter] array $rows): void
    {
        $size  = $connection->getDriverName() === 'sqlite' ? self::SQLITE_ROWS_PER_INSERT : self::ROWS_PER_INSERT;
        $table = EntrySettings::table();

        foreach (array_chunk($rows, $size) as $group) {
            $connection->table($table)->insert($group);
        }
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function connection(): Connection
    {
        return $this->database->connection(StorageConnection::name());
    }
}
