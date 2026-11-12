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
use SineMacula\Laravel\AuditLog\Keys\KeyUses;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\EnvelopeKeys;
use SineMacula\Laravel\AuditLog\Records\ImportedSource;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;

/**
 * Writes one chunk of an import in its own transaction on the storage
 * connection's writer, so its counts never drift from its rows.
 *
 * A chunk that loses to a concurrent import is retried with jitter, never after
 * a lost connection, whose commit may have happened.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ImportWriter
{
    /** @var int Rows per insert on SQLite: 888 placeholders, under its oldest 999. */
    public const int SQLITE_ROWS_PER_INSERT = 24;

    /** @var int Rows per insert on MySQL and PostgreSQL, under 65,535 placeholders. */
    public const int ROWS_PER_INSERT = 1000;

    /** @var int Attempts at a chunk's rows: the first, and one after a violation. */
    public const int ATTEMPTS = 2;

    /** @var int The most attempts a chunk makes in all. */
    public const int MAX_ATTEMPTS = 4;

    /** @var int The first retry's wait bound, in milliseconds; it then doubles. */
    public const int JITTER_BASE_MS = 20;

    /** @var int The longest wait between two attempts, in milliseconds. */
    public const int JITTER_MAX_MS = 1000;

    /** @var string The report of a past-retention count given up, by class. */
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

        /** Resolves the storage connection on every chunk. */
        private DatabaseManager $database,

        /** Classifies the built lines as new, duplicates or conflicts. */
        private ImportClassifier $classifier,

        /** Builds each line's record. */
        private ImportRecordBuilder $builder,

        /** Signs each record under the ring's signing key. */
        private RecordFinaliser $finaliser,

        /** Turns each record into its row. */
        private RowCodec $codec,

        /** Writes the batch's time and counts in each chunk. */
        private ImportBatches $batches,

        /** Tells a chunk lost to a concurrent one from any other failure. */
        private FailureClassifier $failures,

        /** Reports a failed past-retention count. */
        private ExceptionHandler $reporter,
    ) {}

    /**
     * Write the chunk of lines in one transaction and count it.
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
        $uses = array_map(static fn (#[\SensitiveParameter] AuditRecord $record): array => self::keyUsesOf($record), $records);

        try {
            $tally->countPlan($this->attempts($connection, $batchId, $built, $rows, $uses, $tally));
        } catch (QueryException $failure) {
            FailureClassifier::rethrowMasked($failure);
        }
    }

    /**
     * Plan the chunk as a dry run and count it, writing nothing.
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
     * Attempt the chunk until one commits; after a second unique violation its
     * new lines become conflicts.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $batchId
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine>  $lines
     * @param  array<int, array<string, int|string|null>>  $rows
     * @param  array<int, list<array{key_id: string, entry_id: string}>>  $uses
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportPlan
     *
     * @throws \Illuminate\Database\QueryException
     * @throws \Throwable
     */
    private function attempts(
        Connection $connection,
        string $batchId,
        #[\SensitiveParameter]
        array $lines,
        #[\SensitiveParameter]
        array $rows,
        array $uses,
        ImportTally $tally,
    ): ImportPlan {
        $planned    = null;
        $violations = 0;
        $attempt    = 0;

        while ($violations < self::ATTEMPTS) {
            $attempt++;

            try {
                return $this->attempt($connection, $batchId, $lines, $rows, $uses, $tally, $planned);
            } catch (UniqueConstraintViolationException) {
                // The chunk rolled back whole and is classified again
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
     * chunk; rethrow anything else.
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
     * Make one attempt at the chunk, keeping `$planned` even when it rolls
     * back.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $batchId
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine>  $lines
     * @param  array<int, array<string, int|string|null>>  $rows
     * @param  array<int, list<array{key_id: string, entry_id: string}>>  $uses
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
        array $uses,
        ImportTally $tally,
        ?ImportPlan &$planned,
    ): ImportPlan {
        return $connection->transaction(function (Connection $connection) use ($batchId, $lines, $rows, $uses, $tally, &$planned): ImportPlan {
            $this->batches->claim($connection, $batchId);

            $plan    = $this->classifier->classify($connection, $lines);
            $planned = $plan;

            self::insert($connection, array_map(static fn (#[\SensitiveParameter] ImportLine $line): array => $rows[$line->number], $plan->lines));

            KeyUses::insert($connection, array_merge(...array_map(static fn (#[\SensitiveParameter] ImportLine $line): array => $uses[$line->number], $plan->lines)));

            $this->batches->progress($connection, $batchId, $tally->with($plan));

            return $plan;
        }, 1);
    }

    /**
     * Write only the counts of a chunk whose inserts were refused twice.
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
     * The lines that built, in file order, and their records by line number.
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
     * Whether the record was past retention on arrival; a failure gives the
     * count up and is reported by its class.
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
     * The line's record, or why it is rejected.
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
     * The key uses of the record's envelopes, one row per distinct key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return list<array{key_id: string, entry_id: string}>
     *
     * @throws \InvalidArgumentException
     */
    private static function keyUsesOf(#[\SensitiveParameter] AuditRecord $record): array
    {
        $keys = EnvelopeKeys::ofRecord($record);

        return $keys === [] ? [] : KeyUses::rowsFor($record->id, $keys);
    }

    /**
     * Refuse a chunk inside a transaction: it would become a savepoint of the
     * host's, and a subtransaction on PostgreSQL.
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
     * Insert the rows in groups the engine's placeholder limit allows.
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
