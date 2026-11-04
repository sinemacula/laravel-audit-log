<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * The rows of the import batches table, each the record of one import, written
 * and read on the storage connection's writer, which the entries are written
 * through, so a chunk's counts commit with its entries.
 *
 * A batch is inserted `running`, with its counts at nothing, before its first
 * entry. Each chunk writes the time first, which on SQLite takes the write lock
 * before the chunk reads, and its counts last, inside the chunk's own
 * transaction, and the batch moves once from `running` to a final status, its
 * counts and its finishing time written with it; a batch that is no longer
 * running is never updated again, and an attempt to is refused; no row is ever
 * deleted. A `running` batch that has not been written for an hour is stale:
 * the import that ran it has most likely stopped, and `close()` marks it
 * `interrupted`. An import makes its batch final only once the journal holds
 * its finish, through `settles()`, which moves a batch still running and leaves
 * any other as it is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ImportBatches
{
    /** @var list<string> The columns a new batch is given by its import, in table order. */
    public const array GIVEN = [
        'id', 'source_id', 'source_region', 'input_format', 'importer_type', 'importer_id', 'reason', 'external_reference',
        'file_sha256', 'externally_verified', 'hold_id',
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     */
    public function __construct(

        /** The connections the storage connection is resolved from on every call. */
        private DatabaseManager $database,

        /** The time a batch is started, written and finished at. */
        private Clock $clock,
    ) {}

    /**
     * Insert the batch `running`, with its counts at nothing, started and last
     * written now: the columns its import gives, and no others.
     *
     * @param  array<string, bool|string|null>  $batch
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function start(array $batch): void
    {
        $missing = array_diff(self::GIVEN, array_keys($batch));
        $extra   = array_diff(array_keys($batch), self::GIVEN);

        if ($missing !== [] || $extra !== []) {
            throw new \InvalidArgumentException(sprintf('A new import batch is given exactly the columns `%s`.', implode('`, `', self::GIVEN)));
        }

        $now = $this->now();

        $this->table($this->connection())->insert([
            ...array_merge(array_flip(self::GIVEN), $batch),
            'status'       => ImportStatus::RUNNING->value,
            'lines_read'   => 0,
            'imported'     => 0,
            'duplicates'   => 0,
            'conflicts'    => 0,
            'rejected'     => 0,
            'conflict_ids' => null,
            'started_at'   => $now,
            'updated_at'   => $now,
            'finished_at'  => null,
        ]);
    }

    /**
     * Write the time to the running batch as the first statement of a chunk's
     * transaction, which the connection holds, so the chunk holds the storage
     * database's write lock on SQLite before it reads, and a concurrent chunk
     * waits for it rather than failing on a stale read.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $id
     * @return void
     *
     * @throws \LogicException
     */
    public function claim(Connection $connection, string $id): void
    {
        self::checkInTransaction($connection);

        $this->running($connection, $id)->update(['updated_at' => $this->now()]);
    }

    /**
     * Write the running batch's counts and the time, inside the transaction the
     * connection holds, a chunk's own; a batch closed while its import ran is
     * refused, which rolls the chunk back.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $id
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    public function progress(Connection $connection, string $id, ImportTally $tally): void
    {
        self::checkInTransaction($connection);

        self::checkUpdated($this->running($connection, $id)->update([...$tally->toBatch(), 'updated_at' => $this->now()]), false);
    }

    /**
     * Move the running batch to its final status, with its counts, written and
     * finished now; a batch no longer running is refused.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus  $status
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    public function finish(string $id, ImportStatus $status, ImportTally $tally): void
    {
        $now    = $this->now();
        $values = [...$tally->toBatch(), 'status' => self::finalOf($status)->value, 'updated_at' => $now, 'finished_at' => $now];

        self::checkUpdated($this->running($this->connection(), $id)->update($values), false);
    }

    /**
     * Move the batch to the final status given, with the counts given or those
     * it holds, written and finished now, while it is still running, and say
     * whether it was; a batch no longer running is left as it is.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus  $status
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function settles(string $id, ImportStatus $status, ?ImportTally $tally = null): bool
    {
        $now    = $this->now();
        $values = [...($tally?->toBatch() ?? []), 'status' => self::finalOf($status)->value, 'updated_at' => $now, 'finished_at' => $now];

        return $this->running($this->connection(), $id)->update($values) === 1;
    }

    /**
     * Mark the running batch `interrupted`, written and finished now, its
     * counts as they stand; any other batch is refused.
     *
     * @param  string  $id
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function close(string $id): void
    {
        $now = $this->now();

        self::checkUpdated($this->running($this->connection(), $id)->update(['status' => ImportStatus::INTERRUPTED->value, 'updated_at' => $now, 'finished_at' => $now]), true);
    }

    /**
     * The batch's row as the engine returns it, or `null` when there is none.
     *
     * @param  string  $id
     * @return ?array<string, scalar|null>
     */
    public function find(string $id): ?array
    {
        $row = $this->table($this->connection())->useWritePdo()->where('id', $id)->first();

        if ($row === null) {
            return null;
        }

        /** @var array<string, scalar|null> */
        return (array) $row;
    }

    /**
     * Every running batch not written for longer than a running batch stays
     * fresh, by when each was last written.
     *
     * @return list<array<string, scalar|null>>
     */
    public function stale(): array
    {
        $before = StoredTime::toStorage(StoredTime::format($this->clock->now()->subSeconds(ImportSettings::STALE_SECONDS)));

        $rows = $this->table($this->connection())
            ->useWritePdo()
            ->where('status', ImportStatus::RUNNING->value)
            ->where('updated_at', '<', $before)
            ->orderBy('updated_at')
            ->orderBy('id')
            ->get()
            ->all();

        /** @var list<array<string, scalar|null>> */
        return array_values(array_map(static fn (#[\SensitiveParameter] object $row): array => (array) $row, $rows));
    }

    /**
     * A query of the batch while it is running.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $id
     * @return \Illuminate\Database\Query\Builder
     */
    private function running(Connection $connection, string $id): Builder
    {
        return $this->table($connection)->where('id', $id)->where('status', ImportStatus::RUNNING->value);
    }

    /**
     * A query of the batches table on the connection.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return \Illuminate\Database\Query\Builder
     */
    private function table(Connection $connection): Builder
    {
        return $connection->table(LifecycleTables::importBatchesTable());
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

    /**
     * Refuse a chunk's write outside the transaction of the chunk.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     *
     * @throws \LogicException
     */
    private static function checkInTransaction(Connection $connection): void
    {
        if ($connection->transactionLevel() > 0) {
            return;
        }

        throw new \LogicException('An import batch is written by a chunk only inside the chunk\'s own transaction.');
    }

    /**
     * The status, refused unless it is final.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus  $status
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus
     *
     * @throws \InvalidArgumentException
     */
    private static function finalOf(ImportStatus $status): ImportStatus
    {
        return $status->isFinal() ? $status : throw new \InvalidArgumentException('An import batch finishes in a final status.');
    }

    /**
     * Refuse an update of a running batch that changed no row: the batch is no
     * longer running, or never existed. A close is refused as a caller's error,
     * and anything else as the import's.
     *
     * @param  int  $updated
     * @param  bool  $closing
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function checkUpdated(int $updated, bool $closing): void
    {
        if ($updated === 1) {
            return;
        }

        if ($closing) {
            throw new \InvalidArgumentException('Only a running import batch is closed.');
        }

        throw new \LogicException('The import batch is no longer running, and is not written to.');
    }

    /**
     * The clock's instant, as the database stores it.
     *
     * @return string
     */
    private function now(): string
    {
        return StoredTime::toStorage(StoredTime::format($this->clock->now()));
    }
}
