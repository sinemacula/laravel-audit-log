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
 * The import batches table, on the storage connection's writer so a chunk's
 * counts commit with its entries.
 *
 * A batch moves once from `running` to a final status and is never updated
 * again or deleted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ImportBatches
{
    /** @var list<string> The columns an import gives a new batch, in table order. */
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

        /** Resolves the storage connection on every call. */
        private DatabaseManager $database,

        /** Stamps a batch's start, writes and finish. */
        private Clock $clock,
    ) {}

    /**
     * Insert the batch `running` with zero counts, given exactly `GIVEN`.
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
     * Touch the running batch first in a chunk's transaction, so on SQLite the
     * chunk takes the write lock before it reads.
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
     * Write the running batch's counts in the chunk's transaction; the counts
     * always grow, so MySQL counts the row as updated.
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
     * Move the running batch to its final status; a batch no longer running is
     * refused.
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
     * Move the batch to its final status if it is still running, and say
     * whether it was.
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
     * Mark the running batch `interrupted`; any other batch is refused.
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
     * The batch's row, or `null` when there is none.
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
     * Every running batch not written within `STALE_SECONDS`, oldest first.
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
     * Refuse an update that changed no row: a close as the caller's error,
     * anything else as the import's.
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
     * The clock's instant in storage form.
     *
     * @return string
     */
    private function now(): string
    {
        return StoredTime::toStorage(StoredTime::format($this->clock->now()));
    }
}
