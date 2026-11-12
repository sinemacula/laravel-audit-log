<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * The deliveries table on the storage connection's writer: one receipt per
 * record and destination, naming an error by class, never message.
 *
 * An attempt is counted before its call, so a call that never returns still
 * counts, and a delivered receipt never changes again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Receipts
{
    /** @var int Entries reset per statement, below what an engine binds. */
    private const int RESET_CHUNK = 500;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     */
    public function __construct(

        /** Resolves the storage connection on every call. */
        private ConnectionResolverInterface $connections,

        /** The clock the times of attempts and deliveries are read from. */
        private Clock $clock,
    ) {}

    /**
     * The storage connection, which must be a database connection, so it has
     * transaction levels and savepoints.
     *
     * @return \Illuminate\Database\Connection
     *
     * @throws \LogicException
     */
    public function connection(): Connection
    {
        $connection = $this->connections->connection(StorageConnection::name());

        if (!$connection instanceof Connection) {
            throw new \LogicException(sprintf('The storage connection [%s] is not a database connection that supports transactions.', StorageConnection::resolvedName()));
        }

        return $connection;
    }

    /**
     * The entry's receipts by destination; none before the first attempt.
     *
     * @param  string  $entryId
     * @return array<string, \SineMacula\Laravel\AuditLog\Delivery\Receipt>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function forEntry(string $entryId): array
    {
        $receipts = [];

        // Integer columns read back as integers and string or time columns as
        // strings on every engine
        /** @var list<object{destination: string, attempts: int, delivered_at: ?string, last_error_class: ?string}&\stdClass> $rows */
        $rows = $this->table()
            ->where('entry_id', $entryId)
            ->orderBy('destination')
            ->get(['destination', 'attempts', 'delivered_at', 'last_error_class'])
            ->all();

        foreach ($rows as $row) {
            $receipts[$row->destination] = new Receipt($row->destination, $row->attempts, $row->delivered_at !== null, $row->last_error_class);
        }

        return $receipts;
    }

    /**
     * Count an attempt before the call: insert the receipt on the first,
     * otherwise, or when a racing owner made it first, add one; a delivered
     * receipt is left alone.
     *
     * @param  string  $entryId
     * @param  string  $destination
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\Receipt  $existing
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function attempting(string $entryId, string $destination, ?Receipt $existing): void
    {
        if ($existing === null && $this->insertsFirstAttempt($entryId, $destination)) {
            return;
        }

        $this->pending($entryId, $destination)->increment('attempts');
    }

    /**
     * Mark the destination as having the entry now and clear its last error,
     * unless already marked.
     *
     * @param  string  $entryId
     * @param  string  $destination
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function delivered(string $entryId, string $destination): void
    {
        $this->pending($entryId, $destination)->update([
            'delivered_at'     => StoredTime::toStorage(StoredTime::format($this->clock->now())),
            'last_error_class' => null,
        ]);
    }

    /**
     * Name the class of the destination's error, unless it already has the
     * entry.
     *
     * @param  string  $entryId
     * @param  string  $destination
     * @param  string  $errorClass
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function failed(string $entryId, string $destination, string $errorClass): void
    {
        $this->pending($entryId, $destination)->update([
            'last_error_class' => mb_strcut($errorClass, 0, WriteDiagnostics::CLASS_MAX_BYTES, 'UTF-8'),
        ]);
    }

    /**
     * Reset the undelivered receipts of the entries for a replay, leaving
     * delivered ones; returns how many were reset.
     *
     * @param  list<string>  $entryIds
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function resetFailed(array $entryIds): int
    {
        $reset = 0;

        foreach (array_chunk($entryIds, self::RESET_CHUNK) as $chunk) {
            $reset += $this->table()->whereIn('entry_id', $chunk)->whereNull('delivered_at')->update([
                'attempts'         => 0,
                'last_error_class' => null,
            ]);
        }

        return $reset;
    }

    /**
     * Insert a first attempt's receipt, in a savepoint when a transaction is
     * open, so a racing owner's receipt leaves the transaction as it was;
     * returns whether this insert made it.
     *
     * @param  string  $entryId
     * @param  string  $destination
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function insertsFirstAttempt(string $entryId, string $destination): bool
    {
        $connection = $this->connection();
        $table      = DeliveryTables::deliveriesTable();

        $receipt = [
            'entry_id'           => $entryId,
            'destination'        => $destination,
            'attempts'           => 1,
            'first_attempted_at' => StoredTime::toStorage(StoredTime::format($this->clock->now())),
        ];

        try {
            if ($connection->transactionLevel() === 0) {
                return $connection->table($table)->insert($receipt);
            }

            return $connection->transaction(static fn (Connection $nested): bool => $nested->table($table)->insert($receipt));
        } catch (UniqueConstraintViolationException) {
            // A racing owner made the receipt first; the attempt counts on it
            return false;
        }
    }

    /**
     * A query of the destination's undelivered receipt for the entry.
     *
     * @param  string  $entryId
     * @param  string  $destination
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function pending(string $entryId, string $destination): Builder
    {
        return $this->table()
            ->where('entry_id', $entryId)
            ->where('destination', $destination)
            ->whereNull('delivered_at');
    }

    /**
     * A query of the deliveries table on the writer.
     *
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function table(): Builder
    {
        return $this->connection()->table(DeliveryTables::deliveriesTable())->useWritePdo();
    }
}
