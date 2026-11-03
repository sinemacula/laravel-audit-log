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
 * The deliveries table, on the storage connection's writer beside the entries
 * it describes: one receipt per record and destination, saying how many
 * attempts reached for the destination, whether it has the record, and the
 * class of the last error it raised.
 *
 * An attempt is counted before its call, so a call that never returns still
 * counts: the first makes the receipt, and a first attempt that finds the
 * receipt made already, by a racing owner, counts on it instead. A delivered
 * receipt is never changed again, by any method, so its time stays the time the
 * destination first had the record, and a reset after a failure reaches only
 * the destinations that do not have it. A receipt names an error by its class,
 * never its message, and holds nothing of the record. Receipts are kept once
 * their record is delivered.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Receipts
{
    /** @var int Entries reset by one statement, so a long list never exceeds what an engine binds. */
    private const int RESET_CHUNK = 500;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     */
    public function __construct(

        /** The connections the storage connection is resolved from on every call. */
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
     * The receipts of the entry, keyed by destination; none when no attempt has
     * been made.
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

        // An integer column reads back as an integer and a string or time
        // column as a string, on every engine
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
     * Count an attempt to reach the destination with the entry, before the call
     * is made: with no receipt yet, an insert of one with one attempt, first
     * made now; otherwise, and when a racing owner made the receipt first, one
     * more attempt on it. A delivered receipt is left as it is.
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
     * Mark the destination as having the entry, now, and clear its last error,
     * unless it was marked so already.
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
     * Name the class of the error the destination raised for the entry, unless
     * the destination has the entry already.
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
     * Reset the receipts of the entries that are not delivered, so a replay
     * starts their attempts again with no error named; a delivered receipt is
     * kept as it is. Returns how many receipts were reset.
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
     * Insert the receipt of a first attempt, alone outside a transaction and in
     * a savepoint inside one, so a receipt a racing owner made first leaves the
     * transaction as it was. Returns whether this insert made it.
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
            // A racing owner made the receipt first, so the attempt is counted
            // on it instead
            return false;
        }
    }

    /**
     * A query of the destination's receipt for the entry while it is not
     * delivered.
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
