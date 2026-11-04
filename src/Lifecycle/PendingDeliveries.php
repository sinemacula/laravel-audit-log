<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Which entries a prune must keep because their delivery is not finished: an
 * outbox row, pending, claimed or failed, or a destination's receipt not yet
 * delivered. Pruning never removes the memory of a record a destination may
 * still need, so a failed delivery keeps its entry until it is replayed and
 * delivered.
 *
 * Both are read after the chunk's lifecycle lock, never before. The receipts
 * live beside the entries, so they are read inside the chunk's transaction on
 * the maintenance connection. The outbox is read there too when it lives on the
 * storage database; when it lives on another connection it is read through that
 * connection's writer, in a read of its own, which cannot join the transaction.
 * That read is sound: an outbox row for an id already stored and sealed is only
 * ever written again by a restore, and the drain checks every row it claims
 * against the pruned ids. Each statement names at most 500 ids.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingDeliveries
{
    /** @var int The most ids one statement names. */
    public const int CHUNK = 500;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** The connections the outbox connection is resolved from on every call. */
        private DatabaseManager $database,
    ) {}

    /**
     * The ids among those given that have an outbox row, each once, in the
     * order given: read through the maintenance connection, inside its
     * transaction, when the outbox lives on the storage database, and through
     * the outbox connection's writer otherwise.
     *
     * @param  \Illuminate\Database\Connection  $maintenance
     * @param  list<string>  $ids
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function inOutbox(Connection $maintenance, array $ids): array
    {
        $outbox = DeliveryTables::resolvedOutboxConnection() === StorageConnection::resolvedName()
            ? $maintenance
            : $this->database->connection(DeliveryTables::outboxConnection());

        $table = DeliveryTables::outboxTable();

        return self::among($ids, static fn (array $chunk): array => $outbox->table($table)->useWritePdo()->whereIn('id', $chunk)->pluck('id')->all());
    }

    /**
     * The ids among those given that have a receipt not yet delivered, each
     * once, in the order given, read through the connection given, inside the
     * chunk's transaction.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  list<string>  $ids
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function undelivered(Connection $connection, array $ids): array
    {
        $table    = DeliveryTables::deliveriesTable();
        $receipts = static fn (array $chunk): array => $connection->table($table)
            ->useWritePdo()
            ->whereIn('entry_id', $chunk)
            ->whereNull('delivered_at')
            ->pluck('entry_id')
            ->all();

        return self::among($ids, $receipts);
    }

    /**
     * The ids among those given that the read of each chunk of them returns,
     * each once, in the order given.
     *
     * @param  list<string>  $ids
     * @param  \Closure(list<string>): array<array-key, scalar|null>  $read
     * @return list<string>
     */
    private static function among(array $ids, #[\SensitiveParameter] \Closure $read): array
    {
        $found = [];

        foreach (array_chunk(array_values(array_unique($ids)), self::CHUNK) as $chunk) {
            $found += array_fill_keys(array_filter($read($chunk), is_string(...)), true);
        }

        return array_values(array_unique(array_filter($ids, static fn (string $id): bool => isset($found[$id]))));
    }
}
