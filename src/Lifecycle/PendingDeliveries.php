<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Which entries a prune must keep because their delivery is not finished, read
 * after the chunk's lifecycle lock.
 *
 * An outbox on another connection is read through its writer outside the
 * transaction; a stored, sealed id is only queued again by a restore.
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
     * order given.
     *
     * @param  \Illuminate\Database\Connection  $maintenance
     * @param  list<string>  $ids
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function inOutbox(Connection $maintenance, array $ids): array
    {
        $outbox = $this->outboxOn($maintenance);
        $table  = DeliveryTables::outboxTable();

        return self::among($ids, static fn (array $chunk): array => $outbox->table($table)->useWritePdo()->whereIn('id', $chunk)->pluck('id')->all());
    }

    /**
     * How many outbox rows of any owner were created before the instant; the
     * payloads are sealed, so owners cannot be told apart.
     *
     * @param  \Illuminate\Database\Connection  $maintenance
     * @param  string  $instant
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function olderThan(Connection $maintenance, string $instant): int
    {
        return $this->outboxOn($maintenance)
            ->table(DeliveryTables::outboxTable())
            ->useWritePdo()
            ->where('created_at', '<', StoredTime::toStorage($instant))
            ->count();
    }

    /**
     * The ids among those given that have a receipt not yet delivered, each
     * once, in the order given.
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
     * The maintenance connection when the outbox lives on the storage database,
     * the outbox connection otherwise.
     *
     * @param  \Illuminate\Database\Connection  $maintenance
     * @return \Illuminate\Database\Connection
     *
     * @throws \InvalidArgumentException
     */
    private function outboxOn(Connection $maintenance): Connection
    {
        return DeliveryTables::resolvedOutboxConnection() === StorageConnection::resolvedName()
            ? $maintenance
            : $this->database->connection(DeliveryTables::outboxConnection());
    }

    /**
     * The ids the read of each chunk returns, each once, in the order given.
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
