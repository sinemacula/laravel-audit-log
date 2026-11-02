<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\UniqueConstraintViolationException;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * Stores finalised records as rows of the entries table, on the storage
 * connection's writer, with one plain insert each.
 *
 * Outside a transaction the insert runs alone, and the store opens no
 * transaction of its own. Inside one, Laravel-managed on the storage
 * connection, the insert runs in a savepoint (a nested transaction of one
 * attempt), which Laravel rolls back when the insert fails and whose success
 * issues no statement. The guarantee is this narrow: one failed audit statement
 * does not abort a healthy host transaction on the storage connection.
 * Deadlocks and other concurrency errors (Laravel's `DeadlockException`), lost
 * connections and a host transaction that is already aborted propagate, and the
 * host must handle them.
 *
 * The insert never ignores a conflict. When it violates a unique index, the
 * violation is caught outside the savepoint, once it is rolled back, and the
 * row under the record's id is read from the writer; on MySQL inside a
 * transaction, with a shared locking read, a current read past the snapshot
 * that needs only `SELECT`. With no such row (the violation was on another
 * index, or the row is beyond the host's snapshot) the original exception
 * propagates; a row that fails verification, or whose captured content differs,
 * is a `RecordConflictException`; a row that verifies with the same captured
 * content is the record, stored already, and is kept as it is, its time and key
 * included. A row that cannot be verified at all (its key is unknown, its
 * version unsupported, or it is malformed) propagates the signer's or the
 * codec's exception. Nothing else is caught.
 *
 * A record costs one statement, and inside a transaction Laravel's savepoint
 * too; a duplicate costs one more, the read, and inside a transaction the
 * savepoint's rollback.
 *
 * Laravel never releases a savepoint that succeeds, and releasing it would not
 * help: on PostgreSQL every savepoint is a subtransaction, and one that wrote
 * keeps its subtransaction id until the host transaction ends. Each record
 * stored inside a host transaction therefore holds one subtransaction until the
 * host commits or rolls back, and past 64 in one transaction PostgreSQL's
 * snapshots overflow, slowing every session of the cluster, hot standbys
 * included, until it ends. Keep the records stored in one host transaction well
 * under 64, or give the audit log a storage connection of its own, on which the
 * host's transactions are not open, so no savepoint is used.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DatabaseAuditStore implements AuditStore
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \SineMacula\Laravel\AuditLog\Stores\RowCodec  $codec
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RecordSigner  $signer
     */
    public function __construct(

        /** The connections the storage connection is resolved from on every call. */
        private ConnectionResolverInterface $connections,

        /** The codec that turns a record into its row and a stored row back into its envelope. */
        private RowCodec $codec,

        /** The signer that verifies an existing row and digests captured content. */
        private RecordSigner $signer,
    ) {}

    /**
     * Store the finalised record as one row of the entries table, or succeed
     * without writing when a row under its id verifies and holds the same
     * captured content.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Illuminate\Database\UniqueConstraintViolationException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \SineMacula\Laravel\AuditLog\Stores\RecordConflictException
     * @throws \Throwable
     */
    #[\Override]
    public function store(FinalisedRecord $record): void
    {
        $connection = $this->connection();
        $table      = EntrySettings::table();
        $row        = $this->codec->encode($record);

        try {
            $this->insert($connection, $table, $row);
        } catch (UniqueConstraintViolationException $exception) {
            $this->resolveDuplicate($connection, $table, $record, $exception);
        }
    }

    /**
     * The storage connection, which must be a database connection, so it has
     * transaction levels and savepoints.
     *
     * @return \Illuminate\Database\Connection
     *
     * @throws \LogicException
     */
    private function connection(): Connection
    {
        $connection = $this->connections->connection(StorageConnection::name());

        if (!$connection instanceof Connection) {
            throw new \LogicException(sprintf('The storage connection [%s] is not a database connection that supports transactions.', StorageConnection::resolvedName()));
        }

        return $connection;
    }

    /**
     * Insert the row with one plain insert: alone outside a transaction, and in
     * a savepoint of one attempt inside one, so a failed insert rolls back to
     * it and leaves the host transaction as it was.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  array<string, int|string|null>  $row
     * @return void
     *
     * @throws \Throwable
     */
    private function insert(Connection $connection, string $table, array $row): void
    {
        if ($connection->transactionLevel() === 0) {
            $connection->table($table)->insert($row);

            return;
        }

        $connection->transaction(static fn (Connection $nested): bool => $nested->table($table)->insert($row));
    }

    /**
     * Resolve a unique violation of the record's insert: succeed only when the
     * writer holds a row under the record's id that verifies and has the same
     * captured content; otherwise throw, the original exception when no such
     * row is visible.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \Illuminate\Database\UniqueConstraintViolationException  $exception
     * @return void
     *
     * @throws \UnexpectedValueException
     * @throws \Illuminate\Database\UniqueConstraintViolationException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \SineMacula\Laravel\AuditLog\Stores\RecordConflictException
     */
    private function resolveDuplicate(Connection $connection, string $table, FinalisedRecord $record, UniqueConstraintViolationException $exception): void
    {
        $query = $connection->table($table)->useWritePdo()->where('id', $record->record->id);

        if ($connection->getDriverName() === 'mysql' && $connection->transactionLevel() > 0) {
            $query->sharedLock();
        }

        $existing = $query->first();

        if ($existing === null) {
            throw $exception;
        }

        $conflict = $this->conflictWith($record, $this->codec->decode((array) $existing));

        if ($conflict !== null) {
            throw $conflict;
        }
    }

    /**
     * The conflict between the record and the decoded row stored under its id:
     * none when the row verifies and has the record's captured content, and
     * otherwise the conflict naming why. A row that cannot be verified at all
     * is refused by the signer.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  array<string, mixed>  $stored
     * @return ?\SineMacula\Laravel\AuditLog\Stores\RecordConflictException
     *
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    private function conflictWith(FinalisedRecord $record, array $stored): ?RecordConflictException
    {
        $id = $record->record->id;

        if (!$this->signer->verifies($stored)) {
            return RecordConflictException::unverified($id);
        }

        if (!hash_equals($this->signer->capturedDigest($stored), $this->signer->capturedDigest($record->toArray()))) {
            return RecordConflictException::differentContent($id);
        }

        return null;
    }
}
