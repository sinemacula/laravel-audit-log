<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * Stores finalised records as rows of the entries table, on the storage
 * connection's writer, with one plain insert each, and a bulk record's
 * attachment as a row of the artifacts table, written with its entry.
 *
 * Outside a transaction a record's insert runs alone, and the store opens no
 * transaction of its own. Inside one, Laravel-managed on the storage
 * connection, the insert runs in a savepoint (a nested transaction of one
 * attempt), which Laravel rolls back when the insert fails and whose success
 * issues no statement. The guarantee is this narrow: one failed audit statement
 * does not abort a healthy host transaction on the storage connection.
 * Deadlocks and other concurrency errors (Laravel's `DeadlockException`), lost
 * connections and a host transaction that is already aborted propagate, and the
 * host must handle them.
 *
 * A bulk record is a bundle: its artifact and its entry are written together,
 * artifact first, in one transaction of one attempt, which is a real
 * transaction outside a host and a savepoint inside one, so the entry's failure
 * rolls the artifact back and neither is ever kept without the other. A bundle
 * costs two inserts and that one transaction or savepoint.
 *
 * An insert never ignores a conflict. When it violates a unique index, the
 * violation is caught outside the savepoint or the transaction, once it is
 * rolled back, and what is stored under the record's ids is read from the
 * writer; on MySQL inside a transaction, with a shared locking read, a current
 * read past the snapshot that needs only `SELECT`. With nothing stored under
 * them, a record retention has already pruned, which a seal holds as a member
 * though its entry is gone, is a `RecordConflictException` and is not stored
 * again; otherwise (the violation was on another index, or the rows are beyond
 * the host's snapshot) the original exception propagates. An entry that fails
 * verification, or whose captured content differs, is a
 * `RecordConflictException`; an entry that verifies with the same captured
 * content is the record, stored already, and is kept as it is, its time and key
 * included. A bundle's duplicate reads its entry and its artifact, and is the
 * bundle stored already only when the entry is the record's and the artifact
 * has its id, entry, kind, member count and digest, never compared by its
 * sealed members, which a retry carries unchanged; an entry without its
 * artifact, with another, or an artifact without its entry is a
 * `RecordConflictException` too. A row that cannot be verified at all (its key
 * is unknown, its version unsupported, or it is malformed) propagates the
 * signer's or the codec's exception. Nothing else is caught.
 *
 * A fresh insert of a pruned record's id violates no index, so it is not
 * refused here: the store would need a statement on every write to see it. The
 * paths that hand the store an id it did not mint now, the outbox drain and the
 * spill replay, check every id first; a record an application kept and stores
 * again directly is inserted, and verification reports its seal `resurrected`.
 *
 * A record costs one statement, and inside a transaction Laravel's savepoint
 * too; a duplicate costs one more, the read, and inside a transaction the
 * savepoint's rollback; a violation with nothing stored costs the read of the
 * tombstones too. A bundle's duplicate costs the two reads, and the rollback of
 * its transaction or savepoint.
 *
 * Laravel never releases a savepoint that succeeds, and releasing it would not
 * help: on PostgreSQL every savepoint is a subtransaction, and one that wrote
 * keeps its subtransaction id until the host transaction ends. Each record or
 * bundle stored inside a host transaction therefore holds one subtransaction
 * until the host commits or rolls back, and past 64 in one transaction
 * PostgreSQL's snapshots overflow, slowing every session of the cluster, hot
 * standbys included, until it ends. Keep the records stored in one host
 * transaction well under 64, or give the audit log a storage connection of its
 * own, on which the host's transactions are not open, so no savepoint is used.
 *
 * It is durable, since a return is a committed insert or a write inside the
 * host's transaction, it participates in a transaction on the storage
 * connection alone, and it keeps attachments. An application names it as one
 * destination of a `StackAuditStore`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DatabaseAuditStore implements AcceptsAttachments, DurableAuditStore
{
    /** @var list<string> The columns that tell an artifact: everything but its sealed members, which a retry carries unchanged, and its time. */
    private const array ARTIFACT_IDENTITY = ['id', 'entry_id', 'kind', 'member_count', 'digest'];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \SineMacula\Laravel\AuditLog\Stores\RowCodec  $codec
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RecordSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones  $tombstones
     */
    public function __construct(

        /** The connections the storage connection is resolved from on every call. */
        private ConnectionResolverInterface $connections,

        /** The codec that turns a record into its row and a stored row back into its envelope. */
        private RowCodec $codec,

        /** The signer that verifies an existing row and digests captured content. */
        private RecordSigner $signer,

        /** The tombstones that say whether retention has already pruned a record whose insert conflicted. */
        private PruneTombstones $tombstones,
    ) {}

    /**
     * Store the finalised record as one row of the entries table, and a bulk
     * record's attachment with it as one row of the artifacts table, or succeed
     * without writing when what is stored under its ids is the same record.
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
    public function store(#[\SensitiveParameter] FinalisedRecord $record): void
    {
        $connection = $this->connection();
        $table      = EntrySettings::table();
        $row        = $this->codec->encode($record);

        if ($record->record->attachment !== null) {
            $this->storeBundle($connection, $table, $record, $row);

            return;
        }

        try {
            $this->insert($connection, $table, $row);
        } catch (UniqueConstraintViolationException $exception) {
            $this->resolveDuplicate($connection, $table, $record, $exception);
        }
    }

    /**
     * Whether a return is a durable acknowledgement: always, since a return is
     * a committed insert, or one inside the host's transaction that commits
     * with it.
     *
     * @return bool
     */
    #[\Override]
    public function isDurable(): bool
    {
        return true;
    }

    /**
     * Whether a write commits and rolls back with a transaction on the
     * connection: only on the storage connection, compared by its resolved
     * name.
     *
     * @param  string  $connection
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function participatesIn(string $connection): bool
    {
        return $connection === StorageConnection::resolvedName();
    }

    /**
     * Whether the store keeps a record's attachment with its entry: always,
     * since both are written in one transaction or savepoint.
     *
     * @return bool
     */
    #[\Override]
    public function acceptsAttachments(): bool
    {
        return true;
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
     * it and leaves the host transaction as it was. Laravel decides that
     * rollback from the failure's message, so it is given the failure masked: a
     * record's value must not read as a deadlock and cost the savepoint.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  array<string, int|string|null>  $row
     * @return void
     *
     * @throws \Throwable
     */
    private function insert(Connection $connection, string $table, #[\SensitiveParameter] array $row): void
    {
        if ($connection->transactionLevel() === 0) {
            $connection->table($table)->insert($row);

            return;
        }

        $connection->transaction(static function (Connection $nested) use ($table, $row): void {
            try {
                $nested->table($table)->insert($row);
            } catch (QueryException $exception) { // @phpstan-ignore catch.neverThrown
                throw FailureClassifier::masked($exception);
            }
        });
    }

    /**
     * Store the bundle: its artifact's row and then its entry's, in one
     * transaction of one attempt, a savepoint inside a host's, so a failure of
     * either rolls both back. Laravel is given each failure masked, as a
     * record's insert gives it, and a unique violation is resolved once the
     * rollback is done.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  array<string, int|string|null>  $row
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Illuminate\Database\UniqueConstraintViolationException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \SineMacula\Laravel\AuditLog\Stores\RecordConflictException
     * @throws \Throwable
     */
    private function storeBundle(Connection $connection, string $table, #[\SensitiveParameter] FinalisedRecord $record, #[\SensitiveParameter] array $row): void
    {
        $artifacts = EntrySettings::artifactsTable();
        $artifact  = $this->codec->encodeAttachment($record);

        try {
            $connection->transaction(static function (Connection $bundle) use ($artifacts, $artifact, $table, $row): void {
                try {
                    $bundle->table($artifacts)->insert($artifact);
                    $bundle->table($table)->insert($row);
                } catch (QueryException $exception) { // @phpstan-ignore catch.neverThrown
                    throw FailureClassifier::masked($exception);
                }
            });
        } catch (UniqueConstraintViolationException $exception) {
            $this->resolveBundleDuplicate($connection, $table, $artifacts, $record, $artifact, $exception);
        }
    }

    /**
     * Resolve a unique violation of the record's insert: succeed only when the
     * writer holds a row under the record's id that verifies and has the same
     * captured content; otherwise throw, the conflict of a pruned record or the
     * original exception when no such row is visible.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \Illuminate\Database\UniqueConstraintViolationException  $exception
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \Illuminate\Database\UniqueConstraintViolationException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \SineMacula\Laravel\AuditLog\Stores\RecordConflictException
     */
    private function resolveDuplicate(
        Connection $connection,
        string $table,
        #[\SensitiveParameter]
        FinalisedRecord $record,
        #[\SensitiveParameter]
        UniqueConstraintViolationException $exception,
    ): void {
        $existing = self::lookup($connection, $table, $record->record->id);

        if ($existing === null) {
            $this->refuseUnstored($record->record->id, $exception);
        }

        $conflict = $this->conflictWith($record, $this->codec->decode((array) $existing));

        if ($conflict !== null) {
            throw $conflict;
        }
    }

    /**
     * Resolve a unique violation of the bundle's inserts: succeed only when the
     * writer holds an entry under the record's id that verifies and has the
     * same captured content, and an artifact under the attachment's id that is
     * the same artifact; throw the conflict of a pruned record or the original
     * exception when neither is visible, and a conflict otherwise.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  string  $artifacts
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  array{id: string, entry_id: string, kind: string, member_count: int, digest: string, members: string, created_at: string}  $artifact
     * @param  \Illuminate\Database\UniqueConstraintViolationException  $exception
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \Illuminate\Database\UniqueConstraintViolationException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \SineMacula\Laravel\AuditLog\Stores\RecordConflictException
     */
    private function resolveBundleDuplicate(
        Connection $connection,
        string $table,
        string $artifacts,
        #[\SensitiveParameter]
        FinalisedRecord $record,
        #[\SensitiveParameter]
        array $artifact,
        #[\SensitiveParameter]
        UniqueConstraintViolationException $exception,
    ): void {
        $entry  = self::lookup($connection, $table, $record->record->id);
        $stored = self::lookup($connection, $artifacts, $artifact['id']);

        if ($entry === null && $stored === null) {
            $this->refuseUnstored($record->record->id, $exception);
        }

        $conflict = $this->bundleConflictWith($record, $artifact, $entry, $stored);

        if ($conflict !== null) {
            throw $conflict;
        }
    }

    /**
     * Refuse a record whose insert violated a unique index though nothing is
     * stored under its ids: as already pruned when retention has pruned it, and
     * with the original exception otherwise.
     *
     * @param  string  $id
     * @param  \Illuminate\Database\UniqueConstraintViolationException  $exception
     * @return never
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Database\UniqueConstraintViolationException
     * @throws \SineMacula\Laravel\AuditLog\Stores\RecordConflictException
     */
    private function refuseUnstored(string $id, #[\SensitiveParameter] UniqueConstraintViolationException $exception): never
    {
        throw $this->tombstones->isPruned($id) ? RecordConflictException::alreadyPruned($id) : $exception;
    }

    /**
     * The conflict between the bundle and what is stored under its ids: none
     * when the entry verifies with the record's captured content and the
     * artifact is the bundle's, the entry's own conflict when it does not, and
     * otherwise the conflict of an entry stored with another artifact, without
     * its own, or not at all beside it. An entry that cannot be verified at all
     * is refused by the signer.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  array{id: string, entry_id: string, kind: string, member_count: int, digest: string, members: string, created_at: string}  $artifact
     * @param  ?object  $entry
     * @param  ?object  $stored
     * @return ?\SineMacula\Laravel\AuditLog\Stores\RecordConflictException
     *
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    private function bundleConflictWith(
        #[\SensitiveParameter]
        FinalisedRecord $record,
        #[\SensitiveParameter]
        array $artifact,
        #[\SensitiveParameter]
        ?object $entry,
        #[\SensitiveParameter]
        ?object $stored,
    ): ?RecordConflictException {
        $id = $record->record->id;

        if ($entry === null) {
            return RecordConflictException::differentArtifact($id);
        }

        $conflict = $this->conflictWith($record, $this->codec->decode((array) $entry));

        if ($conflict !== null) {
            return $conflict;
        }

        return $stored !== null && self::isSameArtifact($artifact, (array) $stored) ? null : RecordConflictException::differentArtifact($id);
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
    private function conflictWith(#[\SensitiveParameter] FinalisedRecord $record, #[\SensitiveParameter] array $stored): ?RecordConflictException
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

    /**
     * The row the writer holds under the id in the table, or `null`; on MySQL
     * inside a transaction, read with a shared lock, a current read past the
     * snapshot that needs only `SELECT`.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  string  $id
     * @return ?object
     */
    private static function lookup(Connection $connection, string $table, string $id): ?object
    {
        $query = $connection->table($table)->useWritePdo()->where('id', $id);

        if ($connection->getDriverName() === 'mysql' && $connection->transactionLevel() > 0) {
            $query->sharedLock();
        }

        return $query->first();
    }

    /**
     * Whether the stored artifact is the one the bundle carries: the same id,
     * entry, kind, member count and digest, each compared as the engine returns
     * it, a count as its digits.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array{id: string, entry_id: string, kind: string, member_count: int, digest: string, members: string, created_at: string}  $artifact
     * @param  array<array-key, mixed>  $stored
     * @return bool
     */
    private static function isSameArtifact(#[\SensitiveParameter] array $artifact, #[\SensitiveParameter] array $stored): bool
    {
        foreach (self::ARTIFACT_IDENTITY as $column) {
            $value = $stored[$column] ?? null;

            if (!is_string($value) && !is_int($value)) {
                return false;
            }

            if ((string) $value !== (string) $artifact[$column]) {
                return false;
            }
        }

        return true;
    }
}
