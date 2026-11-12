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
use SineMacula\Laravel\AuditLog\Keys\KeyUses;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones;
use SineMacula\Laravel\AuditLog\Records\EnvelopeKeys;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * Stores finalised records as entries rows on the storage connection's writer,
 * with a bulk record's artifact and an envelope's key uses in one transaction.
 *
 * Inside a host transaction each insert uses a savepoint; on PostgreSQL keep
 * records per host transaction well under 64, or use a dedicated connection.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DatabaseAuditStore implements AcceptsAttachments, DurableAuditStore
{
    /** @var list<string> The columns that identify an artifact; its sealed members and time are not compared. */
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

        /** Resolves the storage connection on every call. */
        private ConnectionResolverInterface $connections,

        /** Turns a record into its row and a stored row back into its envelope. */
        private RowCodec $codec,

        /** Verifies an existing row and digests captured content. */
        private RecordSigner $signer,

        /** Says whether retention already pruned a record whose insert conflicted. */
        private PruneTombstones $tombstones,
    ) {}

    /**
     * Store the record with its artifact and key uses, or succeed without
     * writing when the same record is already stored.
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
        $keys       = EnvelopeKeys::ofRecord($record->record);

        if ($record->record->attachment !== null || $keys !== []) {
            $this->storeTogether($connection, $table, $record, $row, $keys === [] ? [] : KeyUses::rowsFor($record->record->id, $keys));

            return;
        }

        try {
            $this->insert($connection, $table, $row);
        } catch (UniqueConstraintViolationException $exception) {
            $this->resolveDuplicate($connection, $table, $record, $exception);
        }
    }

    /**
     * Whether a return is durable: always, since it is a committed insert or
     * one inside the host's transaction.
     *
     * @return bool
     */
    #[\Override]
    public function isDurable(): bool
    {
        return true;
    }

    /**
     * Whether a write joins a transaction on the connection: only on the
     * storage connection, by resolved name.
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
     * Whether the store keeps attachments: always, since both rows are written
     * together.
     *
     * @return bool
     */
    #[\Override]
    public function acceptsAttachments(): bool
    {
        return true;
    }

    /**
     * The storage connection, which must be a database connection with
     * savepoints.
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
     * Insert the row, in a savepoint inside a transaction, masking a failure so
     * a record's value cannot read to Laravel as a deadlock.
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
     * Insert the artifact, entry and key uses in one transaction or savepoint,
     * resolving a unique violation once it has rolled back.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  array<string, int|string|null>  $row
     * @param  list<array{key_id: string, entry_id: string}>  $uses
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
    private function storeTogether(Connection $connection, string $table, #[\SensitiveParameter] FinalisedRecord $record, #[\SensitiveParameter] array $row, array $uses): void
    {
        $artifacts = EntrySettings::artifactsTable();
        $artifact  = $record->record->attachment === null ? null : $this->codec->encodeAttachment($record);

        try {
            $connection->transaction(static function (Connection $together) use ($artifacts, $artifact, $table, $row, $uses): void {
                try {
                    self::insertTogether($together, $artifacts, $artifact, $table, $row, $uses);
                } catch (QueryException $exception) { // @phpstan-ignore catch.neverThrown
                    throw FailureClassifier::masked($exception);
                }
            });
        } catch (UniqueConstraintViolationException $exception) {
            if ($artifact === null) {
                $this->resolveDuplicate($connection, $table, $record, $exception);

                return;
            }

            $this->resolveBundleDuplicate($connection, $table, $artifacts, $record, $artifact, $exception);
        }
    }

    /**
     * Resolve the insert's unique violation: succeed only when a verified row
     * with the same captured content is stored under the record's id.
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
     * Resolve the bundle's unique violation: succeed only when its entry and
     * artifact are both stored as the bundle's.
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
     * Refuse a violation with nothing stored: as already pruned when retention
     * pruned the record, else with the original exception.
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
     * The conflict between the bundle and what is stored under its ids, or
     * `null` when both the entry and the artifact are the bundle's.
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
     * The conflict between the record and the decoded row under its id, or
     * `null` when the row verifies with the same captured content.
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
     * The writer's row under the id; on MySQL inside a transaction, a shared
     * lock reads past the snapshot and needs only `SELECT`.
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
     * Insert the artifact, if any, then the entry, then its key uses.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $artifacts
     * @param  ?array{id: string, entry_id: string, kind: string, member_count: int, digest: string, members: string, created_at: string}  $artifact
     * @param  string  $table
     * @param  array<string, int|string|null>  $row
     * @param  list<array{key_id: string, entry_id: string}>  $uses
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function insertTogether(
        Connection $connection,
        string $artifacts,
        #[\SensitiveParameter]
        ?array $artifact,
        string $table,
        #[\SensitiveParameter]
        array $row,
        array $uses,
    ): void {
        if ($artifact !== null) {
            $connection->table($artifacts)->insert($artifact);
        }

        $connection->table($table)->insert($row);

        KeyUses::insert($connection, $uses);
    }

    /**
     * Whether the stored artifact is the bundle's, each identity column
     * compared as a string, since an engine may return a count as digits.
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
