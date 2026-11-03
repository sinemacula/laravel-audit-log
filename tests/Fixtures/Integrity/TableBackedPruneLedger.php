<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Integrity;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Schema\Blueprint;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;

/**
 * A prune ledger over a table of its own on the maintenance connection, as a
 * lifecycle journal keeps one: a prune deletes a segment's entries and writes
 * its record here in one transaction, so a test can kill it at each boundary,
 * or run it beside a verification, and see the record and the deletes commit
 * together or not at all.
 *
 * The table holds one record per seal, each field stored as the record gives
 * it, so a record reads back exactly as it was written on every engine. Every
 * query reads the writer, so a replica's lag never hides a committed prune. A
 * row is read back into a record, which refuses a malformed field, and nothing
 * more is checked here: verification checks every record it is given. The test
 * that creates the table drops it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TableBackedPruneLedger implements PruneLedger
{
    /** @var string The table the records are kept in. */
    public const string TABLE = 'audit_test_prune_records';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** The connections the maintenance connection is resolved from on every call. */
        private DatabaseManager $database,
    ) {}

    /**
     * Create the table on the maintenance connection, empty, dropping one a
     * test killed before it could drop it.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function createTable(): void
    {
        $schema = $this->connection()->getSchemaBuilder();

        $schema->dropIfExists(self::TABLE);
        $schema->create(self::TABLE, static function (Blueprint $table): void {
            $table->char('seal_id', 36)->primary();
            $table->string('log_id', 64);
            $table->char('seal_digest', 64);
            $table->unsignedInteger('member_count');
            $table->char('operation_id', 36);
            $table->char('pruned_at', 27);
            $table->string('key_id', 32);
            $table->char('signature', 64);
        });
    }

    /**
     * Drop the table from the maintenance connection, if it is there.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function dropTable(): void
    {
        $this->connection()->getSchemaBuilder()->dropIfExists(self::TABLE);
    }

    /**
     * Write the record as the prune record of the seal it names, joining a
     * transaction open on the maintenance connection. A second record for one
     * seal is refused by the table's key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneRecord  $record
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function record(PruneRecord $record): void
    {
        $this->connection()->table(self::TABLE)->insert([
            'seal_id'      => $record->sealId,
            'log_id'       => $record->logId,
            'seal_digest'  => $record->sealDigest,
            'member_count' => $record->memberCount,
            'operation_id' => $record->operationId,
            'pruned_at'    => $record->prunedAt,
            'key_id'       => $record->keyId,
            'signature'    => $record->signature,
        ]);
    }

    /**
     * The record written for the seal, read from the writer, or `null` when
     * none was.
     *
     * @param  string  $sealId
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function recordFor(string $sealId): ?PruneRecord
    {
        $stored = $this->connection()->table(self::TABLE)->useWritePdo()->where('seal_id', $sealId)->first();

        if ($stored === null) {
            return null;
        }

        return new PruneRecord(
            self::text($stored, 'log_id'),
            self::text($stored, 'seal_id'),
            self::text($stored, 'seal_digest'),
            self::count($stored, 'member_count'),
            self::text($stored, 'operation_id'),
            self::text($stored, 'pruned_at'),
            self::text($stored, 'key_id'),
            self::text($stored, 'signature'),
        );
    }

    /**
     * The maintenance connection.
     *
     * @return \Illuminate\Database\Connection
     *
     * @throws \InvalidArgumentException
     */
    private function connection(): Connection
    {
        return $this->database->connection(StorageConnection::forMaintenance());
    }

    /**
     * A text column of a stored record.
     *
     * @param  object  $stored
     * @param  string  $column
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function text(object $stored, string $column): string
    {
        $value = get_object_vars($stored)[$column] ?? null;

        if (!is_string($value)) {
            throw new \UnexpectedValueException(sprintf('A stored prune record\'s `%s` must be text.', $column));
        }

        return $value;
    }

    /**
     * An integer column of a stored record, which a driver may return as its
     * canonical digits.
     *
     * @param  object  $stored
     * @param  string  $column
     * @return int
     *
     * @throws \UnexpectedValueException
     */
    private static function count(object $stored, string $column): int
    {
        $value = get_object_vars($stored)[$column] ?? null;

        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && preg_match('/^(?:0|[1-9][0-9]*)$/', $value) === 1) {
            return (int) $value;
        }

        throw new \UnexpectedValueException(sprintf('A stored prune record\'s `%s` must be an integer.', $column));
    }
}
