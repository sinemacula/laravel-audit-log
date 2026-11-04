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
 * A prune ledger over a table of its own on the maintenance connection, as the
 * lifecycle journal keeps one: a prune deletes some of a segment's entries and
 * writes its record here in one transaction, so a test can kill it at each
 * boundary, or run it beside a verification, and see the record and the deletes
 * commit together or not at all.
 *
 * The table holds every record of a seal, keyed by the seal and the record's
 * sequence among the seal's, each field stored as the record gives it, so a
 * record reads back exactly as it was written on every engine. Every query
 * reads the writer, so a replica's lag never hides a committed prune. A row is
 * read back through `PruneRecord::fromArray()`, which refuses a malformed field
 * as a record that cannot be read, and nothing more is checked here:
 * verification checks every record it is given. The test that creates the table
 * drops it.
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

    /** @var list<string> The columns of a stored record, in the order of the record's constructor. */
    private const array COLUMNS = ['log_id', 'seal_id', 'seal_digest', 'member_count', 'pruned', 'pruned_count', 'operation_id', 'pruned_at', 'key_id', 'signature'];

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
            $table->char('seal_id', 36);
            $table->unsignedInteger('sequence');
            $table->string('log_id', 64);
            $table->char('seal_digest', 64);
            $table->unsignedInteger('member_count');
            $table->text('pruned');
            $table->unsignedInteger('pruned_count');
            $table->char('operation_id', 36);
            $table->char('pruned_at', 27);
            $table->string('key_id', 32);
            $table->char('signature', 64);
            $table->primary(['seal_id', 'sequence']);
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
     * Write the record as the next prune record of the seal it names, joining a
     * transaction open on the maintenance connection.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\PruneRecord  $record
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function record(PruneRecord $record): void
    {
        $last = $this->connection()->table(self::TABLE)->useWritePdo()->where('seal_id', $record->sealId)->max('sequence');

        $this->connection()->table(self::TABLE)->insert([
            'seal_id'      => $record->sealId,
            'sequence'     => (is_numeric($last) ? (int) $last : 0) + 1,
            'log_id'       => $record->logId,
            'seal_digest'  => $record->sealDigest,
            'member_count' => $record->memberCount,
            'pruned'       => $record->pruned,
            'pruned_count' => $record->prunedCount,
            'operation_id' => $record->operationId,
            'pruned_at'    => $record->prunedAt,
            'key_id'       => $record->keyId,
            'signature'    => $record->signature,
        ]);
    }

    /**
     * Every record written for the seal, read from the writer, in the order
     * written, or none.
     *
     * @param  string  $sealId
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function recordsFor(string $sealId): array
    {
        $stored = $this->connection()->table(self::TABLE)->useWritePdo()->where('seal_id', $sealId)->orderBy('sequence')->get(self::COLUMNS)->all();

        return array_values(array_map(static fn (object $columns): PruneRecord => PruneRecord::fromArray(['v' => PruneRecord::VERSION, ...self::fieldsOf($columns)]), $stored));
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
     * The fields of a stored record, each integer column read from an integer
     * or the canonical digits a driver may return it as.
     *
     * @param  object  $columns
     * @return array<string, int|string|null>
     */
    private static function fieldsOf(object $columns): array
    {
        $fields = [];

        foreach (self::COLUMNS as $column) {
            $value   = get_object_vars($columns)[$column] ?? null;
            $integer = in_array($column, ['member_count', 'pruned_count'], true);

            $fields[$column] = $integer && is_string($value) && preg_match('/^(?:0|[1-9][0-9]*)$/', $value) === 1 ? (int) $value : $value;
        }

        /** @var array<string, int|string|null> */
        return $fields;
    }
}
