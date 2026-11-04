<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the import batches table: one row per import, written by the storage
 * connection's writer before the import's first entry, then updated with its
 * counts and status until it ends. Its identity and source are never changed,
 * and a batch is never deleted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return new class extends Migration {
    /**
     * Run the migrations.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function up(): void
    {
        $table  = LifecycleTables::importBatchesTable();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'import.batches_table');

        $mysql = $schema->getConnection()->getDriverName() === 'mysql';

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $mysql): void {
            // The batch's id, which every entry it imports names.
            $blueprint->uuid('id')->primary();

            // Where the records came from and in which format. No column is
            // named a reserved word on any engine: `input_format`, never
            // `format`.
            $blueprint->string('source_id', 64);
            $blueprint->string('source_region', 32)->nullable();
            $blueprint->string('input_format', 32);

            // Who imported them and why.
            $blueprint->string('importer_type', 191);
            $blueprint->string('importer_id', 191);
            $blueprint->string('reason', 64);
            $blueprint->string('external_reference', 191)->nullable();

            // The file's SHA-256, read before the first entry, and whether the
            // records were verified against their source, which this package
            // never claims; always written, so it has no default.
            $blueprint->string('file_sha256', 64);
            $blueprint->boolean('externally_verified');

            // The hold placed with the import, if one was asked for.
            $blueprint->uuid('hold_id')->nullable();

            // Where the import stands, and its counts: `integer()`, never
            // `unsignedInteger()`, which PostgreSQL does not have, and
            // `lines_read`, never `read`.
            $blueprint->string('status', 16);
            $blueprint->integer('lines_read');
            $blueprint->integer('imported');
            $blueprint->integer('duplicates');
            $blueprint->integer('conflicts');
            $blueprint->integer('rejected');

            // The first conflicting source record ids in file order, as a
            // canonical JSON list.
            $blueprint->text('conflict_ids')->nullable();

            // To the microsecond: when the batch started, was last written and
            // ended.
            $blueprint->dateTime('started_at', 6);
            $blueprint->dateTime('updated_at', 6);
            $blueprint->dateTime('finished_at', 6)->nullable();

            if ($mysql) {
                // Binary and without padding (NO PAD), as the entries table,
                // and InnoDB, so the counts commit with the entries.
                $blueprint->charset('utf8mb4');
                $blueprint->collation('utf8mb4_0900_bin');
                $blueprint->engine('InnoDB');
            }

            // The batches still running, by when each was last written, so a
            // stale one is found. Named short, so it fits PostgreSQL's 63
            // characters at the longest table name.
            $blueprint->index(['status', 'updated_at'], $table . '_status_index');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function down(): void
    {
        Schema::connection($this->getConnection())->dropIfExists(LifecycleTables::importBatchesTable());
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`), so
     * a batch is beside the entries it imported.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    #[Override]
    public function getConnection(): ?string
    {
        return StorageConnection::name();
    }
};
