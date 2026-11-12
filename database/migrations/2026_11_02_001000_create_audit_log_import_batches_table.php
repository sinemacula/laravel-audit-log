<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the import batches table: one row per import, written before its first
 * entry, updated with its counts and status until it ends, and never deleted.
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
            $blueprint->uuid('id')->primary();

            // `input_format`, never `format`: no column is a reserved word.
            $blueprint->string('source_id', 64);
            $blueprint->string('source_region', 32)->nullable();
            $blueprint->string('input_format', 32);

            $blueprint->string('importer_type', 191);
            $blueprint->string('importer_id', 191);
            $blueprint->string('reason', 64);
            $blueprint->string('external_reference', 191)->nullable();

            // Whether the records were verified against their source, which
            // this package never claims; always written, so it has no default.
            $blueprint->string('file_sha256', 64);
            $blueprint->boolean('externally_verified');

            $blueprint->uuid('hold_id')->nullable();

            // `integer()`, never `unsignedInteger()`, which PostgreSQL lacks,
            // and `lines_read`, never the reserved `read`.
            $blueprint->string('status', 16);
            $blueprint->integer('lines_read');
            $blueprint->integer('imported');
            $blueprint->integer('duplicates');
            $blueprint->integer('conflicts');
            $blueprint->integer('rejected');

            // The first conflicting source record ids in file order, as a
            // canonical JSON list.
            $blueprint->text('conflict_ids')->nullable();

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

            // Finds a running batch gone stale.
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
     * The storage connection, so a batch is beside the entries it imported.
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
