<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the holds table: an index of the active holds, rebuilt from the
 * journal, which alone decides what a prune keeps. Rows are never updated.
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
        $table  = LifecycleTables::holdsTable();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'lifecycle.holds_table');

        $mysql = $schema->getConnection()->getDriverName() === 'mysql';

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $mysql): void {
            $blueprint->uuid('hold_id')->primary();

            // What the hold covers, as canonical JSON text, and its digest.
            $blueprint->longText('scope');
            $blueprint->string('scope_digest', 64);

            $blueprint->string('basis', 32);
            $blueprint->uuid('import_batch_id')->nullable();
            $blueprint->dateTime('placed_at', 6);
            $blueprint->dateTime('review_by', 6)->nullable();

            $blueprint->string('authority_type', 191);
            $blueprint->string('authority_id', 191);
            $blueprint->string('reason', 64);
            $blueprint->string('external_reference', 191)->nullable();

            $blueprint->uuid('operation_id');
            $blueprint->bigInteger('journal_sequence');

            if ($mysql) {
                // Binary and without padding (NO PAD), as the entries table,
                // and InnoDB, so a row commits with its journal row.
                $blueprint->charset('utf8mb4');
                $blueprint->collation('utf8mb4_0900_bin');
                $blueprint->engine('InnoDB');
            }

            $blueprint->index(['review_by'], $table . '_review_index');
            $blueprint->index(['import_batch_id'], $table . '_batch_index');
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
        Schema::connection($this->getConnection())->dropIfExists(LifecycleTables::holdsTable());
    }

    /**
     * The storage connection, so the holds are beside the journal.
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
