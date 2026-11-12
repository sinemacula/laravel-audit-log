<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the owner erasures table: one marker per erasure or reinstatement of
 * an owner, never changed. The latest decides whether a key may be created.
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
        $table  = KeyTables::ownerErasuresTable();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'privacy.owner_erasures_table');

        $mysql = $schema->getConnection()->getDriverName() === 'mysql';

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $mysql): void {
            // Shared with the journal row that records the transition.
            $blueprint->uuid('id')->primary();

            $blueprint->string('owner_type', 191);
            $blueprint->string('owner_id', 191);

            // Every later key of the owner is created above the floor. No
            // column is a reserved word: never `action` or `floor`.
            $blueprint->string('transition', 16);
            $blueprint->integer('generation_floor');

            // Orders an owner's markers.
            $blueprint->bigInteger('journal_sequence');

            $blueprint->dateTime('created_at', 6);

            if ($mysql) {
                // Binary and without padding (NO PAD), as the entries table,
                // and InnoDB, so a marker commits with its journal row.
                $blueprint->charset('utf8mb4');
                $blueprint->collation('utf8mb4_0900_bin');
                $blueprint->engine('InnoDB');
            }

            // An owner's markers in journal order, its latest read first.
            $blueprint->index(['owner_type', 'owner_id', 'journal_sequence'], $table . '_owner_index');
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
        Schema::connection($this->getConnection())->dropIfExists(KeyTables::ownerErasuresTable());
    }

    /**
     * The storage connection, so a marker is beside the keys and the journal.
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
