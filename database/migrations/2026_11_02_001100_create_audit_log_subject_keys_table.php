<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the subject keys table: one row per generation of an owner's key unit,
 * the owner with a tenant and a category. Never deleted, and updated only by
 * the maintenance connection.
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
        $table  = KeyTables::subjectKeysTable();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'privacy.subject_keys_table');

        $mysql = $schema->getConnection()->getDriverName() === 'mysql';

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $mysql): void {
            // Named by every envelope it sealed, never derived from its owner.
            $blueprint->uuid('id')->primary();

            $blueprint->string('owner_type', 191);
            $blueprint->string('owner_id', 191);
            $blueprint->string('tenant_type', 191)->nullable();
            $blueprint->string('tenant_id', 191)->nullable();
            $blueprint->string('category', 64);

            // A unique index over the nullable tenant columns would let two
            // tenantless rows share a generation, so the unit's digest is used.
            $blueprint->string('unit', 64);
            $blueprint->integer('generation');

            // The wrapped key and its wrapping key's id are null once erased.
            $blueprint->string('state', 16);
            $blueprint->text('wrapped_key')->nullable();
            $blueprint->string('wrap_key_id', 191)->nullable();

            $blueprint->dateTime('created_at', 6);

            // The journal row of the erasure that destroyed the key.
            $blueprint->uuid('erasure_id')->nullable();

            // The HMAC covers only the columns never changed.
            $blueprint->string('key_id', 32);
            $blueprint->string('hmac', 64);

            if ($mysql) {
                // Binary and without padding (NO PAD), as the entries table,
                // and InnoDB, so a tombstone commits with its journal row.
                $blueprint->charset('utf8mb4');
                $blueprint->collation('utf8mb4_0900_bin');
                $blueprint->engine('InnoDB');
            }

            $blueprint->unique(['unit', 'generation'], $table . '_unit_unique');
            $blueprint->index(['owner_type', 'owner_id'], $table . '_owner_index');
            $blueprint->index(['erasure_id'], $table . '_erasure_index');
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
        Schema::connection($this->getConnection())->dropIfExists(KeyTables::subjectKeysTable());
    }

    /**
     * The storage connection, so a key is beside the entries it encrypted.
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
