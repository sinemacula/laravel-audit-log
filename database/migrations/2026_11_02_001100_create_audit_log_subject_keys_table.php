<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the subject keys table: one row for each generation of an owner's key
 * unit, the owner with a tenant and a category. A row is inserted by the
 * storage connection's writer when its key is created, and is never deleted;
 * only its state, its wrapped key, the wrapping key's id and the erasure that
 * destroyed it are ever updated, by the maintenance connection.
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
            // The key's own id, which every envelope it sealed names, never
            // derived from its owner.
            $blueprint->uuid('id')->primary();

            // The key unit: the owner, the tenant of the records it encrypts,
            // if any, and their category.
            $blueprint->string('owner_type', 191);
            $blueprint->string('owner_id', 191);
            $blueprint->string('tenant_type', 191)->nullable();
            $blueprint->string('tenant_id', 191)->nullable();
            $blueprint->string('category', 64);

            // The unit's digest, unique with the generation: a composite unique
            // index over the nullable tenant columns would let two tenantless
            // rows share a generation on every engine.
            $blueprint->string('unit', 64);
            $blueprint->integer('generation');

            // Where the key stands, the data key wrapped under the wrapping key
            // the id names, both null once it is erased.
            $blueprint->string('state', 16);
            $blueprint->text('wrapped_key')->nullable();
            $blueprint->string('wrap_key_id', 191)->nullable();

            // To the microsecond, when the key was created.
            $blueprint->dateTime('created_at', 6);

            // The journal row of the erasure that destroyed the key.
            $blueprint->uuid('erasure_id')->nullable();

            // The signing key and the HMAC over the columns never changed.
            $blueprint->string('key_id', 32);
            $blueprint->string('hmac', 64);

            if ($mysql) {
                // Binary and without padding (NO PAD), as the entries table,
                // and InnoDB, so a tombstone commits with its journal row.
                $blueprint->charset('utf8mb4');
                $blueprint->collation('utf8mb4_0900_bin');
                $blueprint->engine('InnoDB');
            }

            // One key per unit and generation, an owner's keys found together,
            // and the keys an erasure destroyed. Named short, so each fits
            // PostgreSQL's 63 characters at the longest table name.
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
     * The connection the package's tables live on (see `StorageConnection`), so
     * a key is beside the entries whose fields it encrypted.
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
