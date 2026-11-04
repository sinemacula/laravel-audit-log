<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the lifecycle journal: one signed row per lifecycle event (a policy, a
 * prune run and each of its chunks, a hold, a release, an import's start and
 * finish), each chained to the row before it and committed to by every seal.
 * Written only through the maintenance connection, and never updated or
 * deleted.
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
        $table  = LifecycleTables::journalTable();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'lifecycle.journal_table');

        $mysql = $schema->getConnection()->getDriverName() === 'mysql';

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $mysql): void {
            // A UUID v7 from the clock, written lower-case, as PostgreSQL
            // returns it.
            $blueprint->uuid('id')->primary();

            // 1, 2, 3 … with no gap, so a deleted or reordered row breaks the
            // chain, within the one log the seals belong to.
            $blueprint->bigInteger('sequence');
            $blueprint->string('log_id', 64);

            // What the row records, the operation it belongs to, and when.
            $blueprint->string('kind', 32);
            $blueprint->uuid('operation_id');
            $blueprint->dateTime('occurred_at', 6);

            // Who asked for the operation and why, when someone did: a prune
            // run has no authority.
            $blueprint->string('authority_type', 191)->nullable();
            $blueprint->string('authority_id', 191)->nullable();
            $blueprint->string('reason', 64)->nullable();
            $blueprint->string('external_reference', 191)->nullable();

            // The seal a prune row's record covers, and the hold a hold or a
            // release row names.
            $blueprint->uuid('seal_id')->nullable();
            $blueprint->uuid('hold_id')->nullable();

            // Canonical JSON as text, never a JSON column, so the digest the
            // signature covers is the digest of the bytes stored.
            $blueprint->longText('payload');
            $blueprint->string('payload_digest', 64);

            // The HMAC of the row before, null only on the first row, the key
            // that signed this one, and its HMAC-SHA256, in hex.
            $blueprint->string('previous_hmac', 64)->nullable();
            $blueprint->string('key_id', 32);
            $blueprint->string('hmac', 64);

            if ($mysql) {
                // Binary and without padding (NO PAD), as the entries table,
                // and InnoDB, so a row commits with what it describes.
                $blueprint->charset('utf8mb4');
                $blueprint->collation('utf8mb4_0900_bin');
                $blueprint->engine('InnoDB');
            }

            // One row per sequence, so two operations can never both extend the
            // head, and the lookups by seal, by hold and by kind. Named short,
            // so each fits PostgreSQL's 63 characters at the longest table
            // name.
            $blueprint->unique(['sequence'], $table . '_sequence_unique');
            $blueprint->index(['seal_id'], $table . '_seal_index');
            $blueprint->index(['hold_id'], $table . '_hold_index');
            $blueprint->index(['kind', 'occurred_at'], $table . '_kind_index');
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
        Schema::connection($this->getConnection())->dropIfExists(LifecycleTables::journalTable());
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`), so
     * the journal is beside the entries and the seals it describes.
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
