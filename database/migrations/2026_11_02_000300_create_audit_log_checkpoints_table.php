<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the checkpoints table: one signed seal per row, each chained to the
 * one before it, over the entries its members name. A seal is written once and
 * only its anchor columns change after.
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
        $table  = IntegrityTables::checkpointsTable();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'integrity.checkpoints_table');

        $mysql = $schema->getConnection()->getDriverName() === 'mysql';

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $mysql): void {
            // A UUID v7 from the clock, written lower-case, as PostgreSQL
            // returns it.
            $blueprint->uuid('id')->primary();

            // 1, 2, 3 … with no gap, within the one log the seals belong to.
            $blueprint->bigInteger('sequence');
            $blueprint->string('log_id', 64);

            // The previous seal and its digest; null only at genesis.
            $blueprint->uuid('previous_id')->nullable();
            $blueprint->string('previous_digest', 64)->nullable();

            // How many entries the seal holds, and the digest of their ids and
            // HMACs in order.
            $blueprint->integer('member_count');
            $blueprint->string('members_digest', 64);
            $blueprint->string('seal_digest', 64);

            // To the microsecond: the oldest and newest entry sealed, and when.
            $blueprint->dateTime('first_recorded_at', 6);
            $blueprint->dateTime('last_recorded_at', 6);
            $blueprint->dateTime('sealed_at', 6);

            // How the seal is signed, by which key, and the signature in hex.
            $blueprint->string('signer', 16);
            $blueprint->string('key_id', 32);
            $blueprint->smallInteger('algorithm_version');
            $blueprint->string('signature', 64);

            // The only columns written after the row is inserted: a cache of
            // the anchor's receipt, never the authority. Only the class of the
            // last error is named.
            $blueprint->string('anchor', 64)->nullable();
            $blueprint->json('anchor_receipt')->nullable();
            $blueprint->dateTime('anchored_at', 6)->nullable();
            $blueprint->string('anchor_error_class', 191)->nullable();

            if ($mysql) {
                // Binary and without padding (NO PAD), as the entries table,
                // and InnoDB, so a seal and its members commit together.
                $blueprint->charset('utf8mb4');
                $blueprint->collation('utf8mb4_0900_bin');
                $blueprint->engine('InnoDB');
            }

            // One seal per sequence, so two sealers can never both extend the
            // head, and what the anchorer reads: the seals not yet anchored, in
            // order. Named short, so each fits PostgreSQL's 63 characters at
            // the longest table name.
            $blueprint->unique(['sequence'], $table . '_sequence_unique');
            $blueprint->index(['anchored_at', 'sequence'], $table . '_anchored_index');
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
        Schema::connection($this->getConnection())->dropIfExists(IntegrityTables::checkpointsTable());
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`), so
     * a seal is beside the entries it holds.
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
