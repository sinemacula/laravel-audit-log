<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the checkpoints table: one signed seal per row, chained to the one
 * before. Only the anchor columns change after a seal is written.
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

            // Gapless within the one log the seals belong to.
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

            $blueprint->string('signer', 16);
            $blueprint->string('key_id', 32);
            $blueprint->smallInteger('algorithm_version');

            // The lifecycle journal's head the seal commits to; null when the
            // journal was empty or the seal was written without it.
            $blueprint->bigInteger('journal_sequence')->nullable();
            $blueprint->string('journal_head', 64)->nullable();

            $blueprint->string('signature', 64);

            // The only columns written after insert: a cache of the anchor's
            // receipt, never the authority.
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

            // Two sealers can never both extend the head; the other indexes
            // serve the anchorer's backlog and destructive operations' checks.
            $blueprint->unique(['sequence'], $table . '_sequence_unique');
            $blueprint->index(['anchored_at', 'sequence'], $table . '_anchored_index');
            $blueprint->index(['journal_sequence'], $table . '_journal_index');
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
     * The storage connection, so a seal is beside the entries it holds.
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
