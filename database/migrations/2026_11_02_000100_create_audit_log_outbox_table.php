<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;

/**
 * Create the outbox table: one row per record waiting for the drain to deliver
 * it, its envelope encrypted, deleted once every destination has it.
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
        $table  = DeliveryTables::outboxTable();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'delivery.outbox.table');

        $mysql = $schema->getConnection()->getDriverName() === 'mysql';

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $mysql): void {
            // The id of the entry the row delivers, written lower-case, so a
            // record is in the outbox once.
            $blueprint->uuid('id')->primary();

            // The envelope's canonical JSON, encrypted with the application's
            // key, so the row holds nothing readable.
            $blueprint->longText('payload');

            // Counted when a drain claims the row, so an attempt that kills its
            // worker still counts.
            $blueprint->integer('attempts')->default(0);
            $blueprint->dateTime('available_at', 6);

            $blueprint->dateTime('claimed_until', 6)->nullable();
            $blueprint->string('claimed_by', 64)->nullable();

            // Set once the row has had every attempt it gets; the row is kept
            // for a replay, and only the class of the last error is named.
            $blueprint->dateTime('failed_at', 6)->nullable();
            $blueprint->string('last_error_class', 191)->nullable();
            $blueprint->dateTime('created_at', 6);

            if ($mysql) {
                // Binary and without padding (NO PAD), as the entries table,
                // and InnoDB, so an insert joins the transaction it runs in.
                $blueprint->charset('utf8mb4');
                $blueprint->collation('utf8mb4_0900_bin');
                $blueprint->engine('InnoDB');
            }

            // What a drain claims by: rows not failed, in the order they fall
            // due.
            $blueprint->index(['failed_at', 'available_at'], $table . '_due_index');

            // What a monitor reads the backlog's age by: rows not failed, in
            // the order they were queued, which a retry never moves.
            $blueprint->index(['failed_at', 'created_at'], $table . '_queued_index');
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
        Schema::connection($this->getConnection())->dropIfExists(DeliveryTables::outboxTable());
    }

    /**
     * The outbox connection, or the storage connection when none is set.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    #[Override]
    public function getConnection(): ?string
    {
        return DeliveryTables::outboxConnection();
    }
};
