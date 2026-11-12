<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the deliveries table: one receipt per record and destination, so a
 * retried delivery reaches only the destinations that do not have the record
 * yet.
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
        $table  = DeliveryTables::deliveriesTable();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'delivery.deliveries_table');

        $mysql = $schema->getConnection()->getDriverName() === 'mysql';

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $mysql): void {
            $blueprint->uuid('entry_id');
            $blueprint->string('destination', 64);

            // Counted before each call to the destination, so a call that never
            // returns still counts.
            $blueprint->integer('attempts')->default(0);
            $blueprint->dateTime('first_attempted_at', 6);

            // Set once the destination has the record; only the class of the
            // last error is named.
            $blueprint->dateTime('delivered_at', 6)->nullable();
            $blueprint->string('last_error_class', 191)->nullable();

            if ($mysql) {
                // Binary and without padding (NO PAD), as the entries table,
                // and InnoDB, so a receipt joins the transaction it runs in.
                $blueprint->charset('utf8mb4');
                $blueprint->collation('utf8mb4_0900_bin');
                $blueprint->engine('InnoDB');
            }

            // Named short, so it fits 63 characters at the longest table name.
            $blueprint->primary(['entry_id', 'destination'], $table . '_primary');
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
        Schema::connection($this->getConnection())->dropIfExists(DeliveryTables::deliveriesTable());
    }

    /**
     * The storage connection, so a receipt is beside the entry it describes.
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
