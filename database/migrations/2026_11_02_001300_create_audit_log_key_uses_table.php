<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the key uses table: one row for each key and each entry with a field
 * it encrypted, inserted by the storage connection's writer with its entry, and
 * never updated or deleted, a prune included. It is an index derived from the
 * entries, which verification proves complete.
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
        $table  = KeyTables::keyUsesTable();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'privacy.key_uses_table');

        $mysql = $schema->getConnection()->getDriverName() === 'mysql';

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $mysql): void {
            // The key, as an envelope names it, and the entry it encrypted a
            // field of.
            $blueprint->uuid('key_id');
            $blueprint->uuid('entry_id');

            if ($mysql) {
                // Binary and without padding (NO PAD), as the entries table,
                // and InnoDB, so a key use commits with its entry.
                $blueprint->charset('utf8mb4');
                $blueprint->collation('utf8mb4_0900_bin');
                $blueprint->engine('InnoDB');
            }

            // A key's entries read in order, and an entry's keys found. Named
            // short, so each fits PostgreSQL's 63 characters at the longest
            // table name.
            $blueprint->primary(['key_id', 'entry_id'], $table . '_primary');
            $blueprint->index(['entry_id'], $table . '_entry_index');
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
        Schema::connection($this->getConnection())->dropIfExists(KeyTables::keyUsesTable());
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`), so
     * a key use is beside the entry and the key it pairs.
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
