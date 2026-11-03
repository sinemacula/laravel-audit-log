<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the checkpoint members table: one row per entry a seal holds, with the
 * entry's HMAC when it was sealed. A member is written once with its seal and
 * never changed.
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
        $table  = IntegrityTables::membersTable();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'integrity.members_table');

        $mysql = $schema->getConnection()->getDriverName() === 'mysql';

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $mysql): void {
            // The seal and the entry it holds.
            $blueprint->uuid('checkpoint_id');
            $blueprint->uuid('entry_id');

            // The entry's HMAC when it was sealed, in hex.
            $blueprint->string('hmac', 64);

            if ($mysql) {
                // Binary and without padding (NO PAD), as the entries table,
                // and InnoDB, so the members commit with their seal.
                $blueprint->charset('utf8mb4');
                $blueprint->collation('utf8mb4_0900_bin');
                $blueprint->engine('InnoDB');
            }

            // An entry belongs to at most one seal, and the sealer's anti-join
            // probes the entry alone. Named short, so each fits PostgreSQL's 63
            // characters at the longest table name.
            $blueprint->primary(['checkpoint_id', 'entry_id'], $table . '_primary');
            $blueprint->unique(['entry_id'], $table . '_entry_unique');
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
        Schema::connection($this->getConnection())->dropIfExists(IntegrityTables::membersTable());
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`), so
     * a member is beside the entry it names.
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
