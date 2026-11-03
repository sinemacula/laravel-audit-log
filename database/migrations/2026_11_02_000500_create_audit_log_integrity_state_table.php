<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the integrity state table: the operational progress of sealing,
 * anchoring and verification, one named value per row, for monitoring and for
 * resuming a sweep. It is never evidence: verification reads none of it, and
 * any row may be lost or rewritten without hiding a change to the log.
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
        $table  = IntegrityTables::stateTable();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'integrity.state_table');

        $mysql = $schema->getConnection()->getDriverName() === 'mysql';

        $schema->create($table, static function (Blueprint $blueprint) use ($mysql): void {
            // `name`, not `key`, which MySQL reserves.
            $blueprint->string('name', 64)->primary();

            // A JSON map of scalars, and when it was last written.
            $blueprint->text('value');
            $blueprint->dateTime('updated_at', 6);

            if (!$mysql) {
                return;
            }

            // Binary and without padding (NO PAD), as the entries table, and
            // InnoDB, as every table the package keeps.
            $blueprint->charset('utf8mb4');
            $blueprint->collation('utf8mb4_0900_bin');
            $blueprint->engine('InnoDB');
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
        Schema::connection($this->getConnection())->dropIfExists(IntegrityTables::stateTable());
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`), so
     * progress is beside the seals it describes.
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
