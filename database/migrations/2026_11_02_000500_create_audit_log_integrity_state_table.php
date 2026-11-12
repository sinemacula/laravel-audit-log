<?php

declare(strict_types = 1);

use Carbon\CarbonImmutable;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the integrity state table: the progress of sealing, anchoring and
 * verification, which is never evidence. It also seeds the installation id with
 * a plain insert, never replaced, so `audit-log:check` only ever reads it.
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
     * @throws \JsonException
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

            // A JSON map of scalars.
            $blueprint->text('value');
            $blueprint->dateTime('updated_at', 6);

            if (!$mysql) {
                return;
            }

            // Binary NO PAD and InnoDB, as the entries table.
            $blueprint->charset('utf8mb4');
            $blueprint->collation('utf8mb4_0900_bin');
            $blueprint->engine('InnoDB');
        });

        $schema->getConnection()->table($table)->insert(InstallationIdentity::row(CarbonImmutable::now()));
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
     * The storage connection, so progress is beside the seals it describes.
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
