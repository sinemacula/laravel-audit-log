<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the lifecycle lock: one row, locked by an update that is the first
 * statement of every lifecycle transaction, so two lifecycle operations never
 * interleave. The migration seeds the row; it is only ever updated, never
 * inserted again or deleted.
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
        $table  = LifecycleTables::lockTable();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'lifecycle.lock_table');

        $mysql = $schema->getConnection()->getDriverName() === 'mysql';

        $schema->create($table, static function (Blueprint $blueprint) use ($mysql): void {
            // Always 1: the one row there is.
            $blueprint->smallInteger('id')->primary();

            // The token of the operation that last took the lock, and when;
            // each lock writes new values, so the update always changes the
            // row.
            $blueprint->string('token', 64)->nullable();
            $blueprint->dateTime('locked_at', 6)->nullable();

            if (!$mysql) {
                return;
            }

            // Binary and without padding (NO PAD), as the entries table, and
            // InnoDB, so the update takes a row lock held until the commit.
            $blueprint->charset('utf8mb4');
            $blueprint->collation('utf8mb4_0900_bin');
            $blueprint->engine('InnoDB');
        });

        $schema->getConnection()->table($table)->insert(['id' => 1, 'token' => null, 'locked_at' => null]);
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
        Schema::connection($this->getConnection())->dropIfExists(LifecycleTables::lockTable());
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`), so
     * the lock is taken in the database the journal and the entries are in.
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
