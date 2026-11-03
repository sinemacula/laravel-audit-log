<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the artifacts table: one row per bulk operation, holding the encrypted
 * list of the subjects its entry's signed manifest describes. An artifact is
 * written with its entry and never changed.
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
        $table  = EntrySettings::artifactsTable();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'entries.artifacts_table');

        $mysql = $schema->getConnection()->getDriverName() === 'mysql';

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $mysql): void {
            // The artifact's own id and the entry whose manifest names it, both
            // written lower-case.
            $blueprint->uuid('id')->primary();
            $blueprint->uuid('entry_id');

            // What the artifact holds (`bulk`), how many members it lists, and
            // the SHA-256 of their canonical form, in hex.
            $blueprint->string('kind', 16);
            $blueprint->unsignedInteger('member_count');
            $blueprint->string('digest', 64);

            // The canonical member list, encrypted with the application's key,
            // so the row holds nothing readable.
            $blueprint->longText('members');

            // The entry's recorded time.
            $blueprint->dateTime('created_at', 6);

            if ($mysql) {
                // Binary and without padding (NO PAD), as the entries table,
                // and InnoDB, so an artifact commits with its entry.
                $blueprint->charset('utf8mb4');
                $blueprint->collation('utf8mb4_0900_bin');
                $blueprint->engine('InnoDB');
            }

            // An entry has at most one artifact. Named short, so it fits
            // PostgreSQL's 63 characters at the longest table name.
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
        Schema::connection($this->getConnection())->dropIfExists(EntrySettings::artifactsTable());
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`), so
     * an artifact is beside the entry that names it.
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
