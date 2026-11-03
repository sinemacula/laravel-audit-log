<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Create the entries table: one row per audit record, the evidence the package
 * keeps, written once and never updated.
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
        $table  = EntrySettings::table();
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'entries.table');

        $mysql = $schema->getConnection()->getDriverName() === 'mysql';

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $mysql): void {
            // A UUID v7 drawn at capture, so rows sort roughly by when they
            // were captured; written lower-case, as PostgreSQL returns it.
            $blueprint->uuid('id')->primary();

            // The envelope's format and the event code's version, both covered
            // by the HMAC.
            $blueprint->smallInteger('record_version');
            $blueprint->string('event', 191);
            $blueprint->smallInteger('event_version');

            // The category is kept on the row, so retention never needs to read
            // the event catalogue.
            $blueprint->string('category', 64);
            $blueprint->string('outcome', 16);
            $blueprint->string('reason', 64)->nullable();

            // Plain string pairs, never `morphs()`, so a key of any type fits
            // and nothing cascades.
            $blueprint->string('actor_type', 191)->nullable();
            $blueprint->string('actor_id', 191)->nullable();
            $blueprint->string('subject_type', 191)->nullable();
            $blueprint->string('subject_id', 191)->nullable();
            $blueprint->string('principal_type', 191)->nullable();
            $blueprint->string('principal_id', 191)->nullable();
            $blueprint->string('tenant_type', 191)->nullable();
            $blueprint->string('tenant_id', 191)->nullable();

            // The session id is an application's own reference, never Laravel's
            // session cookie id. The credential and request ids are kept for
            // reading, not looked up, so they are not indexed.
            $blueprint->string('credential_id', 191)->nullable();
            $blueprint->string('guard', 64)->nullable();
            $blueprint->string('session_id', 191)->nullable();
            $blueprint->string('request_id', 64)->nullable();
            $blueprint->string('trace_id', 32)->nullable();
            $blueprint->string('correlation_id', 191)->nullable();

            // Null only on an imported record whose origin is unknown.
            $blueprint->string('origin', 16)->nullable();

            $blueprint->string('provenance', 16);
            $blueprint->string('source_id', 64);
            $blueprint->string('source_region', 32)->nullable();
            $blueprint->string('source_record_id', 191)->nullable();
            $blueprint->uuid('import_batch_id')->nullable();

            // 255 characters, so a truncated, hashed or encrypted address fits
            // as well as a full one.
            $blueprint->string('ip', 255)->nullable();
            $blueprint->string('user_agent', 512)->nullable();

            // `json`, never `jsonb`: integrity is verified on the decoded
            // values, so it does not depend on the engine keeping the text.
            $blueprint->json('context')->nullable();
            $blueprint->json('properties')->nullable();

            // To the microsecond, unlike the whole seconds the family's other
            // tables keep, so the records of one request sort in order.
            $blueprint->dateTime('occurred_at', 6);
            $blueprint->dateTime('recorded_at', 6);

            $blueprint->smallInteger('integrity_version');

            // The id of the key that signed the row, and the HMAC-SHA256, in
            // hex, over every other column.
            $blueprint->string('key_id', 32);
            $blueprint->string('hmac', 64);

            if ($mysql) {
                // Binary and without padding (NO PAD), so ids that differ only
                // in case or by a trailing space never compare equal, and
                // InnoDB, so writes are transactional.
                $blueprint->charset('utf8mb4');
                $blueprint->collation('utf8mb4_0900_bin');
                $blueprint->engine('InnoDB');
            }

            self::index($blueprint, $table);
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
        Schema::connection($this->getConnection())->dropIfExists(EntrySettings::table());
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`),
     * the one the model reads and the store writes the table on.
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

    /**
     * Index each lookup the trail makes, by actor, subject, principal, tenant,
     * event, category, correlation and time, index the order sealing pages the
     * entries in, by the time each was recorded and then its id, and keep an
     * imported record's source identity unique.
     *
     * @param  \Illuminate\Database\Schema\Blueprint  $blueprint
     * @param  string  $table
     * @return void
     */
    private static function index(Blueprint $blueprint, string $table): void
    {
        // Named short, so the index names of a 47-character table still fit
        // PostgreSQL's 63-character identifiers.
        $blueprint->index(['actor_type', 'actor_id', 'occurred_at'], $table . '_actor_index');
        $blueprint->index(['subject_type', 'subject_id', 'occurred_at'], $table . '_subject_index');
        $blueprint->index(['principal_type', 'principal_id', 'occurred_at'], $table . '_principal_index');
        $blueprint->index(['tenant_type', 'tenant_id', 'occurred_at'], $table . '_tenant_index');
        $blueprint->index(['event', 'occurred_at'], $table . '_event_index');
        $blueprint->index(['category', 'occurred_at'], $table . '_category_index');
        $blueprint->index(['correlation_id'], $table . '_correlate_index');
        $blueprint->index(['occurred_at'], $table . '_occurred_index');

        // What sealing keyset-pages by: the time each entry was recorded, then
        // its id, so entries recorded in the same microsecond keep an order.
        $blueprint->index(['recorded_at', 'id'], $table . '_recorded_index');
        $blueprint->unique(['source_id', 'source_record_id'], $table . '_source_unique');
    }
};
