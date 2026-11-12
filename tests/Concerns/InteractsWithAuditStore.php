<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Fixtures\Support\FrozenClock;

/**
 * Stores records through the database store, reads back what it wrote, and
 * forces the store's two failures for real on every engine.
 *
 * A test-only unique index on `request_id` breaks an index other than the id's,
 * and the probe table's `NOT NULL` `probe` column, which the store never
 * writes, fails an insert. A class that adds either removes it in its
 * `tearDown()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithAuditStore
{
    /** @var string The table every column of which is nullable but one the store never writes. */
    protected const string PROBE_TABLE = 'audit_probe_entries';

    /** @var string The test-only unique index on the entries table's `request_id`. */
    protected const string REQUEST_ID_INDEX = 'audit_log_entries_request_unique';

    /** @var ?string The entries table configured before the probe table took its place. */
    private ?string $tableBeforeProbe = null;

    /**
     * A finaliser whose clock is frozen at the instant, which is read in UTC.
     *
     * @param  string  $at
     * @return \SineMacula\Laravel\AuditLog\Records\RecordFinaliser
     */
    protected function finaliser(string $at = '2026-11-01 12:00:00.200000'): RecordFinaliser
    {
        return new RecordFinaliser(FrozenClock::at($at), app(RecordSigner::class));
    }

    /**
     * The database store, as the container builds it.
     *
     * @return \SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore
     */
    protected function store(): DatabaseAuditStore
    {
        return app(DatabaseAuditStore::class);
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     */
    protected function storageConnection(): Connection
    {
        return DB::connection(StorageConnection::name());
    }

    /**
     * The envelope the entries table holds under the id, decoded through the
     * row codec; the row must exist.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $id
     * @return array<string, mixed>
     */
    protected function storedRow(string $id): array
    {
        $row = $this->storageConnection()->table(EntrySettings::table())->where('id', $id)->first();

        self::assertNotNull($row, "No entry is stored under {$id}.");

        return (new RowCodec)->decode((array) $row);
    }

    /**
     * The number of rows in the entries table.
     *
     * @return int
     */
    protected function entryCount(): int
    {
        return $this->storageConnection()->table(EntrySettings::table())->count();
    }

    /**
     * Add a unique index on the entries table's `request_id`, so two records
     * with one request id violate an index other than the id's.
     *
     * @return void
     */
    protected function addRequestIdUniqueIndex(): void
    {
        Schema::connection(StorageConnection::name())->table(EntrySettings::table(), static function (Blueprint $table): void {
            $table->unique('request_id', self::REQUEST_ID_INDEX);
        });
    }

    /**
     * Drop the unique index on `request_id`, when the entries table has it.
     *
     * @return void
     */
    protected function removeRequestIdUniqueIndex(): void
    {
        $schema = Schema::connection(StorageConnection::name());
        $table  = EntrySettings::table();

        if (!$schema->hasTable($table) || !$schema->hasIndex($table, self::REQUEST_ID_INDEX)) {
            return;
        }

        $schema->table($table, static function (Blueprint $table): void {
            $table->dropUnique(self::REQUEST_ID_INDEX);
        });
    }

    /**
     * Make the probe table the entries table, so the store's next insert fails
     * on its `NOT NULL` column; its `id` is a UUID so joins on it run on
     * PostgreSQL.
     *
     * @return void
     */
    protected function pointAtProbeTable(): void
    {
        $schema = Schema::connection(StorageConnection::name());

        $schema->dropIfExists(self::PROBE_TABLE);

        $schema->create(self::PROBE_TABLE, static function (Blueprint $table): void {
            foreach (array_keys(RowCodec::COLUMNS) as $column) {
                $column === 'id' ? $table->uuid($column)->nullable() : $table->text($column)->nullable();
            }

            $table->string('probe', 16);
        });

        $config = app(ConfigRepository::class);

        $this->tableBeforeProbe ??= EntrySettings::table();

        $config->set('audit-log.entries.table', self::PROBE_TABLE);
    }

    /**
     * Put the entries table back as it was configured before the probe table
     * took its place, and drop the probe table.
     *
     * @return void
     */
    protected function removeProbeTable(): void
    {
        if ($this->tableBeforeProbe !== null) {
            app(ConfigRepository::class)->set('audit-log.entries.table', $this->tableBeforeProbe);

            $this->tableBeforeProbe = null;
        }

        Schema::connection(StorageConnection::name())->dropIfExists(self::PROBE_TABLE);
    }

    /**
     * The number of rows in the probe table.
     *
     * @return int
     */
    protected function probeCount(): int
    {
        return $this->storageConnection()->table(self::PROBE_TABLE)->count();
    }
}
