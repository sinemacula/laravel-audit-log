<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Reads and seeds the outbox and the deliveries table as the gateways write
 * them, moves the clock the gateways read, and forces a failed outbox insert.
 *
 * Every time a helper takes or gives is an instant in the package's form
 * (`2026-11-01T12:00:00.000000Z`), whatever the engine stores, so one assertion
 * holds on SQLite, MySQL and PostgreSQL alike. The clock is moved through
 * `CarbonImmutable::setTestNow()`, which the package's system clock reads; a
 * class that moves it puts it back in its `tearDown()`.
 *
 * The forced failure is a real one on every engine: the probe table has every
 * column of the outbox as nullable `text`, and a `probe` column that is `NOT
 * NULL` without a default, which an insert never writes. The outbox can also be
 * moved to a connection of its own, with a table prefix of its own, and its
 * table and the deliveries table migrated onto further connections, such as the
 * two sides of a read/write split. A class that does any of these undoes it in
 * its `tearDown()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithOutbox
{
    /** @var string The table every column of which is nullable but one an insert never writes. */
    protected const string OUTBOX_PROBE_TABLE = 'audit_probe_outbox';

    /** @var string The connection the outbox may be moved to. */
    protected const string MOVED_OUTBOX_CONNECTION = 'audit_outbox';

    /** @var string The outbox table once moved, named apart so its index is too where index names share a schema. */
    protected const string MOVED_OUTBOX_TABLE = 'audit_moved_outbox';

    /** @var list<string> The outbox table's columns, in table order. */
    protected const array OUTBOX_COLUMNS = ['id', 'payload', 'attempts', 'available_at', 'claimed_until', 'claimed_by', 'failed_at', 'last_error_class', 'created_at'];

    /** @var list<string> The deliveries table's columns, in table order. */
    protected const array RECEIPT_COLUMNS = ['entry_id', 'destination', 'attempts', 'first_attempted_at', 'delivered_at', 'last_error_class'];

    /** @var list<string> The outbox columns that hold a time. */
    private const array OUTBOX_TIMES = ['available_at', 'claimed_until', 'failed_at', 'created_at'];

    /** @var string Absolute path to the shipped outbox migration file. */
    private const string OUTBOX_MIGRATION = __DIR__ . '/../../database/migrations/2026_11_02_000100_create_audit_log_outbox_table.php';

    /** @var string Absolute path to the shipped deliveries migration file. */
    private const string DELIVERIES_MIGRATION = __DIR__ . '/../../database/migrations/2026_11_02_000200_create_audit_log_deliveries_table.php';

    /** @var string Absolute path to the shipped checkpoints migration file, whose seals a drain's tombstones read. */
    private const string CHECKPOINTS_MIGRATION = __DIR__ . '/../../database/migrations/2026_11_02_000300_create_audit_log_checkpoints_table.php';

    /** @var string Absolute path to the shipped checkpoint members migration file, whose members a drain's tombstones read. */
    private const string MEMBERS_MIGRATION = __DIR__ . '/../../database/migrations/2026_11_02_000400_create_audit_log_checkpoint_members_table.php';

    /** @var ?string The outbox table configured before the probe table took its place. */
    private ?string $outboxTableBeforeProbe = null;

    /** @var bool Whether the outbox was moved to a connection of its own. */
    private bool $outboxMoved = false;

    /**
     * The outbox connection.
     *
     * @return \Illuminate\Database\Connection
     */
    protected function outboxConnection(): Connection
    {
        return DB::connection(DeliveryTables::outboxConnection());
    }

    /**
     * The number of rows in the outbox.
     *
     * @return int
     */
    protected function outboxCount(): int
    {
        return $this->outboxConnection()->table(DeliveryTables::outboxTable())->count();
    }

    /**
     * The outbox row under the id, its attempts an integer and its times
     * instants in the package's form, or `null` when there is none.
     *
     * @param  string  $id
     * @return ?array<string, int|string|null>
     */
    protected function outboxRow(string $id): ?array
    {
        $row = $this->outboxConnection()->table(DeliveryTables::outboxTable())->where('id', $id)->first();

        return $row === null ? null : self::normalisedRow((array) $row, self::OUTBOX_TIMES);
    }

    /**
     * The receipt of the destination for the entry, its attempts an integer and
     * its times instants in the package's form, or `null` when there is none.
     *
     * @param  string  $id
     * @param  string  $destination
     * @return ?array<string, int|string|null>
     */
    protected function receipt(string $id, string $destination): ?array
    {
        $row = DB::connection(StorageConnection::name())
            ->table(DeliveryTables::deliveriesTable())
            ->where('entry_id', $id)
            ->where('destination', $destination)
            ->first();

        return $row === null ? null : self::normalisedRow((array) $row, ['first_attempted_at', 'delivered_at']);
    }

    /**
     * The number of receipts in the deliveries table.
     *
     * @return int
     */
    protected function receiptCount(): int
    {
        return DB::connection(StorageConnection::name())->table(DeliveryTables::deliveriesTable())->count();
    }

    /**
     * Seed an outbox row under the id holding the payload: no attempt, due and
     * created at the clock's now, unclaimed and not failed, unless the columns
     * given say otherwise. A time among the columns is an instant in the
     * package's form.
     *
     * @param  string  $id
     * @param  string  $payload
     * @param  array<string, int|string|null>  $columns
     * @return void
     */
    protected function seedOutboxRow(string $id, string $payload, array $columns = []): void
    {
        $now = StoredTime::format(CarbonImmutable::now());

        $row = [
            'id'               => $id,
            'payload'          => $payload,
            'attempts'         => 0,
            'available_at'     => $now,
            'claimed_until'    => null,
            'claimed_by'       => null,
            'failed_at'        => null,
            'last_error_class' => null,
            'created_at'       => $now,
            ...$columns,
        ];

        foreach (self::OUTBOX_TIMES as $column) {
            if (!is_string($row[$column])) {
                continue;
            }

            $row[$column] = StoredTime::toStorage($row[$column]);
        }

        $this->outboxConnection()->table(DeliveryTables::outboxTable())->insert($row);
    }

    /**
     * Stop the clock at the instant, read in UTC.
     *
     * @param  string  $instant
     * @return void
     */
    protected function moveClockTo(string $instant): void
    {
        CarbonImmutable::setTestNow(new CarbonImmutable($instant, 'UTC'));
    }

    /**
     * Create the probe table on the outbox connection and make it the outbox,
     * so the next insert into the outbox fails on its `NOT NULL` column.
     *
     * @return void
     */
    protected function pointOutboxAtProbeTable(): void
    {
        $schema = Schema::connection(DeliveryTables::outboxConnection());

        $schema->dropIfExists(self::OUTBOX_PROBE_TABLE);

        $schema->create(self::OUTBOX_PROBE_TABLE, static function (Blueprint $table): void {
            foreach (self::OUTBOX_COLUMNS as $column) {
                $table->text($column)->nullable();
            }

            $table->string('probe', 16);
        });

        $this->outboxTableBeforeProbe ??= DeliveryTables::outboxTable();

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.table', self::OUTBOX_PROBE_TABLE);
    }

    /**
     * Put the outbox back as it was configured before the probe table took its
     * place, and drop the probe table.
     *
     * @return void
     */
    protected function removeOutboxProbeTable(): void
    {
        $connection = DeliveryTables::outboxConnection();

        if ($this->outboxTableBeforeProbe !== null) {
            app(ConfigRepository::class)->set('audit-log.delivery.outbox.table', $this->outboxTableBeforeProbe);

            $this->outboxTableBeforeProbe = null;
        }

        Schema::connection($connection)->dropIfExists(self::OUTBOX_PROBE_TABLE);
    }

    /**
     * Move the outbox to a connection of its own, to the test database with a
     * table prefix of its own, under a table name of its own, and create its
     * table there. PostgreSQL keeps index names per schema and a prefix does
     * not reach an index the migration names, so the name keeps the moved
     * table's index apart from the storage connection's.
     *
     * @return void
     */
    protected function moveOutboxToItsOwnConnection(): void
    {
        $config  = app(ConfigRepository::class);
        $testing = $config->array('database.connections.' . $config->string('database.default'));

        $config->set('database.connections.' . self::MOVED_OUTBOX_CONNECTION, [...$testing, 'prefix' => 'outbox_']);
        $config->set('audit-log.delivery.outbox.connection', self::MOVED_OUTBOX_CONNECTION);
        $config->set('audit-log.delivery.outbox.table', self::MOVED_OUTBOX_TABLE);

        Schema::connection(self::MOVED_OUTBOX_CONNECTION)->dropIfExists(self::MOVED_OUTBOX_TABLE);

        self::runMigration(self::OUTBOX_MIGRATION);

        $this->outboxMoved = true;
    }

    /**
     * Drop the outbox from the connection it was moved to and put it back on
     * the storage connection, under its default name.
     *
     * @return void
     */
    protected function removeMovedOutbox(): void
    {
        if (!$this->outboxMoved) {
            return;
        }

        Schema::connection(self::MOVED_OUTBOX_CONNECTION)->dropIfExists(self::MOVED_OUTBOX_TABLE);

        app(ConfigRepository::class)->set([
            'audit-log.delivery.outbox.connection' => null,
            'audit-log.delivery.outbox.table'      => DeliveryTables::DEFAULT_OUTBOX,
        ]);

        DB::purge(self::MOVED_OUTBOX_CONNECTION);

        $this->outboxMoved = false;
    }

    /**
     * Create the outbox and the deliveries table on each connection given, and
     * the seals and their members a drain's tombstones read, as the shipped
     * migrations would with the storage connection there, then put the storage
     * and the outbox connections back as they were.
     *
     * @param  list<string>  $connections
     * @return void
     */
    protected function migrateDeliveryTablesOn(array $connections): void
    {
        $config  = app(ConfigRepository::class);
        $storage = $config->get('audit-log.storage.connection');
        $outbox  = $config->get('audit-log.delivery.outbox.connection');

        foreach ($connections as $connection) {
            $config->set('audit-log.storage.connection', $connection);
            $config->set('audit-log.delivery.outbox.connection', $connection);

            self::runMigration(self::OUTBOX_MIGRATION);
            self::runMigration(self::DELIVERIES_MIGRATION);
            self::runMigration(self::CHECKPOINTS_MIGRATION);
            self::runMigration(self::MEMBERS_MIGRATION);
        }

        $config->set('audit-log.storage.connection', $storage);
        $config->set('audit-log.delivery.outbox.connection', $outbox);
    }

    /**
     * Run a shipped migration's `up()` on the connection its settings name.
     *
     * @param  string  $path
     * @return void
     */
    private static function runMigration(string $path): void
    {
        $migration = require $path;

        assert($migration instanceof Migration && method_exists($migration, 'up'));

        $migration->up();
    }

    /**
     * The stored row with its attempts as an integer and its times, given by
     * name, as instants in the package's form.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $row
     * @param  list<string>  $times
     * @return array<string, int|string|null>
     */
    private static function normalisedRow(array $row, array $times): array
    {
        $normalised = [];

        foreach ($row as $column => $value) {
            $normalised[(string) $column] = match (true) {
                $column === 'attempts'          && is_numeric($value) => (int) $value,
                in_array($column, $times, true) && is_string($value)  => StoredTime::fromStorage($value),
                is_string($value), is_int($value), $value === null    => $value,
                default                                               => get_debug_type($value),
            };
        }

        return $normalised;
    }
}
