<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use Tests\TestCase;

/**
 * Integration tests for where the shipped delivery migrations, run by Laravel's
 * own `migrate` and `migrate:rollback` commands, create the outbox and the
 * deliveries tables: the outbox on the storage connection unless
 * `audit-log.delivery.outbox.connection` names its own, and the deliveries
 * always beside the entries on the storage connection.
 *
 * The storage and the outbox connections are further connections to the test
 * database, each with a table prefix of its own: a database of its own on
 * SQLite, where each in-memory connection has one, and prefixed tables beside
 * the default connection's on PostgreSQL and MySQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliveryTables::class)]
final class DeliveryMigrationsConnectionTest extends TestCase
{
    /** @var string The connection the package's tables live on. */
    private const string STORAGE = 'audit_store';

    /** @var string A connection the outbox may be moved to. */
    private const string OUTBOX = 'audit_outbox';

    /** @var string The shipped migrations, as `--path` takes them. */
    private const string MIGRATIONS = __DIR__ . '/../../../database/migrations';

    /** @var string The outbox table. */
    private const string OUTBOX_TABLE = 'audit_log_outbox';

    /** @var string The deliveries table. */
    private const string DELIVERIES_TABLE = 'audit_log_deliveries';

    /** @var string The entries table. */
    private const string ENTRIES_TABLE = 'audit_log_entries';

    /**
     * With no outbox connection named, the outbox is created on the storage
     * connection, beside the entries and the deliveries, and on no other.
     *
     * @return void
     */
    public function testTheOutboxFollowsTheStorageConnectionByDefault(): void
    {
        self::assertSame(self::STORAGE, DeliveryTables::outboxConnection());

        foreach ([self::ENTRIES_TABLE, self::OUTBOX_TABLE, self::DELIVERIES_TABLE] as $table) {
            self::assertTrue(Schema::connection(self::STORAGE)->hasTable($table), $table);
            self::assertFalse(Schema::connection(self::CONNECTION)->hasTable($table), $table);
            self::assertFalse(Schema::connection(self::OUTBOX)->hasTable($table), $table);
        }
    }

    /**
     * A named outbox connection holds the outbox, and the storage connection
     * then does not.
     *
     * @return void
     */
    public function testTheOutboxGoesOnItsOwnConnection(): void
    {
        $this->moveTheOutbox();

        try {
            self::assertSame(self::OUTBOX, DeliveryTables::outboxConnection());
            self::assertTrue(Schema::connection(self::OUTBOX)->hasTable(self::OUTBOX_TABLE));
            self::assertFalse(Schema::connection(self::STORAGE)->hasTable(self::OUTBOX_TABLE));
            self::assertFalse(Schema::connection(self::CONNECTION)->hasTable(self::OUTBOX_TABLE));
        } finally {
            $this->migrate('migrate:rollback');
        }
    }

    /**
     * Moving the outbox leaves the deliveries and the entries on the storage
     * connection, and puts neither on the outbox connection.
     *
     * @return void
     */
    public function testTheDeliveriesStayOnTheStorageConnectionWhenTheOutboxMoves(): void
    {
        $this->moveTheOutbox();

        try {
            foreach ([self::ENTRIES_TABLE, self::DELIVERIES_TABLE] as $table) {
                self::assertTrue(Schema::connection(self::STORAGE)->hasTable($table), $table);
                self::assertFalse(Schema::connection(self::OUTBOX)->hasTable($table), $table);
            }
        } finally {
            $this->migrate('migrate:rollback');
        }
    }

    /**
     * Rolling the migrations back drops each table from the connection it was
     * created on, and running them again creates each there once more.
     *
     * @return void
     */
    public function testARollbackDropsEachFromItsConnection(): void
    {
        $this->moveTheOutbox();
        $this->migrate('migrate:rollback');

        self::assertFalse(Schema::connection(self::OUTBOX)->hasTable(self::OUTBOX_TABLE));

        foreach ([self::ENTRIES_TABLE, self::DELIVERIES_TABLE] as $table) {
            self::assertFalse(Schema::connection(self::STORAGE)->hasTable($table), $table);
        }

        $this->migrate('migrate');

        try {
            self::assertTrue(Schema::connection(self::OUTBOX)->hasTable(self::OUTBOX_TABLE));
            self::assertTrue(Schema::connection(self::STORAGE)->hasTable(self::DELIVERIES_TABLE));
        } finally {
            $this->migrate('migrate:rollback');
        }

        self::assertFalse(Schema::connection(self::OUTBOX)->hasTable(self::OUTBOX_TABLE));
        self::assertFalse(Schema::connection(self::STORAGE)->hasTable(self::DELIVERIES_TABLE));
    }

    /**
     * Put the package's tables on a second connection to the test database,
     * with a prefix of its own, and register the outbox connection the same
     * way.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config  = $app->make(ConfigRepository::class);
        $testing = $config->array('database.connections.' . self::CONNECTION);

        $config->set('database.connections.' . self::STORAGE, [...$testing, 'prefix' => 'store_']);
        $config->set('database.connections.' . self::OUTBOX, [...$testing, 'prefix' => 'outbox_']);
        $config->set('audit-log.storage.connection', self::STORAGE);
    }

    /**
     * Roll the migrations back from where the test case ran them, then run them
     * again with the outbox on its own connection.
     *
     * @return void
     */
    private function moveTheOutbox(): void
    {
        $this->migrate('migrate:rollback');

        config()->set('audit-log.delivery.outbox.connection', self::OUTBOX);

        $this->migrate('migrate');
    }

    /**
     * Run the migration command on the shipped migrations.
     *
     * @param  string  $command
     * @return void
     */
    private function migrate(string $command): void
    {
        self::assertSame(0, Artisan::call($command, ['--path' => realpath(self::MIGRATIONS), '--realpath' => true]));
    }
}
