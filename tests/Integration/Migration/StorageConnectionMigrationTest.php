<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use Tests\TestCase;

/**
 * Integration tests for the connection `migrate` puts the entries table on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageConnection::class)]
final class StorageConnectionMigrationTest extends TestCase
{
    /** @var string The connection the package's tables live on. */
    private const string STORAGE = 'audit_store';

    /** @var string A connection maintenance runs on. */
    private const string MAINTENANCE = 'audit_maintenance';

    /** @var string A connection a `--database` run puts the table on. */
    private const string CHOSEN = 'chosen';

    /** @var string The shipped migrations, as `--path` takes them. */
    private const string MIGRATIONS = __DIR__ . '/../../../database/migrations';

    /** @var string The table the migration creates. */
    private const string TABLE = 'audit_log_entries';

    /**
     * The table is created on the storage connection, not the default.
     *
     * @return void
     */
    public function testTheMigrationCreatesTheTableOnTheStorageConnection(): void
    {
        self::assertSame(self::STORAGE, StorageConnection::name());
        self::assertTrue(Schema::connection(self::STORAGE)->hasTable(self::TABLE));
        self::assertFalse(Schema::connection(self::CONNECTION)->hasTable(self::TABLE));
        self::assertSame(0, DB::connection(self::STORAGE)->table(self::TABLE)->count());
    }

    /**
     * A rollback drops the table from the storage connection.
     *
     * @return void
     */
    public function testARollbackDropsTheTableFromTheStorageConnection(): void
    {
        $this->migrate('migrate:rollback');

        self::assertFalse(Schema::connection(self::STORAGE)->hasTable(self::TABLE));

        $this->migrate('migrate');

        self::assertTrue(Schema::connection(self::STORAGE)->hasTable(self::TABLE));
        self::assertFalse(Schema::connection(self::CONNECTION)->hasTable(self::TABLE));
    }

    /**
     * With no storage connection named, the default connection is used.
     *
     * @return void
     */
    public function testWithoutAStorageConnectionTheDefaultConnectionIsUsed(): void
    {
        $this->migrate('migrate:rollback');

        config()->set('audit-log.storage.connection', null);

        $this->migrate('migrate');

        try {
            self::assertTrue(Schema::connection(self::CONNECTION)->hasTable(self::TABLE));
            self::assertFalse(Schema::connection(self::STORAGE)->hasTable(self::TABLE));
        } finally {
            $this->migrate('migrate:rollback');
        }

        self::assertFalse(Schema::connection(self::CONNECTION)->hasTable(self::TABLE));
    }

    /**
     * With no storage connection named, the migrator's `--database` is used.
     *
     * @return void
     */
    public function testWithoutAStorageConnectionTheMigratorsConnectionIsUsed(): void
    {
        $this->migrate('migrate:rollback');

        config()->set('audit-log.storage.connection', null);

        $this->migrate('migrate', ['--database' => self::CHOSEN]);

        try {
            self::assertTrue(Schema::connection(self::CHOSEN)->hasTable(self::TABLE));
            self::assertFalse(Schema::connection(self::STORAGE)->hasTable(self::TABLE));
            self::assertFalse(Schema::connection(self::CONNECTION)->hasTable(self::TABLE));
        } finally {
            $this->migrate('migrate:rollback', ['--database' => self::CHOSEN]);

            Schema::connection(self::CHOSEN)->dropIfExists('migrations');
        }

        self::assertFalse(Schema::connection(self::CHOSEN)->hasTable(self::TABLE));
    }

    /**
     * The maintenance connection never holds the table.
     *
     * @return void
     */
    public function testTheMaintenanceConnectionNeverHoldsTheTable(): void
    {
        $this->migrate('migrate:rollback');

        config()->set('audit-log.storage.maintenance_connection', self::MAINTENANCE);

        $this->migrate('migrate');

        self::assertSame(self::MAINTENANCE, StorageConnection::forMaintenance());
        self::assertTrue(Schema::connection(self::STORAGE)->hasTable(self::TABLE));
        self::assertFalse(Schema::connection(self::MAINTENANCE)->hasTable(self::TABLE));
    }

    /**
     * Prefix the other connections to the test database, each a database of its
     * own on in-memory SQLite, and put the package's tables on one.
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
        $config->set('database.connections.' . self::MAINTENANCE, [...$testing, 'prefix' => 'maintain_']);
        $config->set('database.connections.' . self::CHOSEN, [...$testing, 'prefix' => 'chosen_']);
        $config->set('audit-log.storage.connection', self::STORAGE);
    }

    /**
     * Run the migration command on the shipped migrations.
     *
     * @param  string  $command
     * @param  array<string, string>  $options
     * @return void
     */
    private function migrate(string $command, array $options = []): void
    {
        self::assertSame(0, Artisan::call($command, ['--path' => realpath(self::MIGRATIONS), '--realpath' => true, ...$options]));
    }
}
