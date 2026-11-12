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
 * Integration tests for the connections `migrate` puts the delivery tables on.
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
     * With no outbox connection named, the outbox is on the storage connection.
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
     * A named outbox connection holds the outbox.
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
     * Moving the outbox leaves the deliveries on the storage connection.
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
     * A rollback drops each table from its own connection.
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
        $config->set('database.connections.' . self::OUTBOX, [...$testing, 'prefix' => 'outbox_']);
        $config->set('audit-log.storage.connection', self::STORAGE);
    }

    /**
     * Migrate again with the outbox on its own connection.
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
