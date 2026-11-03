<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use Tests\TestCase;

/**
 * Integration tests for where the shipped integrity migrations, run by
 * Laravel's own `migrate` and `migrate:rollback` commands, create the
 * checkpoints, the checkpoint members and the integrity state tables: always on
 * the storage connection, beside the entries they describe, wherever the outbox
 * goes.
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
#[CoversClass(IntegrityTables::class)]
final class IntegrityMigrationsConnectionTest extends TestCase
{
    /** @var string The connection the package's tables live on. */
    private const string STORAGE = 'audit_store';

    /** @var string A connection the outbox may be moved to. */
    private const string OUTBOX = 'audit_outbox';

    /** @var string The shipped migrations, as `--path` takes them. */
    private const string MIGRATIONS = __DIR__ . '/../../../database/migrations';

    /** @var list<string> The integrity tables, under their default names. */
    private const array TABLES = ['audit_log_checkpoints', 'audit_log_checkpoint_members', 'audit_log_integrity_state'];

    /**
     * The integrity tables are created on the storage connection, beside the
     * entries, and on no other.
     *
     * @return void
     */
    public function testTheIntegrityTablesFollowTheStorageConnection(): void
    {
        self::assertSame(self::TABLES, [IntegrityTables::checkpointsTable(), IntegrityTables::membersTable(), IntegrityTables::stateTable()]);

        foreach (['audit_log_entries', ...self::TABLES] as $table) {
            self::assertTrue(Schema::connection(self::STORAGE)->hasTable($table), $table);
            self::assertFalse(Schema::connection(self::CONNECTION)->hasTable($table), $table);
            self::assertFalse(Schema::connection(self::OUTBOX)->hasTable($table), $table);
        }
    }

    /**
     * Moving the outbox leaves the integrity tables on the storage connection,
     * and puts none of them on the outbox connection.
     *
     * @return void
     */
    public function testTheyStayOnTheStorageConnectionWhenTheOutboxMoves(): void
    {
        $this->moveTheOutbox();

        try {
            self::assertTrue(Schema::connection(self::OUTBOX)->hasTable('audit_log_outbox'));

            foreach (self::TABLES as $table) {
                self::assertTrue(Schema::connection(self::STORAGE)->hasTable($table), $table);
                self::assertFalse(Schema::connection(self::OUTBOX)->hasTable($table), $table);
                self::assertFalse(Schema::connection(self::CONNECTION)->hasTable($table), $table);
            }
        } finally {
            $this->migrate('migrate:rollback');
        }
    }

    /**
     * Rolling the migrations back drops each integrity table from the storage
     * connection, and running them again creates each there once more.
     *
     * @return void
     */
    public function testARollbackDropsEachFromTheStorageConnection(): void
    {
        $this->migrate('migrate:rollback');

        foreach (self::TABLES as $table) {
            self::assertFalse(Schema::connection(self::STORAGE)->hasTable($table), $table);
        }

        $this->migrate('migrate');

        try {
            foreach (self::TABLES as $table) {
                self::assertTrue(Schema::connection(self::STORAGE)->hasTable($table), $table);
                self::assertFalse(Schema::connection(self::CONNECTION)->hasTable($table), $table);
            }
        } finally {
            $this->migrate('migrate:rollback');
        }

        foreach (self::TABLES as $table) {
            self::assertFalse(Schema::connection(self::STORAGE)->hasTable($table), $table);
        }
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
