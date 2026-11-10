<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use Tests\TestCase;

/**
 * Integration tests for where the shipped lifecycle migrations, run by
 * Laravel's own `migrate` and `migrate:rollback` commands, create the journal,
 * the holds, the lock and the import batches: always on the storage connection,
 * beside the entries and the seals they describe, never on the default
 * connection, the maintenance connection or wherever the outbox goes, with the
 * lock's one row seeded there.
 *
 * The storage, the maintenance and the outbox connections are further
 * connections to the test database, each with a table prefix of its own: a
 * database of its own on SQLite, where each in-memory connection has one, and
 * prefixed tables beside the default connection's on PostgreSQL and MySQL.
 *
 * Marked `#[CoversNothing]` because a migration is an anonymous class PHPUnit
 * cannot attribute coverage to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class LifecycleMigrationsConnectionTest extends TestCase
{
    /** @var string The connection the package's tables live on. */
    private const string STORAGE = 'audit_store';

    /** @var string The connection pruning, holds and the journal run through. */
    private const string MAINTENANCE = 'audit_upkeep';

    /** @var string A connection the outbox may be moved to. */
    private const string OUTBOX = 'audit_outbox';

    /** @var string The shipped migrations, as `--path` takes them. */
    private const string MIGRATIONS = __DIR__ . '/../../../database/migrations';

    /** @var list<string> The lifecycle tables, under their default names. */
    private const array TABLES = ['audit_log_lifecycle', 'audit_log_holds', 'audit_log_lifecycle_lock', 'audit_log_import_batches'];

    /**
     * The lifecycle tables are created on the storage connection, beside the
     * entries and the seals, and on no other, the maintenance connection
     * included; the lock's one row is seeded there.
     *
     * @return void
     */
    public function testTheLifecycleTablesFollowTheStorageConnection(): void
    {
        foreach (['audit_log_entries', 'audit_log_checkpoints', ...self::TABLES] as $table) {
            self::assertTrue(Schema::connection(self::STORAGE)->hasTable($table), $table);
            self::assertFalse(Schema::connection(self::CONNECTION)->hasTable($table), $table);
            self::assertFalse(Schema::connection(self::MAINTENANCE)->hasTable($table), $table);
            self::assertFalse(Schema::connection(self::OUTBOX)->hasTable($table), $table);
        }

        $ids = array_map(static function (mixed $id): int {
            self::assertIsNumeric($id);

            return (int) $id;
        }, DB::connection(self::STORAGE)->table('audit_log_lifecycle_lock')->pluck('id')->all());

        self::assertSame([1], $ids);
    }

    /**
     * Moving the outbox leaves the lifecycle tables on the storage connection,
     * and puts none of them on the outbox connection.
     *
     * @return void
     */
    public function testTheyStayOnTheStorageConnectionWhenTheOutboxMoves(): void
    {
        $this->migrate('migrate:rollback');

        config()->set('audit-log.delivery.outbox.connection', self::OUTBOX);

        $this->migrate('migrate');

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
     * Rolling the migrations back drops each lifecycle table from the storage
     * connection, and running them again creates each there once more, the lock
     * seeded again with its one row.
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

            self::assertSame(1, DB::connection(self::STORAGE)->table('audit_log_lifecycle_lock')->count());
        } finally {
            $this->migrate('migrate:rollback');
        }

        foreach (self::TABLES as $table) {
            self::assertFalse(Schema::connection(self::STORAGE)->hasTable($table), $table);
        }
    }

    /**
     * Put the package's tables on a second connection to the test database,
     * with a prefix of its own, name a maintenance connection of its own, and
     * register the outbox connection the same way.
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
        $config->set('database.connections.' . self::MAINTENANCE, [...$testing, 'prefix' => 'upkeep_']);
        $config->set('database.connections.' . self::OUTBOX, [...$testing, 'prefix' => 'outbox_']);
        $config->set('audit-log.storage.connection', self::STORAGE);
        $config->set('audit-log.storage.maintenance_connection', self::MAINTENANCE);
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
