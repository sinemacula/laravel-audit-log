<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use Tests\TestCase;

/**
 * Integration tests for the connection `migrate` puts the key tables on; a
 * migration is an anonymous class, so they cover nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class KeyMigrationsConnectionTest extends TestCase
{
    /** @var string The connection the package's tables live on. */
    private const string STORAGE = 'audit_store';

    /** @var string The connection erasure and rewrapping run through. */
    private const string MAINTENANCE = 'audit_upkeep';

    /** @var string A connection the outbox may be moved to. */
    private const string OUTBOX = 'audit_outbox';

    /** @var string The shipped migrations, as `--path` takes them. */
    private const string MIGRATIONS = __DIR__ . '/../../../database/migrations';

    /** @var list<string> The key tables, under their default names. */
    private const array TABLES = ['audit_log_subject_keys', 'audit_log_owner_erasures', 'audit_log_key_uses'];

    /**
     * Each key table is created on the storage connection alone, with no row.
     *
     * @return void
     */
    public function testEachKeyTableIsOnTheStorageConnection(): void
    {
        foreach (['audit_log_entries', 'audit_log_lifecycle', ...self::TABLES] as $table) {
            self::assertTrue(Schema::connection(self::STORAGE)->hasTable($table), $table);
            self::assertFalse(Schema::connection(self::CONNECTION)->hasTable($table), $table);
            self::assertFalse(Schema::connection(self::MAINTENANCE)->hasTable($table), $table);
            self::assertFalse(Schema::connection(self::OUTBOX)->hasTable($table), $table);
        }

        foreach (self::TABLES as $table) {
            self::assertSame(0, Schema::connection(self::STORAGE)->getConnection()->table($table)->count(), $table);
        }

        $this->migrate('migrate:rollback');

        foreach (self::TABLES as $table) {
            self::assertFalse(Schema::connection(self::STORAGE)->hasTable($table), $table);
        }
    }

    /**
     * Moving the outbox leaves the key tables on the storage connection.
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
