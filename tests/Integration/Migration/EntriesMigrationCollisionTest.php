<?php

declare(strict_types = 1);

namespace Tests\Integration\Migration;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\TableAlreadyExistsException;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\TestCase;

/**
 * Integration tests for the entries migration's collision guard on every
 * engine, under a table name the test case never uses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MigrationCollisionGuard::class)]
final class EntriesMigrationCollisionTest extends TestCase
{
    /** @var string Absolute path to the shipped entries migration file. */
    private const string MIGRATION_PATH = __DIR__ . '/../../../database/migrations/2026_11_02_000000_create_audit_log_entries_table.php';

    /** @var string Configured table name the migration runs for. */
    private const string TABLE = 'audit_collision_entries';

    /**
     * Point the entries table at `TABLE`, on a connection without it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('audit-log.entries.table', self::TABLE);

        Schema::dropIfExists(self::TABLE);
    }

    /**
     * Drop the table the test created.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::TABLE);

        parent::tearDown();
    }

    /**
     * An existing table stops the migration, naming the setting.
     *
     * @return void
     */
    public function testAnExistingTableStopsTheMigrationNamingTheSettingThatRenamesIt(): void
    {
        Schema::create(self::TABLE, static function (Blueprint $blueprint): void {
            $blueprint->id();
        });

        $this->expectException(TableAlreadyExistsException::class);
        $this->expectExceptionMessage(
            'Cannot install the laravel-audit-log migration for the \'audit_collision_entries\' table: a table with that name already exists on connection \''
            . self::CONNECTION . '\'. Set `entries.table` in config/audit-log.php to a different name and re-run the migration.',
        );

        $this->runMigrationUp($this->loadMigration());
    }

    /**
     * The guard leaves an existing table as it was.
     *
     * @return void
     */
    public function testTheExistingTableIsLeftAsItWas(): void
    {
        Schema::create(self::TABLE, static function (Blueprint $blueprint): void {
            $blueprint->string('sentinel_column');
        });

        try {
            $this->runMigrationUp($this->loadMigration());
        } catch (TableAlreadyExistsException) { // @phpstan-ignore catch.neverThrown
            // Expected: the assertions below check what the guard left.
        }

        self::assertSame(['sentinel_column'], array_column(Schema::getColumns(self::TABLE), 'name'));
        self::assertSame([], Schema::getIndexes(self::TABLE));
    }

    /**
     * Without a collision the migration creates the configured table.
     *
     * @return void
     */
    public function testWithoutACollisionTheTableIsCreated(): void
    {
        $this->runMigrationUp($this->loadMigration());

        self::assertTrue(Schema::hasTable(self::TABLE));
        self::assertTrue(Schema::hasColumn(self::TABLE, 'hmac'));
        self::assertTrue(Schema::hasColumn(self::TABLE, 'source_record_id'));
        self::assertTrue(Schema::hasColumn(self::TABLE, 'source_digest'));
        self::assertSame(array_keys(RowCodec::COLUMNS), array_column(Schema::getColumns(self::TABLE), 'name'));
    }

    /**
     * Require the shipped migration file and return its instance.
     *
     * @return \Illuminate\Database\Migrations\Migration
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private function loadMigration(): Migration
    {
        $migration = include self::MIGRATION_PATH;

        if (!$migration instanceof Migration) {
            self::fail('Entries migration file did not return a Migration instance.');
        }

        return $migration;
    }

    /**
     * Run `up()`, which the `Migration` parent does not declare.
     *
     * @param  \Illuminate\Database\Migrations\Migration  $migration
     * @return void
     */
    private function runMigrationUp(Migration $migration): void
    {
        if (!method_exists($migration, 'up')) {
            self::fail('The migration has no `up()` method.');
        }

        $migration->up();
    }
}
