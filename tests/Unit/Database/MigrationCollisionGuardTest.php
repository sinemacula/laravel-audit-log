<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\Schema\Builder;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Database\MigrationCollisionGuard;
use SineMacula\Laravel\AuditLog\Database\TableAlreadyExistsException;

/**
 * Unit tests for the migration collision guard on its own: it asks the schema
 * builder it is given whether the table exists, throws naming the table, the
 * builder's connection and the setting that renames the table when it does,
 * names an unnamed connection the default one, and returns silently when the
 * table is missing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MigrationCollisionGuard::class)]
final class MigrationCollisionGuardTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The guard throws when the table already exists on the builder's
     * connection, naming the table, the connection and the configuration key
     * that renames the table.
     *
     * @return void
     */
    public function testEnsureNotExistsThrowsWhenTableExists(): void
    {
        $schema = \Mockery::mock(Builder::class);
        $schema->shouldReceive('hasTable')
            ->once()
            ->with('audit_log_entries')
            ->andReturn(true);

        $connection = \Mockery::mock(Connection::class);
        $connection->shouldReceive('getName')
            ->once()
            ->andReturn('testing');

        $schema->shouldReceive('getConnection')
            ->once()
            ->andReturn($connection);

        $guard = new MigrationCollisionGuard($schema);

        $this->expectException(TableAlreadyExistsException::class);
        $this->expectExceptionMessage(
            'Cannot install the laravel-audit-log migration for the \'audit_log_entries\' table: a table with that name already exists on connection \'testing\'.'
            . ' Set `entries.table` in config/audit-log.php to a different name and re-run the migration.',
        );

        $guard->ensureNotExists('audit_log_entries', 'entries.table');
    }

    /**
     * The guard returns silently when the table is not present in the schema,
     * and never asks for the connection's name.
     *
     * @return void
     */
    public function testEnsureNotExistsSucceedsWhenTableMissing(): void
    {
        $schema = \Mockery::mock(Builder::class);
        $schema->shouldReceive('hasTable')
            ->once()
            ->with('audit_log_entries')
            ->andReturn(false);

        $schema->shouldNotReceive('getConnection');

        $guard = new MigrationCollisionGuard($schema);

        // ensureNotExists is `void` and the assertion lives in the Mockery
        // expectations: if hasTable was not called exactly once, or the
        // connection was asked for, Mockery fails the test in tearDown
        $guard->ensureNotExists('audit_log_entries', 'entries.table');
    }

    /**
     * The exception message echoes the table name and configuration key given
     * at runtime, and names the default connection when the connection has no
     * name, which the database manager never builds.
     *
     * @return void
     */
    public function testEnsureNotExistsNamesTheGivenTableAndKey(): void
    {
        $schema = \Mockery::mock(Builder::class);
        $schema->shouldReceive('hasTable')
            ->once()
            ->with('reporting_entries')
            ->andReturn(true);

        $connection = \Mockery::mock(Connection::class);
        $connection->shouldReceive('getName')
            ->andReturnNull();

        $schema->shouldReceive('getConnection')
            ->andReturn($connection);

        $guard = new MigrationCollisionGuard($schema);

        $this->expectException(TableAlreadyExistsException::class);
        $this->expectExceptionMessage('the \'reporting_entries\' table: a table with that name already exists on connection \'default\'. Set `custom.table`');

        $guard->ensureNotExists('reporting_entries', 'custom.table');
    }
}
