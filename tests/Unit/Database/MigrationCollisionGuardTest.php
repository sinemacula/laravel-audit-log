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
 * Unit tests for the migration collision guard on its own.
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
     * The guard throws when the table exists, naming the table, the connection
     * and the configuration key that renames it.
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

        // The Mockery expectations, checked in tearDown, are the assertion
        $guard->ensureNotExists('audit_log_entries', 'entries.table');
    }

    /**
     * The message names the table and key given, and the default connection
     * when the connection has no name.
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
