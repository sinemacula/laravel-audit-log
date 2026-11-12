<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Filesystem\Factory;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\SQLiteBuilder;
use Illuminate\Database\SQLiteConnection;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\IntegrityChecks;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use Tests\TestCase;

/**
 * Feature tests for the integrity checks of `audit-log:check`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegrityChecks::class)]
final class IntegrityChecksTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string What a missing table is asked to be created by, after its name and connection. */
    private const string PUBLISH = '; publish and run the migrations (`vendor:publish --tag=audit-log-migrations`, then `migrate`).';

    /**
     * The shipped tables with no anchor configured have no problem.
     *
     * @return void
     */
    public function testAGoodInstallHasNoProblem(): void
    {
        self::assertSame([], $this->checks()->problems());
    }

    /**
     * Rows of `[the table's setting, the absent table it names, its label]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideMissingTables(): iterable
    {
        yield from [
            'the checkpoints'        => ['checkpoints_table', 'audit_absent_checkpoints', 'checkpoints'],
            'the checkpoint members' => ['members_table', 'audit_absent_members', 'checkpoint members'],
            'the integrity state'    => ['state_table', 'audit_absent_state', 'integrity state'],
        ];
    }

    /**
     * Each missing integrity table is the one problem, named by its label.
     *
     * @param  string  $setting
     * @param  string  $table
     * @param  string  $label
     * @return void
     */
    #[DataProvider('provideMissingTables')]
    public function testEachMissingTableIsNamedByItsLabel(string $setting, string $table, string $label): void
    {
        $this->config()->set('audit-log.integrity.' . $setting, $table);

        self::assertSame([sprintf('The %s table `%s` does not exist on connection [%s]', $label, $table, self::CONNECTION) . self::PUBLISH], $this->checks()->problems());
    }

    /**
     * Every table missing is listed, in the order checkpoints, members, state.
     *
     * @return void
     */
    public function testEveryMissingTableIsListed(): void
    {
        $this->config()->set([
            'audit-log.integrity.checkpoints_table' => 'audit_absent_checkpoints',
            'audit-log.integrity.members_table'     => 'audit_absent_members',
            'audit-log.integrity.state_table'       => 'audit_absent_state',
        ]);

        self::assertSame([
            'The checkpoints table `audit_absent_checkpoints` does not exist on connection [testing]' . self::PUBLISH,
            'The checkpoint members table `audit_absent_members` does not exist on connection [testing]' . self::PUBLISH,
            'The integrity state table `audit_absent_state` does not exist on connection [testing]' . self::PUBLISH,
        ], $this->checks()->problems());
    }

    /**
     * A table of the wrong shape is a problem, in that table's own words.
     *
     * @return void
     */
    public function testAWrongShapeIsAProblem(): void
    {
        Schema::connection(self::CONNECTION)->table(IntegrityTables::checkpointsTable(), static function (Blueprint $table): void {
            $table->string('notes')->nullable();
        });

        Schema::connection(self::CONNECTION)->table(IntegrityTables::stateTable(), static function (Blueprint $table): void {
            $table->string('owner')->nullable();
        });

        self::assertSame([
            'Column `notes` is not one the package writes, so no seal covers it.',
            'Column `owner` is not one the package writes.',
        ], $this->checks()->problems());
    }

    /**
     * Rows of `[the storage connection's configuration, or null]`.
     *
     * @return iterable<string, array{0: ?array{driver: string, database: string}}>
     */
    public static function provideUnusableConnections(): iterable
    {
        yield from [
            'not configured'        => [null],
            'an unsupported driver' => [['driver' => 'sqlsrv', 'database' => 'audit']],
            'a database not there'  => [['driver' => 'sqlite', 'database' => '/nowhere/audit.sqlite']],
        ];
    }

    /**
     * An unusable connection is left to `schema`; the disk is still checked.
     *
     * @param  ?array{driver: string, database: string}  $connection
     * @return void
     */
    #[DataProvider('provideUnusableConnections')]
    public function testAnUnusableConnectionIsLeftToTheSchemaSubject(?array $connection): void
    {
        $this->config()->set(['database.connections.unusable' => $connection, 'audit-log.storage.connection' => 'unusable']);

        self::assertSame([], $this->checks()->problems());

        $this->config()->set(['audit-log.integrity.anchor.driver' => 'disk', 'audit-log.integrity.anchor.disk' => 'anchors']);

        self::assertSame(['The disk [anchors] that `audit-log.integrity.anchor.disk` names is not configured in `filesystems.disks`.'], $this->checks()->problems());
    }

    /**
     * A failing statement is named by its exception class, never its message.
     *
     * @return void
     */
    public function testAnUnreadableConnectionIsNamedByItsClass(): void
    {
        $schema = \Mockery::mock(SQLiteBuilder::class);

        $schema->shouldReceive('hasTable')->andThrow(new QueryException('fake', 'select secret_column from audit_log_checkpoints', [], new \PDOException('denied')));

        $connection = \Mockery::mock(SQLiteConnection::class . '[getSchemaBuilder]', [new \PDO('sqlite::memory:'), '', '', ['driver' => 'sqlite', 'name' => 'fake']]);

        $connection->shouldReceive('getSchemaBuilder')->andReturn($schema);

        $this->config()->set(['database.connections.fake' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => ''], 'audit-log.storage.connection' => 'fake']);

        $this->app?->make(DatabaseManager::class)->extend('fake', static fn (): SQLiteConnection => $connection);

        $problems = $this->checks()->problems();

        self::assertSame(['The storage connection [fake] could not be read (Illuminate\Database\QueryException).'], $problems);
        self::assertStringNotContainsString('secret_column', implode(' ', $problems));
    }

    /**
     * With the `disk` driver the disk must be in `filesystems.disks`.
     *
     * @return void
     */
    public function testTheDiskMustBeConfigured(): void
    {
        $this->config()->set(['audit-log.integrity.anchor.driver' => 'disk', 'audit-log.integrity.anchor.disk' => 'anchors']);

        self::assertSame(['The disk [anchors] that `audit-log.integrity.anchor.disk` names is not configured in `filesystems.disks`.'], $this->checks()->problems());

        $this->config()->set('filesystems.disks.anchors', ['driver' => 'local', 'root' => '/tmp/anchors']);

        self::assertSame([], $this->checks()->problems());

        $this->config()->set(['audit-log.integrity.anchor.disk' => null, 'filesystems.default' => 'missing']);

        self::assertSame(['The disk [missing] that `audit-log.integrity.anchor.disk` names is not configured in `filesystems.disks`.'], $this->checks()->problems());
    }

    /**
     * A disk configured as a string is not configured.
     *
     * @return void
     */
    public function testADiskConfiguredAsAStringIsAProblem(): void
    {
        $this->config()->set(['audit-log.integrity.anchor.driver' => 'disk', 'audit-log.integrity.anchor.disk' => 'anchors', 'filesystems.disks.anchors' => 'local']);

        self::assertSame(['The disk [anchors] that `audit-log.integrity.anchor.disk` names is not configured in `filesystems.disks`.'], $this->checks()->problems());
    }

    /**
     * With no anchor configured no disk is checked.
     *
     * @return void
     */
    public function testTheNullAnchorChecksNoDisk(): void
    {
        $this->config()->set(['audit-log.integrity.anchor.driver' => 'null', 'audit-log.integrity.anchor.disk' => 'nowhere']);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * The table problems come first and the disk's last, in one list.
     *
     * @return void
     */
    public function testTheTablesAreListedBeforeTheDisk(): void
    {
        $this->config()->set([
            'audit-log.integrity.state_table'   => 'audit_absent_state',
            'audit-log.integrity.anchor.driver' => 'disk',
            'audit-log.integrity.anchor.disk'   => 'anchors',
        ]);

        self::assertSame([
            'The integrity state table `audit_absent_state` does not exist on connection [testing]' . self::PUBLISH,
            'The disk [anchors] that `audit-log.integrity.anchor.disk` names is not configured in `filesystems.disks`.',
        ], $this->checks()->problems());
    }

    /**
     * The disk is never resolved, read or written.
     *
     * @return void
     */
    public function testTheDiskIsNeverTouched(): void
    {
        $spy = \Mockery::mock(Factory::class);

        $spy->shouldReceive('disk')->never();

        $this->app?->instance(Factory::class, $spy);
        $this->app?->instance('filesystem', $spy);

        $this->config()->set(['audit-log.integrity.anchor.driver' => 'disk', 'audit-log.integrity.anchor.disk' => 'anchors']);

        self::assertCount(1, $this->checks()->problems());

        $this->config()->set('filesystems.disks.anchors', ['driver' => 'local', 'root' => '/tmp/anchors']);

        self::assertSame([], $this->checks()->problems());
    }

    /**
     * The checks as the container makes them for the command.
     *
     * @return \SineMacula\Laravel\AuditLog\Console\IntegrityChecks
     */
    private function checks(): IntegrityChecks
    {
        $checks = $this->app?->make(IntegrityChecks::class);

        assert($checks instanceof IntegrityChecks);

        return $checks;
    }

    /**
     * The application's configuration.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        return app(ConfigRepository::class);
    }
}
