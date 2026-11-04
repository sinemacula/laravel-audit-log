<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Lifecycle\SqliteDeleteTriggers;
use Tests\Concerns\RunsDocumentedSql;
use Tests\Concerns\SealsEntries;
use Tests\TestCase;

/**
 * Feature tests for the delete triggers a prune drops and recreates on SQLite:
 * the text it recreates is the storage note's, word for word; only the triggers
 * installed are dropped and created again; a rollback restores them; and on any
 * other engine nothing runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SqliteDeleteTriggers::class)]
final class SqliteDeleteTriggersTest extends TestCase
{
    use MockeryPHPUnitIntegration, RunsDocumentedSql, SealsEntries;

    /** @var list<string> The two delete triggers a prune drops, as the storage note names them. */
    private const array TRIGGERS = ['audit_log_entries_no_delete', 'audit_log_artifacts_no_delete'];

    /** @var bool Whether this test installed the documented triggers. */
    private bool $installed = false;

    /**
     * Drop every documented trigger this test installed.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->installed) {
            $connection = $this->maintenance();

            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }

            self::dropDocumentedTriggers($connection);
        }

        parent::tearDown();
    }

    /**
     * The text recreated for the entries and the artifacts is the storage
     * note's text of their delete triggers, in the triggers block and in the
     * prune block alike.
     *
     * @return void
     */
    public function testTheRecreatedTextIsTheDocumentedText(): void
    {
        $triggers = self::documentedSql('sqlite-triggers');
        $prune    = self::documentedSql('sqlite-prune');

        foreach (['audit_log_entries', 'audit_log_artifacts'] as $table) {
            $statement = SqliteDeleteTriggers::statementFor($table);

            self::assertSame(1, substr_count($triggers, $statement), $table);
            self::assertSame(1, substr_count($prune, $statement), $table);
            self::assertStringStartsWith('CREATE TRIGGER ' . $table . '_no_delete BEFORE DELETE ON ' . $table . "\n", $statement);
            self::assertStringEndsWith("\nEND;", $statement);
        }

        self::assertStringContainsString("DROP TRIGGER audit_log_entries_no_delete;\nDROP TRIGGER audit_log_artifacts_no_delete;", $prune);
    }

    /**
     * Only the delete triggers installed are dropped, named in the order of the
     * entries and then the artifacts, and only those are created again; a
     * trigger that is not installed is neither dropped nor created.
     *
     * @return void
     */
    public function testOnlyPresentTriggersAreDroppedAndRecreated(): void
    {
        $connection = $this->sqlite();

        $this->installTriggers($connection);

        $connection->unprepared('DROP TRIGGER audit_log_artifacts_no_delete');

        $triggers = new SqliteDeleteTriggers;

        $connection->beginTransaction();

        self::assertSame(['audit_log_entries_no_delete'], $triggers->dropPresent($connection));
        self::assertSame([], $this->installedOf($connection));

        $triggers->recreate($connection, ['audit_log_entries_no_delete']);
        $connection->commit();

        self::assertSame(['audit_log_entries_no_delete'], $this->installedOf($connection));

        $connection->unprepared('DROP TRIGGER audit_log_entries_no_delete');

        self::assertSame([], $triggers->dropPresent($connection));
    }

    /**
     * Both triggers dropped inside a transaction that rolls back are installed
     * again, and refuse a delete as before.
     *
     * @return void
     */
    public function testARollbackRestoresTheTriggers(): void
    {
        $connection = $this->sqlite();

        $this->installTriggers($connection);

        $id = $this->storeEntries(1)[0];

        $connection->beginTransaction();

        self::assertSame(self::TRIGGERS, (new SqliteDeleteTriggers)->dropPresent($connection));
        self::assertSame(1, $connection->table(EntrySettings::table())->where('id', $id)->delete());

        $connection->rollBack();

        self::assertSame(self::TRIGGERS, $this->installedOf($connection));

        self::assertRefusedByATrigger(static function () use ($connection, $id): void {
            $connection->table(EntrySettings::table())->where('id', $id)->delete();
        }, 'audit_log_entries', 'DELETE');
    }

    /**
     * On any other engine nothing is asked, dropped or created.
     *
     * @return void
     */
    public function testOffSqliteNothingRuns(): void
    {
        $triggers = new SqliteDeleteTriggers;

        foreach (['mysql', 'mariadb', 'pgsql'] as $driver) {
            $connection = \Mockery::mock(Connection::class);

            $connection->allows('getDriverName')->andReturn($driver);
            $connection->shouldNotReceive('table', 'unprepared', 'statement', 'select');

            self::assertSame([], $triggers->dropPresent($connection), $driver);

            $triggers->recreate($connection, self::TRIGGERS);
        }
    }

    /**
     * Run the storage note's SQLite triggers on the connection, for this test
     * to drop again.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     */
    private function installTriggers(Connection $connection): void
    {
        self::runDocumentedSql($connection, 'sqlite-triggers', []);

        $this->installed = true;
    }

    /**
     * The delete triggers of the entries and the artifacts installed on the
     * connection, in that order.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return list<string>
     */
    private function installedOf(Connection $connection): array
    {
        $names   = [EntrySettings::table() . '_no_delete', EntrySettings::artifactsTable() . '_no_delete'];
        $present = $connection->table('sqlite_master')->where('type', 'trigger')->whereIn('name', $names)->pluck('name')->all();

        return array_values(array_filter($names, static fn (string $name): bool => in_array($name, $present, true)));
    }

    /**
     * The maintenance connection, when it is SQLite; the test is skipped on any
     * other engine.
     *
     * @return \Illuminate\Database\Connection
     */
    private function sqlite(): Connection
    {
        $connection = $this->maintenance();

        if ($connection->getDriverName() !== 'sqlite') {
            self::markTestSkipped('Only SQLite drops and recreates its delete triggers.');
        }

        return $connection;
    }

    /**
     * The maintenance connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function maintenance(): Connection
    {
        return DB::connection(StorageConnection::forMaintenance());
    }
}
