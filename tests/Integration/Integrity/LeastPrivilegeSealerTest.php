<?php

declare(strict_types = 1);

namespace Tests\Integration\Integrity;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Integrity\Anchorer;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\Sealer;
use SineMacula\Laravel\AuditLog\Integrity\SegmentVerifier;
use SineMacula\Laravel\AuditLog\Integrity\VerificationContext;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use Tests\Concerns\RunsDocumentedSql;
use Tests\Concerns\SeedsArtifacts;
use Tests\Concerns\TampersWithTheLog;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Integration tests for sealing, anchoring and verification under the grants
 * the storage note documents, run exactly as written by the tables' owner, on
 * MySQL and PostgreSQL: a writer granted those privileges and nothing else
 * records, seals, anchors, verifies strictly and completes a sweep, which
 * forgets its cursor; a bundle's artifact is verified by a user granted only
 * `SELECT` on it; it cannot change an immutable checkpoint column, update or
 * delete a member, delete a seal, truncate any of the package's tables or run
 * any DDL; and the maintenance user may delete an entry and read the evidence,
 * and nothing more.
 *
 * Each worker creates logins of its own, `audit_writer_<token>` and
 * `audit_maintenance_<token>`, and drops them when the test ends. No trigger is
 * installed: the grants alone refuse each of these. SQLite has no privileges,
 * so these tests are skipped there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Sealer::class)]
#[CoversClass(Anchorer::class)]
#[CoversClass(Verifier::class)]
final class LeastPrivilegeSealerTest extends TestCase
{
    use RunsDocumentedSql, SeedsArtifacts, TampersWithTheLog;

    /** @var string The connection the writer's login uses, which is the storage connection. */
    private const string WRITER = 'audit_writer';

    /** @var string The connection the maintenance user's login uses. */
    private const string MAINTENANCE = 'audit_maintenance';

    /** @var string When the entries are sealed and verified: within the allowed age of every entry. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string The clock a segment is verified at directly, at which every grace ends. */
    private const string RUN_CLOCK = '2026-11-02T00:00:00.000000Z';

    /** @var array<string, string> The names this worker gives the placeholders, once its logins exist. */
    private array $names = [];

    /**
     * Create this worker's logins, run the documented grants for them as the
     * tables' owner, make the writer's connection the storage connection,
     * register both commands, stop the clock and anchor to a faked disk, on
     * MySQL and PostgreSQL only.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $root = $this->root();

        if ($root->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite has no logins or privileges.');
        }

        $this->names = self::documentedNames($root);

        self::createLogin($root, $this->names['audit_writer']);
        self::createLogin($root, $this->names['audit_maintenance']);
        self::runDocumentedSql($root, $root->getDriverName() . '-grants', $this->names);
        self::connectAs(self::WRITER, self::CONNECTION, $this->names['audit_writer']);
        self::connectAs(self::MAINTENANCE, self::CONNECTION, $this->names['audit_maintenance']);

        app(ConfigRepository::class)->set('audit-log.storage.connection', self::WRITER);
        app()->instance(Clock::class, FrozenClock::at(self::SEALED_AT));

        $this->registerIntegrityCommands();
        $this->sealAt(self::SEALED_AT);
        $this->useDiskAnchor();
    }

    /**
     * Close the logins' connections and drop the logins.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->names !== []) {

            foreach ([self::WRITER, self::MAINTENANCE] as $connection) {
                $this->rollBack(DB::connection($connection));

                DB::purge($connection);
            }

            self::dropLogin($this->root(), $this->names['audit_writer']);
            self::dropLogin($this->root(), $this->names['audit_maintenance']);
        }

        parent::tearDown();
    }

    /**
     * The writer records through the store, `audit-log:seal` seals and anchors
     * what it recorded, and a strict `audit-log:verify` passes and records its
     * completion in the integrity state table.
     *
     * @return void
     */
    public function testAWriterGrantedExactlyTheDocumentedPrivilegesSealsAnchorsAndVerifies(): void
    {
        $this->storeEntries(3);

        self::assertSame(0, $this->runSeal()[0]);

        $seals = $this->seals();

        self::assertCount(1, $seals);
        self::assertSame(3, (int) $seals[0]['member_count']);
        self::assertNotNull($seals[0]['anchored_at']);
        self::assertSame(0, $this->verify(['--strict' => true])[0]);

        $progress = [
            IntegrityProgress::ANCHOR_LAST,
            IntegrityProgress::SEAL_LAST,
            IntegrityProgress::SEAL_LAST_RUN,
            IntegrityProgress::SEAL_RECENT,
            IntegrityProgress::VERIFY_LAST_FULL,
        ];

        self::assertSame($progress, $this->progressNames());
    }

    /**
     * A sweep over more than one window seals every entry, writes its cursor
     * after each window and, once complete, forgets it, which is the state
     * table's `DELETE`; a second sweep completes again from the beginning.
     *
     * @return void
     */
    public function testAWriterGrantedExactlyTheDocumentedPrivilegesCompletesASweep(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.seal.batch', 100);

        $this->storeEntries(150);

        $kernel = app(Kernel::class);

        self::assertSame(0, $kernel->call('audit-log:seal', ['--sweep' => true]));
        self::assertSame(150, $this->root()->table(IntegrityTables::membersTable())->count());
        self::assertNotContains(IntegrityProgress::SWEEP_CURSOR, $this->progressNames());
        self::assertContains(IntegrityProgress::SWEEP_COMPLETED, $this->progressNames());
        self::assertSame(0, $kernel->call('audit-log:seal', ['--sweep' => true]));
        self::assertNotContains(IntegrityProgress::SWEEP_CURSOR, $this->progressNames());
        self::assertSame(2, $this->root()->table(IntegrityTables::checkpointsTable())->count());
    }

    /**
     * The writer can change none of the 15 immutable checkpoint columns, each
     * refused by the column grants, while an anchor column stays writable; the
     * seal is left as it was.
     *
     * @return void
     */
    public function testTheWriterCannotChangeAnImmutableCheckpointColumn(): void
    {
        $this->storeEntries(2);
        $this->runSeal();

        $writer = $this->writer();
        $seal   = $writer->table(IntegrityTables::checkpointsTable())->where('sequence', 1);
        $before = $this->root()->table(IntegrityTables::checkpointsTable())->first();

        foreach (self::IMMUTABLE_COLUMNS as $column => $value) {
            self::assertRefusedByTheGrants(static fn () => $seal->clone()->update([$column => $value]), $writer->getDriverName(), "The writer's update of {$column}");
        }

        self::assertEquals($before, $this->root()->table(IntegrityTables::checkpointsTable())->first());
        self::assertSame(1, $seal->clone()->update(['anchor_error_class' => \RuntimeException::class]));
    }

    /**
     * The writer can neither update nor delete a member, nor delete a seal, and
     * every member and seal stays.
     *
     * @return void
     */
    public function testTheWriterCannotDeleteAMemberOrACheckpoint(): void
    {
        $this->storeEntries(2);
        $this->runSeal();

        $writer  = $this->writer();
        $driver  = $writer->getDriverName();
        $members = $writer->table(IntegrityTables::membersTable());
        $seals   = $writer->table(IntegrityTables::checkpointsTable());

        self::assertRefusedByTheGrants(static fn () => $members->clone()->delete(), $driver, 'The writer\'s delete of a member');
        self::assertRefusedByTheGrants(static fn () => $members->clone()->update(['hmac' => str_repeat('e', 64)]), $driver, 'The writer\'s update of a member');
        self::assertRefusedByTheGrants(static fn () => $seals->clone()->delete(), $driver, 'The writer\'s delete of a seal');
        self::assertSame(2, $this->root()->table(IntegrityTables::membersTable())->count());
        self::assertSame(1, $this->root()->table(IntegrityTables::checkpointsTable())->count());
    }

    /**
     * The writer can truncate none of the entries, the checkpoints, the members
     * or the integrity state, though it may delete the state's rows: every row
     * stays.
     *
     * @return void
     */
    public function testTheWriterCannotTruncateAnyIntegrityTable(): void
    {
        $this->storeEntries(2);
        $this->runSeal();

        $writer = $this->writer();
        $tables = [EntrySettings::table(), IntegrityTables::checkpointsTable(), IntegrityTables::membersTable(), IntegrityTables::stateTable()];

        foreach ($tables as $table) {
            $count = $this->root()->table($table)->count();

            self::assertGreaterThan(0, $count, $table);
            self::assertRefusedByTheGrants(static fn () => $writer->statement(sprintf('TRUNCATE TABLE %s', $table)), $writer->getDriverName(), "The writer's truncate of {$table}");
            self::assertSame($count, $this->root()->table($table)->count(), $table);
        }
    }

    /**
     * The writer can create no table, index or trigger, and alter or drop no
     * table, and the schema is left as it was.
     *
     * @return void
     */
    public function testTheWriterCannotRunDdl(): void
    {
        $writer  = $this->writer();
        $driver  = $writer->getDriverName();
        $entries = EntrySettings::table();
        $columns = Schema::connection(self::CONNECTION)->getColumnListing($entries);
        $trigger = $driver === 'mysql'
            ? sprintf('CREATE TRIGGER audit_log_intruder BEFORE INSERT ON %s FOR EACH ROW SET NEW.reason = NULL', $entries)
            : sprintf('CREATE TRIGGER audit_log_intruder BEFORE UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION suppress_redundant_updates_trigger()', $entries);

        $statements = [
            'create a table'   => 'CREATE TABLE audit_log_intruders (id integer)',
            'alter a table'    => sprintf('ALTER TABLE %s ADD COLUMN intruder integer', $entries),
            'drop a table'     => sprintf('DROP TABLE %s', IntegrityTables::membersTable()),
            'create an index'  => sprintf('CREATE INDEX audit_log_intruder_index ON %s (event)', $entries),
            'create a trigger' => $trigger,
        ];

        foreach ($statements as $what => $statement) {
            self::assertRefusedByTheGrants(static fn () => $writer->statement($statement), $driver, "The writer's attempt to {$what}");
        }

        self::assertFalse(Schema::connection(self::CONNECTION)->hasTable('audit_log_intruders'));
        self::assertTrue(Schema::connection(self::CONNECTION)->hasTable(IntegrityTables::membersTable()));
        self::assertSame($columns, Schema::connection(self::CONNECTION)->getColumnListing($entries));
    }

    /**
     * The maintenance user reads the entries, the seals and the members and
     * deletes an entry, as a prune does; it can insert or update no entry,
     * delete no member or seal, write no anchor column, truncate no table and
     * read no progress.
     *
     * @return void
     */
    public function testTheMaintenanceUserIsGrantedOnlyTheEntriesDelete(): void
    {
        $ids = $this->storeEntries(2);

        $this->runSeal();

        $maintenance = DB::connection(self::MAINTENANCE);
        $driver      = $maintenance->getDriverName();
        $entries     = $maintenance->table(EntrySettings::table());
        $copy        = ['id' => '01932b4e-8a40-7000-8000-00000000f0f0'] + (array) $this->root()->table(EntrySettings::table())->where('id', $ids[1])->first();

        self::assertSame(1, $maintenance->table(IntegrityTables::checkpointsTable())->count());
        self::assertSame(2, $maintenance->table(IntegrityTables::membersTable())->count());
        self::assertSame(1, $entries->clone()->where('id', $ids[0])->delete());

        $refusals = [
            'insert an entry'      => static fn () => $entries->clone()->insert($copy),
            'update an entry'      => static fn () => $entries->clone()->where('id', $ids[1])->update(['outcome' => 'failure']),
            'delete a member'      => static fn () => $maintenance->table(IntegrityTables::membersTable())->delete(),
            'delete a seal'        => static fn () => $maintenance->table(IntegrityTables::checkpointsTable())->delete(),
            'write an anchor'      => static fn () => $maintenance->table(IntegrityTables::checkpointsTable())->update(['anchor_error_class' => \RuntimeException::class]),
            'truncate the entries' => static fn () => $maintenance->statement(sprintf('TRUNCATE TABLE %s', EntrySettings::table())),
            'read the progress'    => static fn () => $maintenance->table(IntegrityTables::stateTable())->count(),
        ];

        foreach ($refusals as $what => $refusal) {
            self::assertRefusedByTheGrants($refusal, $driver, "The maintenance user's attempt to {$what}");
        }

        self::assertSame([$ids[1]], $this->root()->table(EntrySettings::table())->pluck('id')->all());
        self::assertSame(2, $this->root()->table(IntegrityTables::membersTable())->count());
    }

    /**
     * A bundle the writer stores is sealed and verified strictly, and its
     * segment, artifact included, verifies on the maintenance user's
     * connection, which holds no privilege on the artifacts but `SELECT` and
     * `DELETE`, and no `INSERT` it could have used.
     *
     * @return void
     */
    public function testVerificationReadsArtifactsWithOnlySelect(): void
    {
        $this->storeEntries(1);

        $entryId = $this->seedBundle();

        self::assertSame(0, $this->runSeal()[0]);
        self::assertSame(0, $this->verify(['--strict' => true])[0]);

        $maintenance = DB::connection(self::MAINTENANCE);
        $artifact    = $this->root()->table(EntrySettings::artifactsTable())->where('entry_id', $entryId)->first();
        $copy        = ['id' => '01932b4e-8a40-7000-8000-00000000f0f1', 'entry_id' => '01932b4e-8a40-7000-8000-00000000f0f2'] + (array) $artifact;

        $insert = static fn () => $maintenance->table(EntrySettings::artifactsTable())->insert($copy);

        self::assertRefusedByTheGrants($insert, $maintenance->getDriverName(), 'The maintenance user\'s insert of an artifact');

        app(ConfigRepository::class)->set('audit-log.storage.connection', self::MAINTENANCE);

        $seal   = (array) $maintenance->table(IntegrityTables::checkpointsTable())->where('sequence', 1)->first();
        $report = app(SegmentVerifier::class)->verify($seal, 1, null, new VerificationContext(null, true, self::RUN_CLOCK, self::RUN_CLOCK));

        self::assertSame(IntegrityStatus::VALID, $report->integrity);
        self::assertNull($report->finding);
        self::assertSame(2, $report->members);
    }

    /**
     * The names of the progress the integrity state table holds, sorted.
     *
     * @return list<string>
     */
    private function progressNames(): array
    {
        /** @var list<string> $names */
        $names = $this->root()->table(IntegrityTables::stateTable())->pluck('name')->all();

        sort($names);

        return $names;
    }

    /**
     * Roll back every transaction left open on the connection.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     */
    private function rollBack(Connection $connection): void
    {
        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }
    }

    /**
     * The writer's connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function writer(): Connection
    {
        return DB::connection(self::WRITER);
    }

    /**
     * The worker's own connection, as the tables' owner.
     *
     * @return \Illuminate\Database\Connection
     */
    private function root(): Connection
    {
        return DB::connection(self::CONNECTION);
    }
}
