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
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
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
 * Integration tests for sealing, anchoring and verification under the
 * documented grants alone, with no trigger, on MySQL and PostgreSQL.
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
     * Create this worker's logins, run the documented grants, and use the
     * writer as the storage connection with a stopped clock and a faked disk
     * anchor.
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
        self::createLogin($root, $this->names['audit_verifier']);
        self::runDocumentedGrants($root, $this->names);
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
            self::dropLogin($this->root(), $this->names['audit_verifier']);
        }

        parent::tearDown();
    }

    /**
     * The writer records, seals, anchors and strictly verifies, recording the
     * run's completion.
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
            InstallationIdentity::NAME,
            IntegrityProgress::SEAL_LAST,
            IntegrityProgress::SEAL_LAST_RUN,
            IntegrityProgress::SEAL_RECENT,
            IntegrityProgress::VERIFY_LAST_FULL,
        ];

        self::assertSame($progress, $this->progressNames());
    }

    /**
     * A sweep over several windows writes its cursor after each and deletes it
     * once complete.
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
     * The writer can change none of the 17 immutable checkpoint columns, while
     * an anchor column stays writable.
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
     * The writer can truncate none of the package's tables, though it may
     * delete the state's rows.
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
     * The writer reads the lifecycle journal and the holds but writes neither,
     * nor touches the lock.
     *
     * @return void
     */
    public function testTheWriterReadsTheJournalAndTheHolds(): void
    {
        $writer = $this->writer();
        $driver = $writer->getDriverName();

        $this->root()->table(LifecycleTables::journalTable())->insert(self::journalRow());

        self::assertSame(1, $writer->table(LifecycleTables::journalTable())->count());
        self::assertSame(0, $writer->table(LifecycleTables::holdsTable())->count());

        $refusals = [
            'insert a journal row' => static fn () => $writer->table(LifecycleTables::journalTable())->insert(self::journalRow(2)),
            'delete a journal row' => static fn () => $writer->table(LifecycleTables::journalTable())->delete(),
            'insert a hold'        => static fn () => $writer->table(LifecycleTables::holdsTable())->insert(['hold_id' => '01932b4e-9000-7000-8000-00000000f0f3']),
            'read the lock'        => static fn () => $writer->table(LifecycleTables::lockTable())->count(),
        ];

        foreach ($refusals as $what => $refusal) {
            self::assertRefusedByTheGrants($refusal, $driver, "The writer's attempt to {$what}");
        }

        self::assertSame(1, $this->root()->table(LifecycleTables::journalTable())->count());
    }

    /**
     * The maintenance user reads the evidence, deletes entries and receipts,
     * inserts journal rows, places and removes holds and takes the lock, and
     * nothing more.
     *
     * @return void
     */
    public function testTheMaintenanceUserIsGrantedExactlyItsDocumentedPrivileges(): void
    {
        $ids = $this->storeEntries(2);

        $this->runSeal();

        $maintenance = DB::connection(self::MAINTENANCE);
        $driver      = $maintenance->getDriverName();
        $entries     = $maintenance->table(EntrySettings::table());
        $journal     = $maintenance->table(LifecycleTables::journalTable());
        $copy        = ['id' => '01932b4e-8a40-7000-8000-00000000f0f0'] + (array) $this->root()->table(EntrySettings::table())->where('id', $ids[1])->first();

        self::assertSame(1, $maintenance->table(IntegrityTables::checkpointsTable())->count());
        self::assertSame(2, $maintenance->table(IntegrityTables::membersTable())->count());
        self::assertGreaterThan(0, $maintenance->table(IntegrityTables::stateTable())->count());
        self::assertSame(1, $entries->clone()->where('id', $ids[0])->delete());
        self::assertSame(0, $maintenance->table(DeliveryTables::deliveriesTable())->where('entry_id', $ids[0])->delete());
        self::assertTrue($journal->clone()->insert(self::journalRow()));
        self::assertTrue($maintenance->table(LifecycleTables::holdsTable())->insert(self::holdRow()));
        self::assertSame(1, $maintenance->table(LifecycleTables::holdsTable())->delete());
        $lock = ['token' => 'upkeep:0123456789abcdef', 'locked_at' => '2026-11-01 13:00:00.000000'];

        self::assertSame(1, $maintenance->table(LifecycleTables::lockTable())->where('id', 1)->update($lock));

        $refusals = [
            'insert an entry'      => static fn () => $entries->clone()->insert($copy),
            'update an entry'      => static fn () => $entries->clone()->where('id', $ids[1])->update(['outcome' => 'failure']),
            'delete a member'      => static fn () => $maintenance->table(IntegrityTables::membersTable())->delete(),
            'delete a seal'        => static fn () => $maintenance->table(IntegrityTables::checkpointsTable())->delete(),
            'write an anchor'      => static fn () => $maintenance->table(IntegrityTables::checkpointsTable())->update(['anchor_error_class' => \RuntimeException::class]),
            'update a journal row' => static fn () => $journal->clone()->update(['reason' => 'rewritten']),
            'delete a journal row' => static fn () => $journal->clone()->delete(),
            'insert a lock row'    => static fn () => $maintenance->table(LifecycleTables::lockTable())->insert(['id' => 2]),
            'truncate the entries' => static fn () => $maintenance->statement(sprintf('TRUNCATE TABLE %s', EntrySettings::table())),
            'write the state'      => static fn () => $maintenance->table(IntegrityTables::stateTable())->delete(),
        ];

        foreach ($refusals as $what => $refusal) {
            self::assertRefusedByTheGrants($refusal, $driver, "The maintenance user's attempt to {$what}");
        }

        self::assertSame([$ids[1]], $this->root()->table(EntrySettings::table())->pluck('id')->all());
        self::assertSame(2, $this->root()->table(IntegrityTables::membersTable())->count());
        self::assertSame(1, $this->root()->table(LifecycleTables::journalTable())->count());
    }

    /**
     * A bundle's artifact verifies on the maintenance user's connection, which
     * holds only `SELECT` and `DELETE` on the artifacts.
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
     * A journal row with every column a row must have, numbered so its id and
     * sequence are its own.
     *
     * @param  int  $number
     * @return array<string, int|string>
     */
    private static function journalRow(int $number = 1): array
    {
        return [
            'id'             => sprintf('01932b4e-9000-7000-8000-%012d', $number),
            'sequence'       => $number,
            'log_id'         => 'app-eu-1',
            'kind'           => 'policy',
            'operation_id'   => '01932b4e-9000-7000-8000-00000000aaaa',
            'occurred_at'    => '2026-11-01 13:00:00.000000',
            'payload'        => '{}',
            'payload_digest' => str_repeat('a', 64),
            'key_id'         => 'k2026',
            'hmac'           => str_repeat('b', 64),
        ];
    }

    /**
     * A hold with every column a hold must have.
     *
     * @return array<string, int|string>
     */
    private static function holdRow(): array
    {
        return [
            'hold_id'          => '01932b4e-9000-7000-8000-00000000f0f4',
            'scope'            => '{}',
            'scope_digest'     => str_repeat('a', 64),
            'basis'            => 'litigation',
            'placed_at'        => '2026-11-01 13:00:00.000000',
            'authority_type'   => 'operator',
            'authority_id'     => '7',
            'reason'           => 'legal_hold',
            'operation_id'     => '01932b4e-9000-7000-8000-00000000aaaa',
            'journal_sequence' => 1,
        ];
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
