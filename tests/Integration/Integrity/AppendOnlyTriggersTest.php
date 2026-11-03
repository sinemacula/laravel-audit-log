<?php

declare(strict_types = 1);

namespace Tests\Integration\Integrity;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use Tests\Concerns\RunsDocumentedSql;
use Tests\Concerns\TampersWithTheLog;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Integration tests for the triggers the storage note documents, run exactly as
 * written on whichever engine the suite runs against: they install, refuse an
 * update of an entry, an artifact or a member, a change to any immutable
 * checkpoint column and a delete of a member or a seal, allow the anchor
 * columns, refuse a delete of an entry or an artifact by anyone but the
 * maintenance user (on SQLite by anyone), let the maintenance user delete one,
 * refuse a `TRUNCATE` on PostgreSQL, leave the integrity state table alone, and
 * leave sealing, anchoring, the sweep and verification working; the documented
 * SQLite prune deletes and restores its triggers, an entry's artifact with it,
 * and a failed one rolled back keeps them.
 *
 * On MySQL and PostgreSQL the documented grants are run too, for the logins
 * this worker creates, `audit_writer_<token>` and `audit_maintenance_<token>`,
 * which are dropped when the test ends, as the triggers are, and they limit
 * what each login does to an artifact. The tests cover documented SQL, not a
 * class of the package.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class AppendOnlyTriggersTest extends TestCase
{
    use RunsDocumentedSql, TampersWithTheLog;

    /** @var string The connection the writer's login uses. */
    private const string WRITER = 'audit_writer';

    /** @var string The connection the maintenance user's login uses. */
    private const string MAINTENANCE = 'audit_maintenance';

    /** @var string When the log is sealed. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When every command runs: past the anchoring grace of every seal, and within the allowed age of every entry. */
    private const string VERIFIED_AT = '2026-11-01 14:00:00';

    /** @var string The id an artifact a test stores is given, its number replacing `%012d`. */
    private const string ARTIFACT_ID = '01932b4e-9000-7000-8000-%012d';

    /** @var array<string, string> The names this worker gives the placeholders, once its logins exist. */
    private array $names = [];

    /** @var list<string> Logins a test creates beyond the documented two, dropped when it ends. */
    private array $logins = [];

    /**
     * Register both commands, stop the clock when every command runs, seal at a
     * fixed time, then run the documented grants for this worker's logins,
     * where the engine has users, and the documented triggers.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->registerIntegrityCommands();

        app()->instance(Clock::class, FrozenClock::at(self::VERIFIED_AT));

        $this->sealAt(self::SEALED_AT);

        $root = $this->root();

        if ($root->getDriverName() !== 'sqlite') {
            $this->createDocumentedLogins($root);
        }

        self::runDocumentedSql($root, $root->getDriverName() . '-triggers', $this->names);
    }

    /**
     * Drop the documented triggers, close the logins' connections and drop the
     * logins.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $root = $this->root();

        self::dropDocumentedTriggers($root);

        if ($this->names !== []) {
            DB::purge(self::WRITER);
            DB::purge(self::MAINTENANCE);

            foreach ([$this->names['audit_writer'], $this->names['audit_maintenance'], ...$this->logins] as $login) {
                self::dropLogin($root, $login);
            }
        }

        parent::tearDown();
    }

    /**
     * Every documented trigger is installed, and no other, and on PostgreSQL
     * the two functions they call.
     *
     * @return void
     */
    public function testTheDocumentedTriggersInstall(): void
    {
        $root     = $this->root();
        $sql      = self::documentedSql($root->getDriverName() . '-triggers');
        $expected = array_keys(self::documentedTriggers($sql));

        sort($expected);

        self::assertSame($expected, $this->installedTriggers($root));

        if ($root->getDriverName() !== 'pgsql') {
            return;
        }

        $functions = $root->table('pg_proc')->whereIn('proname', self::documentedFunctions($sql))->orderBy('proname')->pluck('proname')->all();

        self::assertSame(['audit_log_refuse', 'audit_log_refuse_delete'], $functions);
    }

    /**
     * An entry is never updated, even by the tables' owner, and is left as it
     * was.
     *
     * @return void
     */
    public function testAnEntryUpdateIsRefused(): void
    {
        $entry   = $this->sealedLog()[0];
        $entries = $this->root()->table(EntrySettings::table());

        self::assertRefusedByATrigger(static fn () => $entries->clone()->where('id', $entry)->update(['outcome' => 'failure']), EntrySettings::table(), 'UPDATE');
        self::assertSame('success', $entries->clone()->where('id', $entry)->value('outcome'));
    }

    /**
     * Rows of `[column, value]`: each artifact column changed to a value no
     * stored artifact has.
     *
     * @return iterable<string, array{0: string, 1: int|string}>
     */
    public static function provideArtifactColumns(): iterable
    {
        yield from [
            'id'           => ['id', sprintf(self::ARTIFACT_ID, 999)],
            'entry_id'     => ['entry_id', '01932b4e-8a40-7000-8000-00000000ffff'],
            'kind'         => ['kind', 'other'],
            'member_count' => ['member_count', 99],
            'digest'       => ['digest', str_repeat('e', 64)],
            'members'      => ['members', 'eyJpdiI6ImFub3RoZXIifQ=='],
            'created_at'   => ['created_at', '2026-01-01 00:00:00.000000'],
        ];
    }

    /**
     * A change to any column of an artifact is refused, even by the tables'
     * owner, and the artifact is left as it was.
     *
     * @param  string  $column
     * @param  int|string  $value
     * @return void
     */
    #[DataProvider('provideArtifactColumns')]
    public function testAnArtifactUpdateIsRefused(string $column, int|string $value): void
    {
        $artifact  = $this->storeArtifact(1, $this->sealedLog()[0]);
        $artifacts = $this->root()->table(EntrySettings::artifactsTable());
        $before    = $artifacts->clone()->where('id', $artifact)->first();

        self::assertNotNull($before);
        self::assertRefusedByATrigger(static fn () => $artifacts->clone()->where('id', $artifact)->update([$column => $value]), EntrySettings::artifactsTable(), 'UPDATE');
        self::assertEquals($before, $artifacts->clone()->where('id', $artifact)->first());
    }

    /**
     * A delete of an artifact by the tables' owner is refused, and on MySQL and
     * PostgreSQL so is one by the writer granted `DELETE` beyond the documented
     * grants, while the maintenance user deletes it, as a prune does, and the
     * entries, the other artifact, every member and every seal stay.
     *
     * @return void
     */
    public function testAnArtifactDeleteIsRefusedButForTheMaintenanceUser(): void
    {
        $entries = $this->sealedLog();
        $root    = $this->root();
        $table   = EntrySettings::artifactsTable();
        $first   = $this->storeArtifact(1, $entries[0]);

        $this->storeArtifact(2, $entries[1]);

        self::assertRefusedByATrigger(static fn () => $root->table($table)->where('id', $first)->delete(), $table, 'DELETE');

        if ($this->names === []) {
            self::assertSame(2, $root->table($table)->count());

            return;
        }

        $root->statement($root->getDriverName() === 'mysql'
            ? sprintf('GRANT DELETE ON `%s`.`%s` TO \'%s\'@\'%%\'', $this->names['app_db'], $table, $this->names['audit_writer'])
            : sprintf('GRANT DELETE ON "%s" TO "%s"', $table, $this->names['audit_writer']));

        $writer = DB::connection(self::WRITER);

        self::assertRefusedByATrigger(static fn () => $writer->table($table)->where('id', $first)->delete(), $table, 'DELETE');
        self::assertSame(2, $root->table($table)->count());
        self::assertSame(1, DB::connection(self::MAINTENANCE)->table($table)->where('id', $first)->delete());
        self::assertFalse($root->table($table)->where('id', $first)->exists());
        self::assertSame(1, $root->table($table)->count());
        self::assertSame(4, $root->table(EntrySettings::table())->count());
        self::assertSame(4, $root->table(IntegrityTables::membersTable())->count());
        self::assertSame(2, $root->table(IntegrityTables::checkpointsTable())->count());
    }

    /**
     * On MySQL and PostgreSQL the documented grants let the writer read and
     * insert an artifact and nothing more, and the maintenance user read one
     * but never update it: the engine, not a trigger, refuses the rest.
     *
     * @return void
     */
    public function testTheGrantsLimitWhatEachUserDoesToAnArtifact(): void
    {
        $this->skipOnSqlite();

        $entry       = $this->sealedLog()[0];
        $driver      = $this->root()->getDriverName();
        $table       = EntrySettings::artifactsTable();
        $writer      = DB::connection(self::WRITER)->table($table);
        $maintenance = DB::connection(self::MAINTENANCE)->table($table);
        $artifact    = sprintf(self::ARTIFACT_ID, 1);
        $digest      = self::artifactRow(1, $entry)['digest'];
        $change      = ['digest' => str_repeat('e', 64)];

        self::assertTrue($writer->clone()->insert(self::artifactRow(1, $entry)));
        self::assertSame($digest, $writer->clone()->where('id', $artifact)->value('digest'));
        self::assertSame($digest, $maintenance->clone()->where('id', $artifact)->value('digest'));

        self::assertRefusedByTheGrants(static fn () => $writer->clone()->where('id', $artifact)->update($change), $driver, 'The writer\'s update of an artifact');
        self::assertRefusedByTheGrants(static fn () => $writer->clone()->where('id', $artifact)->delete(), $driver, 'The writer\'s delete of an artifact');
        self::assertRefusedByTheGrants(static fn () => $maintenance->clone()->where('id', $artifact)->update($change), $driver, 'The maintenance user\'s update of an artifact');
        self::assertSame($digest, $this->root()->table($table)->where('id', $artifact)->value('digest'));
    }

    /**
     * A member is never updated or deleted, even by the tables' owner, and
     * every member is left as it was.
     *
     * @return void
     */
    public function testAMemberUpdateAndDeleteAreRefused(): void
    {
        $entry   = $this->sealedLog()[0];
        $members = $this->root()->table(IntegrityTables::membersTable());
        $before  = $members->clone()->orderBy('entry_id')->get()->all();

        $hmac = str_repeat('e', 64);

        self::assertRefusedByATrigger(static fn () => $members->clone()->where('entry_id', $entry)->update(['hmac' => $hmac]), IntegrityTables::membersTable(), 'UPDATE');
        self::assertRefusedByATrigger(static fn () => $members->clone()->where('entry_id', $entry)->delete(), IntegrityTables::membersTable(), 'DELETE');
        self::assertEquals($before, $members->clone()->orderBy('entry_id')->get()->all());
    }

    /**
     * Rows of `[column, value, sequence]`: each immutable checkpoint column
     * changed to a value no stored seal has, on the genesis seal, whose
     * previous fields are null, and those fields of the next seal made null.
     *
     * @return iterable<string, array{0: string, 1: int|string|null, 2: int}>
     */
    public static function provideImmutableColumns(): iterable
    {
        foreach (self::IMMUTABLE_COLUMNS as $column => $value) {
            yield $column => [$column, $value, 1];
        }

        yield from [
            'previous_id made null'     => ['previous_id', null, 2],
            'previous_digest made null' => ['previous_digest', null, 2],
        ];
    }

    /**
     * A change to any immutable checkpoint column is refused, even by the
     * tables' owner and from or to null, and the seal is left as it was.
     *
     * @param  string  $column
     * @param  int|string|null  $value
     * @param  int  $sequence
     * @return void
     */
    #[DataProvider('provideImmutableColumns')]
    public function testAnImmutableCheckpointUpdateIsRefused(string $column, int|string|null $value, int $sequence): void
    {
        $this->sealedLog();

        $seal   = $this->root()->table(IntegrityTables::checkpointsTable())->where('sequence', $sequence);
        $before = $seal->clone()->first();

        self::assertRefusedByATrigger(static fn () => $seal->clone()->update([$column => $value]), IntegrityTables::checkpointsTable(), 'UPDATE');
        self::assertEquals($before, $seal->clone()->first());
    }

    /**
     * Every column of the checkpoints table is classified, in the table's own
     * order, as an immutable column the triggers and grants protect or as one
     * of the four anchor columns the writer may update, so a column added to
     * the migration fails here until the documented triggers and grants, and
     * the lists every trigger and grant test draws on, say which it is.
     *
     * @return void
     */
    public function testEveryCheckpointColumnIsImmutableOrAnAnchorColumn(): void
    {
        $columns = $this->root()->getSchemaBuilder()->getColumnListing(IntegrityTables::checkpointsTable());

        self::assertSame([...array_keys(self::IMMUTABLE_COLUMNS), ...self::ANCHOR_COLUMNS], $columns);
    }

    /**
     * The four anchor columns stay writable on the genesis seal, whose null
     * previous fields a careless comparison would trip on: they are written,
     * read back, and cleared again.
     *
     * @return void
     */
    public function testAnAnchorColumnUpdateIsAllowed(): void
    {
        $this->sealedLog();

        $seal    = $this->root()->table(IntegrityTables::checkpointsTable())->where('sequence', 1);
        $columns = [
            'anchor'             => 'disk:0123456789abcdef',
            'anchor_receipt'     => '{"path": "a"}',
            'anchored_at'        => '2026-11-01 13:30:00.000000',
            'anchor_error_class' => \RuntimeException::class,
        ];

        self::assertSame(1, $seal->clone()->update($columns));
        self::assertSame('disk:0123456789abcdef', $seal->clone()->value('anchor'));
        self::assertSame(\RuntimeException::class, $seal->clone()->value('anchor_error_class'));
        self::assertSame(1, $seal->clone()->update(array_fill_keys(self::ANCHOR_COLUMNS, null)));
        self::assertNull($seal->clone()->value('anchored_at'));
    }

    /**
     * A seal is never deleted, even by the tables' owner.
     *
     * @return void
     */
    public function testACheckpointDeleteIsRefused(): void
    {
        $this->sealedLog();

        $seals = $this->root()->table(IntegrityTables::checkpointsTable());

        self::assertRefusedByATrigger(static fn () => $seals->clone()->where('sequence', 2)->delete(), IntegrityTables::checkpointsTable(), 'DELETE');
        self::assertSame(2, $seals->clone()->count());
    }

    /**
     * A delete of an entry by the tables' owner is refused, and on MySQL and
     * PostgreSQL so is one by the writer granted `DELETE` beyond the documented
     * grants: the trigger, not the grant, refuses it.
     *
     * @return void
     */
    public function testTheTriggerRefusesADeleteByAnyoneButTheMaintenanceUser(): void
    {
        $entry = $this->sealedLog()[0];
        $root  = $this->root();
        $table = EntrySettings::table();

        self::assertRefusedByATrigger(static fn () => $root->table($table)->where('id', $entry)->delete(), $table, 'DELETE');

        if ($this->names !== []) {
            $root->statement($root->getDriverName() === 'mysql'
                ? sprintf('GRANT DELETE ON `%s`.`%s` TO \'%s\'@\'%%\'', $this->names['app_db'], $table, $this->names['audit_writer'])
                : sprintf('GRANT DELETE ON "%s" TO "%s"', $table, $this->names['audit_writer']));

            $writer = DB::connection(self::WRITER);

            self::assertRefusedByATrigger(static fn () => $writer->table($table)->where('id', $entry)->delete(), $table, 'DELETE');
        }

        self::assertSame(4, $root->table($table)->count());
    }

    /**
     * On MySQL and PostgreSQL the maintenance user deletes an entry, as a prune
     * does, while the other entries, every member and every seal stay.
     *
     * @return void
     */
    public function testTheMaintenanceUserMayDeleteAnEntry(): void
    {
        $this->skipOnSqlite();

        $entries = $this->sealedLog();
        $root    = $this->root();

        self::assertSame(1, DB::connection(self::MAINTENANCE)->table(EntrySettings::table())->where('id', $entries[0])->delete());
        self::assertFalse($root->table(EntrySettings::table())->where('id', $entries[0])->exists());
        self::assertSame(3, $root->table(EntrySettings::table())->count());
        self::assertSame(4, $root->table(IntegrityTables::membersTable())->count());
        self::assertSame(2, $root->table(IntegrityTables::checkpointsTable())->count());
    }

    /**
     * On MySQL the delete trigger compares the client's name byte for byte, so
     * a login whose name differs from the maintenance user's only in case is
     * refused, though it holds the same grant.
     *
     * @return void
     */
    public function testOnMySqlTheTriggerComparesTheNameExactly(): void
    {
        $root = $this->root();

        if ($root->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL compares the name the client gave.');
        }

        $entry          = $this->sealedLog()[0];
        $login          = strtoupper($this->names['audit_maintenance']);
        $this->logins[] = $login;

        self::createLogin($root, $login);

        $root->statement(sprintf('GRANT SELECT, DELETE ON `%s`.`%s` TO \'%s\'@\'%%\'', $this->names['app_db'], EntrySettings::table(), $login));

        self::connectAs('audit_impostor', self::CONNECTION, $login);

        $impostor = DB::connection('audit_impostor');

        try {
            self::assertRefusedByATrigger(static fn () => $impostor->table(EntrySettings::table())->where('id', $entry)->delete(), EntrySettings::table(), 'DELETE');
        } finally {
            DB::purge('audit_impostor');
        }

        self::assertSame(4, $root->table(EntrySettings::table())->count());
    }

    /**
     * On SQLite the documented prune, with a delete where the prune's own
     * statements go, deletes the entry and leaves the delete trigger as it was,
     * so the next delete is refused; members and seals stay.
     *
     * @return void
     */
    public function testTheDocumentedSqlitePruneDeletesAndRestoresTheTrigger(): void
    {
        $this->skipUnlessSqlite();

        $entries = $this->sealedLog();
        $root    = $this->root();

        $root->unprepared($this->pruneOf(sprintf('DELETE FROM %s WHERE id = \'%s\';', EntrySettings::table(), $entries[0])));

        self::assertFalse($root->table(EntrySettings::table())->where('id', $entries[0])->exists());
        self::assertSame(3, $root->table(EntrySettings::table())->count());
        self::assertSame($this->installedTriggers($root), $this->documentedTriggerNames());
        self::assertRefusedByATrigger(static fn () => $root->table(EntrySettings::table())->where('id', $entries[1])->delete(), EntrySettings::table(), 'DELETE');
        self::assertSame(4, $root->table(IntegrityTables::membersTable())->count());
    }

    /**
     * On SQLite the documented prune deletes an entry's artifact with the entry
     * and leaves both delete triggers as they were, so the next artifact's
     * delete is refused; the other artifact stays.
     *
     * @return void
     */
    public function testTheDocumentedSqlitePruneDeletesAnArtifactWithItsEntry(): void
    {
        $this->skipUnlessSqlite();

        $entries   = $this->sealedLog();
        $root      = $this->root();
        $artifacts = EntrySettings::artifactsTable();
        $pruned    = $this->storeArtifact(1, $entries[0]);
        $kept      = $this->storeArtifact(2, $entries[1]);

        $root->unprepared($this->pruneOf(sprintf(
            'DELETE FROM %s WHERE entry_id = \'%s\'; DELETE FROM %s WHERE id = \'%s\';',
            $artifacts,
            $entries[0],
            EntrySettings::table(),
            $entries[0],
        )));

        self::assertFalse($root->table($artifacts)->where('id', $pruned)->exists());
        self::assertFalse($root->table(EntrySettings::table())->where('id', $entries[0])->exists());
        self::assertSame($this->installedTriggers($root), $this->documentedTriggerNames());
        self::assertRefusedByATrigger(static fn () => $root->table($artifacts)->where('id', $kept)->delete(), $artifacts, 'DELETE');
        self::assertSame(1, $root->table($artifacts)->count());
    }

    /**
     * On SQLite a prune that fails after dropping the trigger and deleting an
     * entry, rolled back, keeps the entry and the trigger.
     *
     * @return void
     */
    public function testAFailedSqlitePruneRolledBackKeepsTheTrigger(): void
    {
        $this->skipUnlessSqlite();

        $entries = $this->sealedLog();
        $root    = $this->root();
        $prune   = $this->pruneOf(sprintf('DELETE FROM %s WHERE id = \'%s\'; INSERT INTO audit_log_missing VALUES (1);', EntrySettings::table(), $entries[0]));

        self::refusalOf(static fn () => $root->unprepared($prune), 'The failing prune');

        $root->unprepared('ROLLBACK');

        self::assertSame(4, $root->table(EntrySettings::table())->count());
        self::assertSame($this->installedTriggers($root), $this->documentedTriggerNames());
        self::assertRefusedByATrigger(static fn () => $root->table(EntrySettings::table())->where('id', $entries[0])->delete(), EntrySettings::table(), 'DELETE');
    }

    /**
     * Rows of `[table]`: each table the PostgreSQL truncate triggers are on.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideTruncatedTables(): iterable
    {
        yield from [
            'entries'     => [EntrySettings::DEFAULT_TABLE],
            'artifacts'   => [EntrySettings::DEFAULT_ARTIFACTS_TABLE],
            'checkpoints' => [IntegrityTables::DEFAULT_CHECKPOINTS],
            'members'     => [IntegrityTables::DEFAULT_MEMBERS],
        ];
    }

    /**
     * On PostgreSQL a `TRUNCATE`, which no row trigger sees, is refused by the
     * statement trigger, even for the tables' owner, and every row stays.
     *
     * @param  string  $table
     * @return void
     */
    #[DataProvider('provideTruncatedTables')]
    public function testATruncateIsRefusedOnPostgres(string $table): void
    {
        $root = $this->root();

        if ($root->getDriverName() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL has the truncate triggers; MySQL refuses it by the grants.');
        }

        $this->storeArtifact(1, $this->sealedLog()[0]);

        $count = $root->table($table)->count();

        self::assertGreaterThan(0, $count);
        self::assertRefusedByATrigger(static fn () => $root->statement(sprintf('TRUNCATE %s', $table)), $table, 'TRUNCATE');
        self::assertSame($count, $root->table($table)->count());
    }

    /**
     * The integrity state table, which is never evidence, is covered by no
     * trigger: its rows are written, replaced and deleted as progress needs.
     *
     * @return void
     */
    public function testTheStateTableIsNotCovered(): void
    {
        $progress = app(IntegrityProgress::class);
        $at       = FrozenClock::at(self::SEALED_AT)->now();

        $progress->put(IntegrityProgress::SWEEP_CURSOR, ['recorded_at' => '2026-11-01 12:00:00.000000'], $at);
        $progress->put(IntegrityProgress::SWEEP_CURSOR, ['recorded_at' => '2026-11-01 12:01:00.000000'], $at);

        self::assertSame(['recorded_at' => '2026-11-01 12:01:00.000000'], $progress->get(IntegrityProgress::SWEEP_CURSOR));

        $progress->forget(IntegrityProgress::SWEEP_CURSOR);

        self::assertNull($progress->get(IntegrityProgress::SWEEP_CURSOR));
    }

    /**
     * Under the triggers, `audit-log:seal` seals and anchors, its sweep
     * completes and forgets its cursor, and a strict `audit-log:verify` passes.
     *
     * @return void
     */
    public function testSealingAndAnchoringStillWorkUnderTheTriggers(): void
    {
        $this->useDiskAnchor();
        $this->storeEntries(3);

        self::assertSame(0, $this->runSeal()[0]);
        self::assertSame(0, app(Kernel::class)->call('audit-log:seal', ['--sweep' => true]));

        $seals = $this->seals();

        self::assertCount(1, $seals);
        self::assertNotNull($seals[0]['anchored_at']);
        self::assertNull(app(IntegrityProgress::class)->get(IntegrityProgress::SWEEP_CURSOR));
        self::assertNotNull(app(IntegrityProgress::class)->get(IntegrityProgress::SWEEP_COMPLETED));
        self::assertSame(0, $this->verify(['--strict' => true])[0]);
    }

    /**
     * Create this worker's logins, run the documented grants for them, and
     * configure a connection for each.
     *
     * @param  \Illuminate\Database\Connection  $root
     * @return void
     */
    private function createDocumentedLogins(Connection $root): void
    {
        $this->names = self::documentedNames($root);

        self::createLogin($root, $this->names['audit_writer']);
        self::createLogin($root, $this->names['audit_maintenance']);
        self::runDocumentedSql($root, $root->getDriverName() . '-grants', $this->names);
        self::connectAs(self::WRITER, self::CONNECTION, $this->names['audit_writer']);
        self::connectAs(self::MAINTENANCE, self::CONNECTION, $this->names['audit_maintenance']);
    }

    /**
     * Store two entries and seal them, then two more a minute later and seal
     * those, and return the four entries' ids in the order they are stored.
     *
     * @return list<string>
     */
    private function sealedLog(): array
    {
        $first = $this->storeEntries(2);

        $this->sealAll();

        $second = $this->storeEntries(2, '2026-11-01 12:01:00.000000');

        $this->sealAll();

        return [...$first, ...$second];
    }

    /**
     * Store an artifact of the entry, as the tables' owner, and return its id.
     *
     * @param  int  $number
     * @param  string  $entryId
     * @return string
     */
    private function storeArtifact(int $number, string $entryId): string
    {
        $this->root()->table(EntrySettings::artifactsTable())->insert(self::artifactRow($number, $entryId));

        return sprintf(self::ARTIFACT_ID, $number);
    }

    /**
     * An artifact row of the entry, its id numbered.
     *
     * @param  int  $number
     * @param  string  $entryId
     * @return array<string, int|string>
     */
    private static function artifactRow(int $number, string $entryId): array
    {
        return [
            'id'           => sprintf(self::ARTIFACT_ID, $number),
            'entry_id'     => $entryId,
            'kind'         => 'bulk',
            'member_count' => 3,
            'digest'       => str_repeat('a', 64),
            'members'      => 'eyJpdiI6IjAxMjM0NTY3ODkifQ==',
            'created_at'   => '2026-11-01 12:00:00.000000',
        ];
    }

    /**
     * The documented SQLite prune, with the statements given where the prune's
     * own go.
     *
     * @param  string  $statements
     * @return string
     */
    private function pruneOf(string $statements): string
    {
        return str_replace(self::PRUNE_STATEMENTS, $statements, self::documentedSql('sqlite-prune'));
    }

    /**
     * The names of the engine's documented triggers, sorted.
     *
     * @return list<string>
     */
    private function documentedTriggerNames(): array
    {
        $names = array_keys(self::documentedTriggers(self::documentedSql($this->root()->getDriverName() . '-triggers')));

        sort($names);

        return $names;
    }

    /**
     * The names of the triggers installed on the connection's database or
     * schema, sorted bytewise, whatever order the engine's collation gives.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return list<string>
     */
    private function installedTriggers(Connection $connection): array
    {
        $query = match ($connection->getDriverName()) {
            'mysql' => 'select trigger_name as name from information_schema.triggers where trigger_schema = database()',
            'pgsql' => 'select t.tgname as name from pg_trigger t join pg_class c on c.oid = t.tgrelid'
                . ' where c.relnamespace = current_schema()::regnamespace and not t.tgisinternal',
            default => 'select name from sqlite_master where type = \'trigger\'',
        };

        /** @var list<object{name: string}> $triggers */
        $triggers = $connection->select($query);
        $names    = array_map(static fn (object $trigger): string => $trigger->name, $triggers);

        sort($names);

        return $names;
    }

    /**
     * Skip the test on SQLite, which has no users.
     *
     * @return void
     */
    private function skipOnSqlite(): void
    {
        if ($this->root()->getDriverName() !== 'sqlite') {
            return;
        }

        self::markTestSkipped('SQLite has no users, so no maintenance user may delete.');
    }

    /**
     * Skip the test on any engine but SQLite, the only one whose pruning drops
     * and recreates a trigger.
     *
     * @return void
     */
    private function skipUnlessSqlite(): void
    {
        if ($this->root()->getDriverName() === 'sqlite') {
            return;
        }

        self::markTestSkipped('Only SQLite prunes by dropping and recreating the delete trigger.');
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
