<?php

declare(strict_types = 1);

namespace Tests\Integration\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use Tests\Concerns\RunsDocumentedSql;
use Tests\TestCase;

/**
 * Integration tests for the storage note's lifecycle triggers and grants, run
 * as written on every engine; they cover documented SQL, not a package class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class LifecycleTriggersTest extends TestCase
{
    use RunsDocumentedSql;

    /** @var string The connection the writer's login uses. */
    private const string WRITER = 'audit_writer';

    /** @var string The connection the maintenance user's login uses. */
    private const string MAINTENANCE = 'audit_maintenance';

    /** @var string The connection the verifier's login uses. */
    private const string VERIFIER = 'audit_verifier';

    /** @var string The id of the batch a test stores. */
    private const string BATCH_ID = '01932b4e-9000-7000-8000-000000000b01';

    /** @var string The id of the hold a test stores, its number replacing `%012d`. */
    private const string HOLD_ID = '01932b4e-9000-7000-8000-%012d';

    /** @var array<string, string> The names this worker gives the placeholders, once its logins exist. */
    private array $names = [];

    /**
     * Run the documented grants for this worker's logins, then the triggers.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $root = $this->root();

        if ($root->getDriverName() !== 'sqlite') {
            $this->names = self::documentedNames($root);

            foreach ([self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
                self::createLogin($root, $this->names[$placeholder]);
            }

            self::runDocumentedGrants($root, $this->names);

            foreach ([self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
                self::connectAs($placeholder, self::CONNECTION, $this->names[$placeholder]);
            }
        }

        self::runDocumentedSql($root, $root->getDriverName() . '-triggers', $this->names);
    }

    /**
     * Drop the triggers, close the logins' connections and drop the logins.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $root = $this->root();

        self::dropDocumentedTriggers($root);

        foreach ($this->names === [] ? [] : [self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
            DB::purge($placeholder);

            self::dropLogin($root, $this->names[$placeholder]);
        }

        parent::tearDown();
    }

    /**
     * Exactly the documented triggers are installed on the lifecycle tables.
     *
     * @return void
     */
    public function testTheDocumentedTriggersInstall(): void
    {
        $tables     = [LifecycleTables::journalTable(), LifecycleTables::holdsTable(), LifecycleTables::lockTable(), LifecycleTables::importBatchesTable()];
        $triggers   = self::documentedTriggers(self::documentedSql($this->root()->getDriverName() . '-triggers'));
        $documented = array_keys(array_filter($triggers, static fn (string $table): bool => in_array($table, $tables, true)));

        sort($documented);

        self::assertSame($documented, $this->installedTriggers($tables));
        self::assertCount(match ($this->root()->getDriverName()) {
            'sqlite' => 7,
            'pgsql'  => 12,
            default  => 8,
        }, $documented);
    }

    /**
     * A journal row is never updated, even by the tables' owner.
     *
     * @return void
     */
    public function testAJournalUpdateIsRefused(): void
    {
        $journal = $this->root()->table(LifecycleTables::journalTable());

        $journal->clone()->insert(self::journalRow(1));

        $before = $journal->clone()->first();

        self::assertRefusedByATrigger(static fn () => $journal->clone()->where('sequence', 1)->update(['reason' => 'rewritten']), LifecycleTables::journalTable(), 'UPDATE');
        self::assertEquals($before, $journal->clone()->first());
    }

    /**
     * A journal row is never deleted, even by the maintenance user.
     *
     * @return void
     */
    public function testAJournalDeleteIsRefusedEvenForTheMaintenanceUser(): void
    {
        $root  = $this->root();
        $table = LifecycleTables::journalTable();

        $root->table($table)->insert(self::journalRow(1));

        self::assertRefusedByATrigger(static fn () => $root->table($table)->delete(), $table, 'DELETE');

        if ($this->names !== []) {
            $this->grantBeyondTheDocumentation('DELETE', $table, self::MAINTENANCE);

            $maintenance = DB::connection(self::MAINTENANCE);

            self::assertRefusedByATrigger(static fn () => $maintenance->table($table)->delete(), $table, 'DELETE');
        }

        self::assertSame(1, $root->table($table)->count());
    }

    /**
     * A hold is never updated, even by the tables' owner.
     *
     * @return void
     */
    public function testAHoldUpdateIsRefused(): void
    {
        $holds = $this->root()->table(LifecycleTables::holdsTable());

        $holds->clone()->insert(self::holdRow(1));

        $before = $holds->clone()->first();

        self::assertRefusedByATrigger(static fn () => $holds->clone()->update(['basis' => 'regulatory']), LifecycleTables::holdsTable(), 'UPDATE');
        self::assertEquals($before, $holds->clone()->first());
    }

    /**
     * On MySQL and PostgreSQL only the maintenance user deletes a hold.
     *
     * @return void
     */
    public function testAHoldDeleteIsRefusedButForTheMaintenanceUser(): void
    {
        $this->skipOnSqlite();

        $root  = $this->root();
        $table = LifecycleTables::holdsTable();

        $root->table($table)->insert([self::holdRow(1), self::holdRow(2)]);

        $this->grantBeyondTheDocumentation('DELETE', $table, self::WRITER);

        $writer = DB::connection(self::WRITER);
        $first  = sprintf(self::HOLD_ID, 1);

        self::assertRefusedByATrigger(static fn () => $root->table($table)->where('hold_id', $first)->delete(), $table, 'DELETE');
        self::assertRefusedByATrigger(static fn () => $writer->table($table)->where('hold_id', $first)->delete(), $table, 'DELETE');
        self::assertSame(1, DB::connection(self::MAINTENANCE)->table($table)->where('hold_id', $first)->delete());
        self::assertSame([sprintf(self::HOLD_ID, 2)], $root->table($table)->pluck('hold_id')->all());
    }

    /**
     * On SQLite, which has no users, a release deletes its hold.
     *
     * @return void
     */
    public function testOnSqliteAHoldDeleteIsAllowed(): void
    {
        $this->skipUnlessSqlite();

        $holds = $this->root()->table(LifecycleTables::holdsTable());

        $holds->clone()->insert([self::holdRow(1), self::holdRow(2)]);

        self::assertSame(1, $holds->clone()->where('hold_id', sprintf(self::HOLD_ID, 1))->delete());
        self::assertSame(1, $holds->clone()->count());
    }

    /**
     * Rows of `[column, value]`, the value one no stored batch has.
     *
     * @return iterable<string, array{0: string, 1: bool|string}>
     */
    public static function provideImmutableBatchColumns(): iterable
    {
        foreach (self::IMMUTABLE_BATCH_COLUMNS as $column => $value) {
            yield $column => [$column, $value];
        }
    }

    /**
     * A change to any immutable batch column is refused, even for the owner.
     *
     * @param  string  $column
     * @param  bool|string  $value
     * @return void
     */
    #[DataProvider('provideImmutableBatchColumns')]
    public function testAnImmutableBatchColumnUpdateIsRefused(string $column, bool|string $value): void
    {
        $batches = $this->root()->table(LifecycleTables::importBatchesTable());

        $batches->clone()->insert(self::batchRow());

        $before = $batches->clone()->first();

        self::assertRefusedByATrigger(static fn () => $batches->clone()->update([$column => $value]), LifecycleTables::importBatchesTable(), 'UPDATE');
        self::assertEquals($before, $batches->clone()->first());
    }

    /**
     * A batch's progress columns are written under the triggers.
     *
     * @return void
     */
    public function testABatchCountUpdateIsAllowed(): void
    {
        $batches  = $this->root()->table(LifecycleTables::importBatchesTable());
        $progress = self::progress();

        $batches->clone()->insert(self::batchRow());

        self::assertSame(1, $batches->clone()->where('id', self::BATCH_ID)->update($progress));
        self::assertEquals($progress, (array) $batches->clone()->first(self::BATCH_PROGRESS_COLUMNS));
    }

    /**
     * A batch is never deleted, even by the tables' owner.
     *
     * @return void
     */
    public function testABatchDeleteIsRefused(): void
    {
        $batches = $this->root()->table(LifecycleTables::importBatchesTable());

        $batches->clone()->insert(self::batchRow());

        self::assertRefusedByATrigger(static fn () => $batches->clone()->delete(), LifecycleTables::importBatchesTable(), 'DELETE');
        self::assertSame(1, $batches->clone()->count());
    }

    /**
     * The lock's one row is never deleted or renumbered.
     *
     * @return void
     */
    public function testTheLockRowCannotBeDeletedOrRenumbered(): void
    {
        $lock = $this->root()->table(LifecycleTables::lockTable());

        self::assertRefusedByATrigger(static fn () => $lock->clone()->delete(), LifecycleTables::lockTable(), 'DELETE');
        self::assertRefusedByATrigger(static fn () => $lock->clone()->where('id', 1)->update(['id' => 2]), LifecycleTables::lockTable(), 'UPDATE');
        self::assertEquals([1], $lock->clone()->pluck('id')->all());
    }

    /**
     * The lock is taken by writing its token and time under the triggers.
     *
     * @return void
     */
    public function testTheLockTokenUpdateIsAllowed(): void
    {
        $table = LifecycleTables::lockTable();
        $lock  = $this->root()->table($table)->where('id', 1);

        self::assertSame(1, $lock->clone()->update(['token' => 'owner:0123456789abcdef', 'locked_at' => '2026-11-01 12:00:00.000000']));
        self::assertSame('owner:0123456789abcdef', $lock->clone()->value('token'));

        if ($this->names === []) {
            return;
        }

        $maintenance = DB::connection(self::MAINTENANCE)->table($table)->where('id', 1);

        self::assertSame(1, $maintenance->clone()->update(['token' => 'upkeep:0123456789abcdef', 'locked_at' => '2026-11-01 12:00:01.000000']));
        self::assertSame('upkeep:0123456789abcdef', $lock->clone()->value('token'));
        $renumber = static fn () => $maintenance->clone()->update(['id' => 1]);

        self::assertRefusedByTheGrants($renumber, $this->root()->getDriverName(), 'The maintenance user\'s update of the lock\'s id');
    }

    /**
     * Rows of `[table]`: each table with a PostgreSQL truncate trigger.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideTruncatedTables(): iterable
    {
        yield from [
            'the journal'        => [LifecycleTables::DEFAULT_JOURNAL],
            'the holds'          => [LifecycleTables::DEFAULT_HOLDS],
            'the lock'           => [LifecycleTables::DEFAULT_LOCK],
            'the import batches' => [LifecycleTables::DEFAULT_IMPORT_BATCHES],
        ];
    }

    /**
     * On PostgreSQL a `TRUNCATE` is refused by the statement trigger.
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

        $root->table(LifecycleTables::journalTable())->insert(self::journalRow(1));
        $root->table(LifecycleTables::holdsTable())->insert(self::holdRow(1));
        $root->table(LifecycleTables::importBatchesTable())->insert(self::batchRow());

        self::assertSame(1, $root->table($table)->count());
        self::assertRefusedByATrigger(static fn () => $root->statement(sprintf('TRUNCATE %s', $table)), $table, 'TRUNCATE');
        self::assertSame(1, $root->table($table)->count());
    }

    /**
     * The grants let the writer only read the journal, and the maintenance user
     * only insert into it.
     *
     * @return void
     */
    public function testTheGrantsLimitWhatEachUserDoesToTheJournal(): void
    {
        $this->skipOnSqlite();

        $driver      = $this->root()->getDriverName();
        $table       = LifecycleTables::journalTable();
        $writer      = DB::connection(self::WRITER)->table($table);
        $maintenance = DB::connection(self::MAINTENANCE)->table($table);

        self::assertRefusedByTheGrants(static fn () => $writer->clone()->insert(self::journalRow(1)), $driver, 'The writer\'s insert into the journal');
        self::assertTrue($maintenance->clone()->insert(self::journalRow(1)));
        self::assertSame(1, $writer->clone()->count());
        self::assertSame(1, $maintenance->clone()->count());

        $refusals = [
            'The writer\'s update of a journal row'           => static fn () => $writer->clone()->update(['reason' => 'rewritten']),
            'The writer\'s delete of a journal row'           => static fn () => $writer->clone()->delete(),
            'The maintenance user\'s update of a journal row' => static fn () => $maintenance->clone()->update(['reason' => 'rewritten']),
            'The maintenance user\'s delete of a journal row' => static fn () => $maintenance->clone()->delete(),
            'The writer\'s insert of a hold'                  => static fn () => DB::connection(self::WRITER)->table(LifecycleTables::holdsTable())->insert(self::holdRow(1)),
            'The writer\'s update of the lock'                => static fn () => DB::connection(self::WRITER)->table(LifecycleTables::lockTable())->update(['token' => 'writer']),
        ];

        foreach ($refusals as $what => $refusal) {
            self::assertRefusedByTheGrants($refusal, $driver, $what);
        }

        self::assertSame(1, $this->root()->table($table)->count());
    }

    /**
     * The grants let the writer update only a batch's progress columns.
     *
     * @return void
     */
    public function testTheWriterUpdatesOnlyTheBatchCountsStatusAndTimes(): void
    {
        $this->skipOnSqlite();

        $driver = $this->root()->getDriverName();
        $writer = DB::connection(self::WRITER)->table(LifecycleTables::importBatchesTable());

        self::assertTrue($writer->clone()->insert(self::batchRow()));
        self::assertSame(1, $writer->clone()->where('id', self::BATCH_ID)->update(self::progress()));

        foreach (self::IMMUTABLE_BATCH_COLUMNS as $column => $value) {
            self::assertRefusedByTheGrants(static fn () => $writer->clone()->where('id', self::BATCH_ID)->update([$column => $value]), $driver, "The writer's update of {$column}");
        }

        self::assertRefusedByTheGrants(static fn () => $writer->clone()->delete(), $driver, 'The writer\'s delete of a batch');
        self::assertRefusedByTheGrants(
            static fn () => DB::connection(self::MAINTENANCE)->table(LifecycleTables::importBatchesTable())->count(),
            $driver,
            'The maintenance user\'s read of the batches',
        );
        self::assertSame('legacy-app', $this->root()->table(LifecycleTables::importBatchesTable())->value('source_id'));
    }

    /**
     * The verifier reads the journal and holds, and writes neither.
     *
     * @return void
     */
    public function testTheVerifierReadsTheJournalWithOnlySelect(): void
    {
        $this->skipOnSqlite();

        $driver   = $this->root()->getDriverName();
        $verifier = DB::connection(self::VERIFIER);
        $journal  = $verifier->table(LifecycleTables::journalTable());

        $this->root()->table(LifecycleTables::journalTable())->insert(self::journalRow(1));
        $this->root()->table(LifecycleTables::holdsTable())->insert(self::holdRow(1));

        self::assertSame(1, $journal->clone()->count());
        self::assertSame(1, $verifier->table(LifecycleTables::holdsTable())->count());

        $refusals = [
            'insert a journal row' => static fn () => $journal->clone()->insert(self::journalRow(2)),
            'update a journal row' => static fn () => $journal->clone()->update(['reason' => 'rewritten']),
            'delete a journal row' => static fn () => $journal->clone()->delete(),
            'delete a hold'        => static fn () => $verifier->table(LifecycleTables::holdsTable())->delete(),
            'read the lock'        => static fn () => $verifier->table(LifecycleTables::lockTable())->count(),
            'read the batches'     => static fn () => $verifier->table(LifecycleTables::importBatchesTable())->count(),
        ];

        foreach ($refusals as $what => $refusal) {
            self::assertRefusedByTheGrants($refusal, $driver, "The verifier's attempt to {$what}");
        }
    }

    /**
     * A journal row, numbered so its id and sequence are its own.
     *
     * @param  int  $number
     * @return array<string, int|string>
     */
    private static function journalRow(int $number): array
    {
        return [
            'id'             => sprintf('01932b4e-9000-7000-8000-%012d', $number),
            'sequence'       => $number,
            'log_id'         => 'app-eu-1',
            'kind'           => 'hold',
            'operation_id'   => '01932b4e-9000-7000-8000-00000000aaaa',
            'occurred_at'    => '2026-11-01 12:00:00.000000',
            'authority_type' => 'operator',
            'authority_id'   => '7',
            'reason'         => 'legal_hold',
            'payload'        => '{}',
            'payload_digest' => str_repeat('a', 64),
            'key_id'         => 'k2026',
            'hmac'           => str_repeat('b', 64),
        ];
    }

    /**
     * A hold, numbered so its id and journal row are its own.
     *
     * @param  int  $number
     * @return array<string, int|string>
     */
    private static function holdRow(int $number): array
    {
        return [
            'hold_id'          => sprintf(self::HOLD_ID, $number),
            'scope'            => '{}',
            'scope_digest'     => str_repeat('a', 64),
            'basis'            => 'litigation',
            'placed_at'        => '2026-11-01 12:00:00.000000',
            'authority_type'   => 'operator',
            'authority_id'     => '7',
            'reason'           => 'legal_hold',
            'operation_id'     => '01932b4e-9000-7000-8000-00000000aaaa',
            'journal_sequence' => $number,
        ];
    }

    /**
     * A running batch with no region, reference or hold.
     *
     * @return array<string, bool|int|string>
     */
    private static function batchRow(): array
    {
        return [
            'id'                  => self::BATCH_ID,
            'source_id'           => 'legacy-app',
            'input_format'        => 'audit-log-import/v1',
            'importer_type'       => 'operator',
            'importer_id'         => '7',
            'reason'              => 'migration',
            'file_sha256'         => str_repeat('a', 64),
            'externally_verified' => false,
            'status'              => 'running',
            'lines_read'          => 0,
            'imported'            => 0,
            'duplicates'          => 0,
            'conflicts'           => 0,
            'rejected'            => 0,
            'started_at'          => '2026-11-01 12:00:00.000000',
            'updated_at'          => '2026-11-01 12:00:00.000000',
        ];
    }

    /**
     * The progress a finished batch is written with.
     *
     * @return array<string, int|string>
     */
    private static function progress(): array
    {
        return [
            'status'       => 'partial',
            'lines_read'   => 5,
            'imported'     => 2,
            'duplicates'   => 1,
            'conflicts'    => 1,
            'rejected'     => 1,
            'conflict_ids' => '["r4"]',
            'updated_at'   => '2026-11-01 12:05:00.123456',
            'finished_at'  => '2026-11-01 12:05:00.123456',
        ];
    }

    /**
     * Grant the placeholder's login a privilege beyond the documented grants.
     *
     * @param  string  $privilege
     * @param  string  $table
     * @param  string  $placeholder
     * @return void
     */
    private function grantBeyondTheDocumentation(string $privilege, string $table, string $placeholder): void
    {
        $root = $this->root();

        $root->statement($root->getDriverName() === 'mysql'
            ? sprintf('GRANT %s ON `%s`.`%s` TO \'%s\'@\'%%\'', $privilege, $this->names['app_db'], $table, $this->names[$placeholder])
            : sprintf('GRANT %s ON "%s" TO "%s"', $privilege, $table, $this->names[$placeholder]));
    }

    /**
     * The triggers on the tables, sorted bytewise whatever the collation.
     *
     * @param  list<string>  $tables
     * @return list<string>
     */
    private function installedTriggers(array $tables): array
    {
        $connection = $this->root();
        $in         = implode(', ', array_fill(0, count($tables), '?'));

        $query = match ($connection->getDriverName()) {
            'mysql' => "select trigger_name as name from information_schema.triggers where trigger_schema = database() and event_object_table in ({$in})",
            'pgsql' => 'select t.tgname as name from pg_trigger t join pg_class c on c.oid = t.tgrelid'
                . " where c.relnamespace = current_schema()::regnamespace and not t.tgisinternal and c.relname in ({$in})",
            default => "select name from sqlite_master where type = 'trigger' and tbl_name in ({$in})",
        };

        /** @var list<object{name: string}> $triggers */
        $triggers = $connection->select($query, $tables);
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

        self::markTestSkipped('SQLite has no users or privileges.');
    }

    /**
     * Skip the test on any engine but SQLite, the only one without users.
     *
     * @return void
     */
    private function skipUnlessSqlite(): void
    {
        if ($this->root()->getDriverName() === 'sqlite') {
            return;
        }

        self::markTestSkipped('Only SQLite leaves the holds without a delete trigger.');
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
