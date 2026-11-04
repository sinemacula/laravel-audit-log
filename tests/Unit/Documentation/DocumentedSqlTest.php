<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Console\TableShape;
use Tests\Concerns\RunsDocumentedSql;

/**
 * A drift guard for the grants and triggers the storage note documents as SQL:
 * each of the six blocks is marked and found by its marker alone, names no
 * database or user but the placeholders, grants exactly the documented
 * privileges and nothing that changes the schema, grants each of the writer,
 * the maintenance user and the verifier what the role matrix says, and creates
 * exactly the documented triggers; each engine's checkpoints and import batches
 * triggers guard every immutable column and no column written later, the lock's
 * guards its id alone, and the journal's refuse everything; the artifacts' and
 * the holds' triggers are the entries' own; the SQLite prune takes the lock
 * first and recreates the very triggers it drops; the note states what it must,
 * in its own section, in order; and it lists the entries' indexes as the schema
 * checks expect them.
 *
 * The integration tests run the same blocks against each engine; this test
 * holds them to what the note says on any engine, SQLite included.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class DocumentedSqlTest extends TestCase
{
    use RunsDocumentedSql;

    /** @var list<string> The tables the triggers are on, in the order they are created. */
    private const array TABLES = [
        'audit_log_entries',
        'audit_log_artifacts',
        'audit_log_checkpoints',
        'audit_log_checkpoint_members',
        'audit_log_lifecycle',
        'audit_log_holds',
        'audit_log_lifecycle_lock',
        'audit_log_import_batches',
    ];

    /** @var list<string> The tables a prune deletes from, which only the maintenance user deletes from, in the order the role matrix lists them. */
    private const array PRUNED_TABLES = ['audit_log_entries', 'audit_log_artifacts', 'audit_log_deliveries'];

    /** @var list<string> The tables whose delete trigger the SQLite prune drops and recreates, in order: those a prune deletes from that have one. */
    private const array SQLITE_PRUNED_TRIGGERS = ['audit_log_entries_no_delete', 'audit_log_artifacts_no_delete'];

    /** @var list<string> The tables a delete trigger lets the maintenance user delete from, on MySQL and PostgreSQL. */
    private const array MAINTENANCE_DELETES = ['audit_log_entries', 'audit_log_artifacts', 'audit_log_holds'];

    /** @var list<string> Every table the shipped migrations create, under its default name, in the order the role matrix lists them. */
    private const array PACKAGE_TABLES = [
        'audit_log_entries',
        'audit_log_artifacts',
        'audit_log_outbox',
        'audit_log_deliveries',
        'audit_log_checkpoints',
        'audit_log_checkpoint_members',
        'audit_log_integrity_state',
        'audit_log_lifecycle',
        'audit_log_holds',
        'audit_log_lifecycle_lock',
        'audit_log_import_batches',
    ];

    /** @var array<string, string> Each placeholder user, by the role matrix's column that names it. */
    private const array USERS = ['Writer' => 'audit_writer', 'Maintenance' => 'audit_maintenance', 'Verifier' => 'audit_verifier'];

    /** @var string The statement the SQLite prune takes the lifecycle lock with, straight after it begins. */
    private const string LOCK_STATEMENT = 'UPDATE audit_log_lifecycle_lock SET token = \'manual\', locked_at = CURRENT_TIMESTAMP WHERE id = 1;';

    /** @var list<string> The privileges the grants give, in the order the role matrix lists them. */
    private const array PRIVILEGES = ['SELECT', 'INSERT', 'UPDATE', 'DELETE'];

    /** @var list<string> The sections of the storage note, in order. */
    private const array SECTIONS = [
        'Purpose',
        'Invariants',
        'Success Path',
        'Failure / Edge Cases',
        'Grants And Triggers',
        'Seams Left',
        'Implementation Anchors',
        'Authoritative Tests',
        'Change Triggers',
    ];

    /**
     * Rows of `[marker]`: the marker of each documented block.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMarkers(): iterable
    {
        yield from [
            'mysql-grants'    => ['mysql-grants'],
            'mysql-triggers'  => ['mysql-triggers'],
            'pgsql-grants'    => ['pgsql-grants'],
            'pgsql-triggers'  => ['pgsql-triggers'],
            'sqlite-triggers' => ['sqlite-triggers'],
            'sqlite-prune'    => ['sqlite-prune'],
        ];
    }

    /**
     * Each block is in the storage note, after its marker, and holds SQL.
     *
     * @param  string  $marker
     * @return void
     */
    #[DataProvider('provideMarkers')]
    public function testEachBlockIsMarked(string $marker): void
    {
        $sql = self::documentedSql($marker);

        self::assertNotSame('', trim($sql));
        self::assertStringNotContainsString('```', $sql);
    }

    /**
     * The scanner returns the block straight after the marker, past blank lines
     * only, and nothing for a marker that is absent, repeated, followed by
     * prose or a block of another language, or only the start of another
     * marker.
     *
     * @return void
     */
    public function testTheMarkerScannerFindsOnlyTheBlockAfterIt(): void
    {
        $markdown = <<<'MD'
            <!-- sql: first -->

            ```sql
            SELECT 1;
            ```

            <!-- sql: second -->
            ```sql
            SELECT 2;
            SELECT 3;
            ```

            <!-- sql: prose -->

            Some prose before the block.

            ```sql
            SELECT 4;
            ```

            <!-- sql: shell -->

            ```bash
            echo 5
            ```

            <!-- sql: twice -->

            ```sql
            SELECT 6;
            ```

            <!-- sql: twice -->

            ```sql
            SELECT 7;
            ```

            <!-- sql: first-extra -->

            ```sql
            SELECT 8;
            ```
            MD;

        self::assertSame("SELECT 1;\n", self::sqlAfterMarker($markdown, 'first'));
        self::assertSame("SELECT 2;\nSELECT 3;\n", self::sqlAfterMarker($markdown, 'second'));
        self::assertSame("SELECT 8;\n", self::sqlAfterMarker($markdown, 'first-extra'));
        self::assertNull(self::sqlAfterMarker($markdown, 'prose'));
        self::assertNull(self::sqlAfterMarker($markdown, 'shell'));
        self::assertNull(self::sqlAfterMarker($markdown, 'twice'));
        self::assertNull(self::sqlAfterMarker($markdown, 'absent'));
        self::assertNull(self::sqlAfterMarker($markdown, 'fir'));
    }

    /**
     * A marker the storage note does not have fails the test that asks for it,
     * naming the marker.
     *
     * @return void
     */
    public function testAnAbsentBlockFailsTheTest(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The storage note has no SQL block marked `absent`.');

        self::documentedSql('absent');
    }

    /**
     * Rows of `[marker, names]`: each block with the names it uses in a user or
     * database position, which are placeholders alone.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function providePlaceholders(): iterable
    {
        yield from [
            'mysql-grants'    => ['mysql-grants', ['app_db', 'audit_maintenance', 'audit_verifier', 'audit_writer']],
            'mysql-triggers'  => ['mysql-triggers', ['audit_maintenance']],
            'pgsql-grants'    => ['pgsql-grants', ['app_db', 'audit_maintenance', 'audit_verifier', 'audit_writer']],
            'pgsql-triggers'  => ['pgsql-triggers', ['audit_maintenance']],
            'sqlite-triggers' => ['sqlite-triggers', []],
            'sqlite-prune'    => ['sqlite-prune', []],
        ];
    }

    /**
     * Every block names no database and no user but the placeholders, which a
     * reader replaces with their own.
     *
     * @param  string  $marker
     * @param  list<string>  $names
     * @return void
     */
    #[DataProvider('providePlaceholders')]
    public function testEveryBlockUsesOnlyThePlaceholders(string $marker, array $names): void
    {
        self::assertSame($names, self::namesIn(self::documentedSql($marker)));
    }

    /**
     * The name scanner finds a name in every user or database position the
     * blocks use, quoted or not, and none in a message, a column or a value a
     * statement sets.
     *
     * @return void
     */
    public function testTheNameScannerFindsEveryNameInAUserOrDatabasePosition(): void
    {
        $sql = <<<'SQL'
            GRANT SELECT ON shop.audit_log_entries TO 'root'@'localhost';
            GRANT CONNECT ON DATABASE billing TO postgres, admin;
            CREATE USER IF NOT EXISTS 'intruder'@'%';
            CREATE ROLE reader;
            IF CAST(SUBSTRING_INDEX(USER(), '@', 1) AS BINARY) <> 'operator' THEN
            IF current_user = 'superuser' THEN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_entries refuses DELETE';
            WHEN (OLD.id IS DISTINCT FROM NEW.id)
            SQL;

        self::assertSame(['admin', 'billing', 'intruder', 'operator', 'postgres', 'reader', 'root', 'shop', 'superuser'], self::namesIn($sql));
        self::assertSame([], self::namesIn('SIGNAL SQLSTATE \'45000\' SET MESSAGE_TEXT = \'audit_log_entries refuses DELETE\';'));
        self::assertSame([], self::namesIn(self::LOCK_STATEMENT));
        self::assertSame(['admin', 'auditor'], self::namesIn('IF session_user = \'auditor\' OR USER() = \'admin\' THEN'));
    }

    /**
     * Rows of `[statement]`: what the storage note must state about the grants
     * and triggers, however its lines are wrapped.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRequiredStatements(): iterable
    {
        yield from [
            'the placeholders'           => ['Replace `app_db`, `audit_writer`, `audit_maintenance` and `audit_verifier` with your database and users.'],
            'the writer\'s grants'       => ['is granted `SELECT` and `INSERT` on the entries, the artifacts, the checkpoints and the members'],
            'the writer\'s anchor grant' => ['`UPDATE` on the checkpoints\' four anchor columns alone, and `SELECT`'],
            'the writer\'s state grants' => ['and `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the integrity state table'],
            'the sweep\'s delete'        => ['the `DELETE` is for the sweep, which forgets its cursor when it completes'],
            'the maintenance user'       => ['the maintenance user is granted `SELECT` and `DELETE` on the entries, the artifacts and the deliveries, because pruning deletes'
                . ' an entry\'s artifact and receipts with it and keeps every checkpoint and member'],
            'the maintenance reads' => ['`SELECT` on the checkpoints, the members, the integrity state, for the installation id, and the outbox when it is on the storage'
                . ' database'],
            'the maintenance lifecycle' => ['`SELECT` and `INSERT` on the journal; `SELECT`, `INSERT` and `DELETE` on the holds; and `SELECT` and `UPDATE` of `token` and'
                . ' `locked_at` alone on the lock'],
            'the writer\'s lifecycle'  => ['`SELECT` on the journal and the holds, because sealing reads the journal\'s head'],
            'the writer\'s batches'    => ['`SELECT` and `INSERT` on the import batches, with `UPDATE` of their status, counts, conflict ids and times alone'],
            'the verifier'             => ['The verifier, an optional third user for scheduled verification, holds exactly those; the writer may verify instead'],
            'no delete to verify'      => ['The verifier role never needs delete-capable credentials to read prune evidence'],
            'the first guarantee'      => ['Database credentials can still destroy rows'],
            'the second guarantee'     => ['The package\'s cryptographic evidence makes an unauthorised destruction detectable, never impossible.'],
            'the journal is final'     => ['A journal row is never updated or deleted, with no maintenance exception'],
            'the holds on SQLite'      => ['The holds get no delete trigger on SQLite, because a release could not delete its row otherwise'],
            'the prune takes the lock' => ['That prune takes the lifecycle lock first'],
            'no runtime schema change' => ['nothing changes the schema at runtime, except the documented SQLite prune, which drops and recreates the delete triggers inside its'
                . ' own transaction'],
            'the maintenance connection' => ['`storage.maintenance_connection` is the connection pruning, holds and the lifecycle journal run through'],
            'the lifecycle tables'       => ['`import.batches_table` (`audit_log_import_batches`) are always on the storage connection'],
            'the journal is append-only' => ['the journal is never updated or deleted, by a prune or anything else'],
            'the batches stay'           => ['a batch is never deleted'],
            'the lock row'               => ['The lock row is seeded and only updated'],
            'the projection'             => ['The holds projection is never trusted by a prune'],
            'the source digest'          => ['`source_digest` (`string(64)`, nullable) is the keyed digest of an imported record\'s source assertion'],
            'the journal head'           => ['`journal_sequence` (a signed `bigInteger`) and `journal_head` (`string(64)`) are the lifecycle journal\'s head'],
            'the installation id'        => ['It is written once, through the storage connection\'s writer, with a plain insert that never replaces one'],
            'no DDL'                     => ['no DDL for the application user'],
            'no documented DDL'          => ['no documented user holds `DROP`, `TRUNCATE`, `TRIGGER` or `ALTER`'],
            'the verify user'            => ['the user that runs `audit-log:verify` also needs `SELECT`, `INSERT` and `UPDATE` on the integrity state table'],
            'the definer'                => ['`CURRENT_USER()` in a trigger is the definer, so the MySQL triggers read `USER()`'],
            'the client\'s name'         => ['`USER()` is the name the client gave, so on MySQL the grants, not the triggers, are the boundary'],
            'grants alone'               => ['or prefer grants alone'],
            'truncate'                   => ['A row trigger never fires on `TRUNCATE`'],
            'truncate on MySQL'          => ['On MySQL `TRUNCATE` needs `DROP`, which no documented user holds, and fires no trigger'],
            'the owner'                  => ['The tables\' owner can drop the triggers: they guard against the application\'s users, not against the owner'],
            'SQLite'                     => ['SQLite has no users, so its triggers refuse every update and delete they cover, with no maintenance exception'],
            'pruning on SQLite'          => ['with no maintenance exception, and pruning on SQLite drops and recreates the delete triggers of the entries and the artifacts'],
            'a failed prune'             => ['A prune that fails before `COMMIT` is rolled back, and the rollback restores the triggers'],
            'column grants'              => ['column grants exist on MySQL and PostgreSQL only'],
            'the anchor columns'         => ['The anchor columns are the only ones written after a seal is inserted'],
            'the integrity tables'       => ['are always on the storage connection, beside the entries they describe, and no setting moves them'],
            'the recorded index'         => ['`_recorded_index` over `recorded_at` and `id`'],
            'the existing two tables'    => ['`delivery.deliveries_table` (`audit_log_deliveries` by default) is always on the storage connection'],
            'the existing outbox'        => ['`delivery.outbox.table` (`audit_log_outbox` by default) is on `delivery.outbox.connection`'],
            'the existing outbox grants' => ['In outbox mode the writer also needs'],
            'the artifacts table'        => ['`entries.artifacts_table` (`audit_log_artifacts` by default) is always on the storage connection'],
            'one artifact per entry'     => ['under the unique `<table>_entry_unique`, so an entry has at most one artifact'],
            'the artifacts\' lifecycle'  => ['An artifact is written with its entry and never changed. It is kept as long as its entry and deleted only with it,'
                . ' by the maintenance user'],
            'the writer\'s artifacts' => ['the application\'s writer needs `SELECT` and `INSERT` on the entries and the artifacts tables and nothing else'],
            'the truncate triggers'   => ['a statement trigger on each of the eight tables'],
            'the trail\'s lookups'    => ['category and occurred indexes, ends in `occurred_at` and then `id`, the order a page of the trail is read in'],
            'no collation on the id'  => ['no collation is applied to `id`, which compares in the type the migration gives it'],
            'a combined read'         => ['uses one index and filters the rest of its conditions row by row'],
            'the plans'               => ['`tests/Integration/Querying/TrailPlansTest.php` reads each engine\'s plan'],
        ];
    }

    /**
     * The storage note states each of those, however the line is wrapped.
     *
     * @param  string  $statement
     * @return void
     */
    #[DataProvider('provideRequiredStatements')]
    public function testTheStorageNoteStatesWhatItMust(string $statement): void
    {
        self::assertStringContainsString($statement, (string) preg_replace('/\s+/', ' ', self::note()));
    }

    /**
     * The storage note has its grants and triggers section, then the seams it
     * leaves, between the failure and edge cases and the implementation
     * anchors.
     *
     * @return void
     */
    public function testTheStorageNoteHasItsExtraSectionInOrder(): void
    {
        $prose = (string) preg_replace('/^ *(```|~~~)[^\n]*\n.*?^ *\1[ \t]*$/ms', '', self::note());

        preg_match_all('/^## (.+)$/m', $prose, $sections);

        self::assertSame(self::SECTIONS, $sections[1]);
    }

    /**
     * The storage note's table of the entries' indexes lists each index the
     * schema checks expect, by its suffix, with its columns in order and its
     * uniqueness, and no other.
     *
     * @return void
     */
    public function testTheStorageNoteListsEveryEntriesIndex(): void
    {
        preg_match_all('/^ *\| `(_[a-z_]+)` +\| (.+?) +\|$/m', self::note(), $rows, PREG_SET_ORDER);

        $documented = [];

        foreach ($rows as [, $suffix, $cells]) {
            $columns = explode(', ', $cells);
            $unique  = end($columns) === 'unique';
            $names   = array_map(static fn (string $column): string => trim($column, '`'), $unique ? array_slice($columns, 0, -1) : $columns);

            $documented[$suffix] = [$names, $unique];
        }

        self::assertSame(TableShape::entries()->indexes, $documented);
    }

    /**
     * Rows of `[marker]`: each engine's triggers.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideTriggerMarkers(): iterable
    {
        yield from [
            'mysql'  => ['mysql-triggers'],
            'pgsql'  => ['pgsql-triggers'],
            'sqlite' => ['sqlite-triggers'],
        ];
    }

    /**
     * Each engine's checkpoints update trigger guards exactly the 17 immutable
     * columns, in order, and no anchor column: on MySQL a null-safe comparison
     * of each old and new value, on PostgreSQL the old and new rows compared
     * with `IS DISTINCT FROM`, and on SQLite the columns an update names.
     *
     * @param  string  $marker
     * @return void
     */
    #[DataProvider('provideTriggerMarkers')]
    public function testTheTriggersCoverEveryImmutableCheckpointColumn(string $marker): void
    {
        $trigger = self::statementCreating(self::documentedSql($marker), 'audit_log_checkpoints_no_update');

        foreach (self::guardedColumnLists($marker, $trigger) as $list) {
            self::assertSame(array_keys(self::IMMUTABLE_COLUMNS), $list);
        }

        foreach (self::ANCHOR_COLUMNS as $column) {
            self::assertDoesNotMatchRegularExpression('/\b' . $column . '\b/', $trigger, "The trigger names the anchor column {$column}.");
        }
    }

    /**
     * Rows of `[marker, triggers]`: each block that creates triggers, with the
     * name and table of each, in order.
     *
     * @return iterable<string, array{0: string, 1: array<string, string>}>
     */
    public static function provideDocumentedTriggers(): iterable
    {
        $sqlite = self::triggersOf(['no_update', 'no_delete']);

        unset($sqlite['audit_log_holds_no_delete']);

        yield from [
            'mysql'        => ['mysql-triggers', self::triggersOf(['no_update', 'no_delete'])],
            'pgsql'        => ['pgsql-triggers', self::triggersOf(['no_update', 'no_delete', 'no_truncate'])],
            'sqlite'       => ['sqlite-triggers', $sqlite],
            'sqlite prune' => ['sqlite-prune', ['audit_log_entries_no_delete' => 'audit_log_entries', 'audit_log_artifacts_no_delete' => 'audit_log_artifacts']],
        ];
    }

    /**
     * Each engine creates an update and a delete trigger on each of the eight
     * tables, and PostgreSQL a truncate trigger on each too, each named after
     * its table, but for SQLite's holds, which have no delete trigger; the
     * SQLite prune creates the entries' and the artifacts' delete triggers
     * alone.
     *
     * @param  string  $marker
     * @param  array<string, string>  $triggers
     * @return void
     */
    #[DataProvider('provideDocumentedTriggers')]
    public function testEachEngineDocumentsEveryTrigger(string $marker, array $triggers): void
    {
        self::assertSame($triggers, self::documentedTriggers(self::documentedSql($marker)));
    }

    /**
     * The PostgreSQL triggers call the two documented functions: the entries',
     * the artifacts' and the holds' delete triggers the one that lets the
     * maintenance user through, by `current_user`, and every other trigger the
     * one that refuses everyone; the truncate triggers fire once per statement.
     *
     * @return void
     */
    public function testThePostgresTriggersCallTheirFunctions(): void
    {
        $sql = self::documentedSql('pgsql-triggers');

        self::assertSame(['audit_log_refuse', 'audit_log_refuse_delete'], self::documentedFunctions($sql));
        self::assertStringContainsString('IF current_user <> \'audit_maintenance\' THEN', $sql);

        foreach (array_keys(self::documentedTriggers($sql)) as $trigger) {
            $statement = self::statementCreating($sql, $trigger);
            $function  = in_array($trigger, self::maintenanceDeleteTriggers(), true) ? 'audit_log_refuse_delete' : 'audit_log_refuse';

            self::assertStringEndsWith('EXECUTE FUNCTION ' . $function . '()', $statement, $trigger);
            self::assertSame(str_ends_with($trigger, '_no_truncate'), str_contains($statement, 'FOR EACH STATEMENT'), $trigger);
        }
    }

    /**
     * Rows of `[marker, grants]`: each grants block with every grant it makes,
     * as its privileges, its object and its grantees.
     *
     * @return iterable<string, array{0: string, 1: list<array{0: string, 1: string, 2: string}>}>
     */
    public static function provideGrants(): iterable
    {
        $anchor   = 'UPDATE (anchor, anchor_receipt, anchored_at, anchor_error_class)';
        $progress = 'UPDATE (' . implode(', ', self::BATCH_PROGRESS_COLUMNS) . ')';
        $lock     = 'UPDATE (' . implode(', ', self::LOCK_COLUMNS) . ')';
        $writer   = '\'audit_writer\'@\'%\'';
        $upkeep   = '\'audit_maintenance\'@\'%\'';
        $verifier = '\'audit_verifier\'@\'%\'';

        yield 'mysql' => ['mysql-grants', [
            ['SELECT, INSERT', 'app_db.audit_log_entries', $writer],
            ['SELECT, INSERT', 'app_db.audit_log_artifacts', $writer],
            ['SELECT, INSERT', 'app_db.audit_log_checkpoints', $writer],
            [$anchor, 'app_db.audit_log_checkpoints', $writer],
            ['SELECT, INSERT', 'app_db.audit_log_checkpoint_members', $writer],
            ['SELECT, INSERT, UPDATE, DELETE', 'app_db.audit_log_integrity_state', $writer],
            ['SELECT', 'app_db.audit_log_lifecycle', $writer],
            ['SELECT', 'app_db.audit_log_holds', $writer],
            ['SELECT, INSERT', 'app_db.audit_log_import_batches', $writer],
            [$progress, 'app_db.audit_log_import_batches', $writer],
            ['SELECT, DELETE', 'app_db.audit_log_entries', $upkeep],
            ['SELECT, DELETE', 'app_db.audit_log_artifacts', $upkeep],
            ['SELECT, DELETE', 'app_db.audit_log_deliveries', $upkeep],
            ['SELECT', 'app_db.audit_log_checkpoints', $upkeep],
            ['SELECT', 'app_db.audit_log_checkpoint_members', $upkeep],
            ['SELECT', 'app_db.audit_log_integrity_state', $upkeep],
            ['SELECT', 'app_db.audit_log_outbox', $upkeep],
            ['SELECT, INSERT', 'app_db.audit_log_lifecycle', $upkeep],
            ['SELECT, INSERT, DELETE', 'app_db.audit_log_holds', $upkeep],
            ['SELECT', 'app_db.audit_log_lifecycle_lock', $upkeep],
            [$lock, 'app_db.audit_log_lifecycle_lock', $upkeep],
            ['SELECT', 'app_db.audit_log_entries', $verifier],
            ['SELECT', 'app_db.audit_log_artifacts', $verifier],
            ['SELECT', 'app_db.audit_log_checkpoints', $verifier],
            ['SELECT', 'app_db.audit_log_checkpoint_members', $verifier],
            ['SELECT', 'app_db.audit_log_lifecycle', $verifier],
            ['SELECT', 'app_db.audit_log_holds', $verifier],
            ['SELECT, INSERT, UPDATE', 'app_db.audit_log_integrity_state', $verifier],
        ]];

        yield 'pgsql' => ['pgsql-grants', [
            ['CONNECT', 'DATABASE app_db', 'audit_writer, audit_maintenance, audit_verifier'],
            ['USAGE', 'SCHEMA public', 'audit_writer, audit_maintenance, audit_verifier'],
            ['SELECT, INSERT', 'audit_log_entries, audit_log_artifacts, audit_log_checkpoints, audit_log_checkpoint_members', 'audit_writer'],
            [$anchor, 'audit_log_checkpoints', 'audit_writer'],
            ['SELECT, INSERT, UPDATE, DELETE', 'audit_log_integrity_state', 'audit_writer'],
            ['SELECT', 'audit_log_lifecycle, audit_log_holds', 'audit_writer'],
            ['SELECT, INSERT', 'audit_log_import_batches', 'audit_writer'],
            [$progress, 'audit_log_import_batches', 'audit_writer'],
            ['SELECT, DELETE', 'audit_log_entries, audit_log_artifacts, audit_log_deliveries', 'audit_maintenance'],
            ['SELECT', 'audit_log_checkpoints, audit_log_checkpoint_members, audit_log_integrity_state, audit_log_outbox, audit_log_lifecycle_lock', 'audit_maintenance'],
            ['SELECT, INSERT', 'audit_log_lifecycle', 'audit_maintenance'],
            ['SELECT, INSERT, DELETE', 'audit_log_holds', 'audit_maintenance'],
            [$lock, 'audit_log_lifecycle_lock', 'audit_maintenance'],
            ['SELECT', 'audit_log_entries, audit_log_artifacts, audit_log_checkpoints, audit_log_checkpoint_members, audit_log_lifecycle, audit_log_holds', 'audit_verifier'],
            ['SELECT, INSERT, UPDATE', 'audit_log_integrity_state', 'audit_verifier'],
        ]];
    }

    /**
     * Each grants block makes exactly the documented grants: the writer may
     * read and insert the entries, the artifacts and the evidence, update the
     * anchor columns alone, keep the state table, read the journal and the
     * holds, and insert an import batch and update its progress alone; the
     * maintenance user may read and delete the entries, the artifacts and the
     * receipts, read the evidence, the state and the outbox, insert the
     * journal, insert and delete a hold and update the lock's token and time;
     * the verifier may read the evidence and the journal and keep the state.
     *
     * @param  string  $marker
     * @param  list<array{0: string, 1: string, 2: string}>  $grants
     * @return void
     */
    #[DataProvider('provideGrants')]
    public function testTheGrantsAreExactlyTheDocumentedPrivileges(string $marker, array $grants): void
    {
        self::assertSame($grants, self::grantsIn(self::documentedSql($marker)));
    }

    /**
     * Rows of `[marker]`: each grants block.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideGrantMarkers(): iterable
    {
        yield from [
            'mysql' => ['mysql-grants'],
            'pgsql' => ['pgsql-grants'],
        ];
    }

    /**
     * No grant gives a privilege that changes the schema, drops or truncates a
     * table or creates a trigger, and none can be passed on; every statement of
     * a grants block is a grant.
     *
     * @param  string  $marker
     * @return void
     */
    #[DataProvider('provideGrantMarkers')]
    public function testNoGrantGivesDdlOrTruncate(string $marker): void
    {
        $sql = self::documentedSql($marker);

        foreach (self::grantsIn($sql) as [$privileges]) {
            self::assertDoesNotMatchRegularExpression('/\b(?:ALL|ALTER|CREATE|DROP|INDEX|REFERENCES|SUPER|TRIGGER|TRUNCATE)\b/i', $privileges);
        }

        self::assertStringNotContainsStringIgnoringCase('GRANT OPTION', $sql);
        self::assertCount(count(self::grantsIn($sql)), array_filter(explode(';', $sql), static fn (string $statement): bool => trim($statement) !== ''));
    }

    /**
     * The SQLite prune runs in one immediate transaction: it drops the delete
     * triggers of the tables a prune deletes from that have one, the entries'
     * and the artifacts', leaves the line where the prune's own statements go,
     * recreates each trigger exactly as the triggers block creates it, and
     * commits.
     *
     * @return void
     */
    public function testTheSqlitePruneRecreatesTheDocumentedDeleteTrigger(): void
    {
        $prune    = self::documentedSql('sqlite-prune');
        $triggers = self::documentedTriggers(self::documentedSql('sqlite-triggers'));
        $deletes  = array_map(static fn (string $table): string => $table . '_no_delete', self::PRUNED_TABLES);
        $guarded  = array_values(array_filter($deletes, static fn (string $trigger): bool => isset($triggers[$trigger])));

        self::assertSame(self::SQLITE_PRUNED_TRIGGERS, $guarded);
        self::assertStringStartsWith("BEGIN IMMEDIATE;\n", $prune);
        self::assertStringEndsWith("COMMIT;\n", $prune);
        self::assertStringContainsString("\n" . self::PRUNE_STATEMENTS . "\n", $prune);
        self::assertSame(count(self::SQLITE_PRUNED_TRIGGERS), substr_count($prune, 'DROP TRIGGER'));

        foreach (self::SQLITE_PRUNED_TRIGGERS as $trigger) {
            $statement = self::statementCreating($prune, $trigger);
            $drop      = strpos($prune, "\nDROP TRIGGER {$trigger};\n");

            self::assertIsInt($drop, "The prune does not drop {$trigger}.");
            self::assertSame(self::statementCreating(self::documentedSql('sqlite-triggers'), $trigger), $statement);
            self::assertLessThan(strpos($prune, $statement), strpos($prune, self::PRUNE_STATEMENTS));
            self::assertLessThan(strpos($prune, self::PRUNE_STATEMENTS), $drop);
        }
    }

    /**
     * The SQLite prune takes the lifecycle lock before anything else: the
     * statement straight after `BEGIN IMMEDIATE` updates the lock's one row,
     * writing its token and its time alone, before any trigger is dropped, and
     * the lock is named nowhere else.
     *
     * @return void
     */
    public function testTheSqlitePruneTakesTheLockFirst(): void
    {
        $prune = self::documentedSql('sqlite-prune');

        self::assertStringStartsWith("BEGIN IMMEDIATE;\n\n" . self::LOCK_STATEMENT . "\n", $prune);
        self::assertLessThan((int) strpos($prune, 'DROP TRIGGER'), (int) strpos($prune, self::LOCK_STATEMENT));
        self::assertSame(1, substr_count($prune, 'audit_log_lifecycle_lock'));
        self::assertSame(1, preg_match('/^UPDATE audit_log_lifecycle_lock SET (.+) WHERE id = 1;$/', self::LOCK_STATEMENT, $statement));

        $columns = array_map(static fn (string $assignment): string => explode(' = ', $assignment)[0], explode(', ', $statement[1]));

        self::assertSame(self::LOCK_COLUMNS, $columns);
    }

    /**
     * Each engine's import batches update trigger guards exactly the immutable
     * batch columns, in order, and none of the columns the writer updates as an
     * import runs.
     *
     * @param  string  $marker
     * @return void
     */
    #[DataProvider('provideTriggerMarkers')]
    public function testTheTriggersCoverEveryImmutableBatchColumn(string $marker): void
    {
        $trigger = self::statementCreating(self::documentedSql($marker), 'audit_log_import_batches_no_update');

        foreach (self::guardedColumnLists($marker, $trigger) as $list) {
            self::assertSame(array_keys(self::IMMUTABLE_BATCH_COLUMNS), $list);
        }

        foreach (self::BATCH_PROGRESS_COLUMNS as $column) {
            self::assertDoesNotMatchRegularExpression('/\b' . $column . '\b/', $trigger, "The trigger names the progress column {$column}.");
        }
    }

    /**
     * Each engine's lock update trigger guards the lock's `id` alone, so a
     * lifecycle transaction writes its token and its time, and the row is never
     * renumbered.
     *
     * @param  string  $marker
     * @return void
     */
    #[DataProvider('provideTriggerMarkers')]
    public function testTheLockTriggerGuardsItsIdAlone(string $marker): void
    {
        $trigger = self::statementCreating(self::documentedSql($marker), 'audit_log_lifecycle_lock_no_update');

        foreach (self::guardedColumnLists($marker, $trigger) as $list) {
            self::assertSame(['id'], $list);
        }

        foreach (self::LOCK_COLUMNS as $column) {
            self::assertDoesNotMatchRegularExpression('/\b' . $column . '\b/', $trigger, "The trigger names the lock column {$column}.");
        }
    }

    /**
     * Each engine's journal triggers are the members' own, with only the
     * table's name changed: a journal row is never updated or deleted, with no
     * condition, no column list and no maintenance exception.
     *
     * @param  string  $marker
     * @return void
     */
    #[DataProvider('provideTriggerMarkers')]
    public function testTheJournalTriggersRefuseEveryChange(string $marker): void
    {
        $sql = self::documentedSql($marker);

        foreach (['no_update', 'no_delete'] as $suffix) {
            $members = self::statementCreating($sql, 'audit_log_checkpoint_members_' . $suffix);
            $journal = self::statementCreating($sql, 'audit_log_lifecycle_' . $suffix);

            self::assertSame(str_replace('audit_log_checkpoint_members', 'audit_log_lifecycle', $members), $journal);
            self::assertDoesNotMatchRegularExpression('/\bWHEN\b|\bUPDATE OF\b|\bIF\b/', $journal);
        }
    }

    /**
     * Rows of `[marker, suffixes]`: each engine's triggers, with the suffix of
     * each trigger the holds get.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideHoldTriggers(): iterable
    {
        yield from [
            'mysql'  => ['mysql-triggers', ['no_update', 'no_delete']],
            'pgsql'  => ['pgsql-triggers', ['no_update', 'no_delete', 'no_truncate']],
            'sqlite' => ['sqlite-triggers', ['no_update']],
        ];
    }

    /**
     * Each engine's holds triggers are the entries' own, with only the table's
     * name changed: a hold is never updated, and is deleted by the maintenance
     * user alone; SQLite, which has no users, has no holds delete trigger, so a
     * release can delete one.
     *
     * @param  string  $marker
     * @param  list<string>  $suffixes
     * @return void
     */
    #[DataProvider('provideHoldTriggers')]
    public function testTheHoldTriggersAreTheEntriesOwn(string $marker, array $suffixes): void
    {
        $sql = self::documentedSql($marker);

        foreach ($suffixes as $suffix) {
            $entries = self::statementCreating($sql, 'audit_log_entries_' . $suffix);

            self::assertSame(str_replace('audit_log_entries', 'audit_log_holds', $entries), self::statementCreating($sql, 'audit_log_holds_' . $suffix));
        }

        self::assertSame($marker !== 'sqlite-triggers', array_key_exists('audit_log_holds_no_delete', self::documentedTriggers($sql)));
    }

    /**
     * Every column of the checkpoints, the import batches and the lock is
     * either guarded by its update trigger or one the triggers leave writable,
     * exactly as the shapes the schema checks hold, so a column added to a
     * migration fails here until the triggers say which it is.
     *
     * @return void
     */
    public function testEveryGuardedTableColumnIsGuardedOrWritable(): void
    {
        $batches = [...array_keys(self::IMMUTABLE_BATCH_COLUMNS), ...self::BATCH_PROGRESS_COLUMNS];

        self::assertSame(array_keys(TableShape::checkpoints()->columns), [...array_keys(self::IMMUTABLE_COLUMNS), ...self::ANCHOR_COLUMNS]);
        self::assertSame(array_keys(TableShape::lock()->columns), ['id', ...self::LOCK_COLUMNS]);
        self::assertCount(count($batches), array_unique($batches));
        self::assertEqualsCanonicalizing(array_keys(TableShape::importBatches()->columns), $batches);
    }

    /**
     * The storage note's role matrix has a column for each of the writer, the
     * maintenance user and the verifier, and a row for each table the shipped
     * migrations create, under its default name, in order.
     *
     * @return void
     */
    public function testTheRoleMatrixNamesEveryTableAndUser(): void
    {
        $matrix = self::roleMatrix();

        self::assertSame(['Table', ...array_keys(self::USERS)], $matrix[0]);
        self::assertSame(self::PACKAGE_TABLES, array_map(static fn (array $row): string => trim($row[0], '`'), array_slice($matrix, 1)));

        foreach (array_slice($matrix, 1) as $row) {
            self::assertCount(4, $row, $row[0]);
        }
    }

    /**
     * Each grants block gives each user, on each table, exactly the privileges
     * the role matrix lists, and nothing on a table the matrix gives the user
     * none of; the grants the writer needs only in outbox mode are in no block.
     *
     * @param  string  $marker
     * @return void
     */
    #[DataProvider('provideGrantMarkers')]
    public function testEachGrantsBlockGrantsWhatTheRoleMatrixSays(string $marker): void
    {
        $granted = self::privilegesGranted(self::documentedSql($marker));

        self::assertSame([], array_diff(array_keys($granted), self::PACKAGE_TABLES), 'A grant names a table the matrix does not.');

        foreach (array_slice(self::roleMatrix(), 1) as $row) {

            $table = trim($row[0], '`');

            foreach (array_values(self::USERS) as $column => $user) {
                self::assertSame(self::privilegesListed($row[$column + 1]), $granted[$table][$user] ?? [], "{$table}, {$user}");
            }
        }
    }

    /**
     * Each grants block lets the maintenance user alone delete, and only from
     * the tables a prune deletes from and the holds a release deletes; the
     * writer deletes from the integrity state alone, for the sweep, and the
     * verifier deletes nothing.
     *
     * @param  string  $marker
     * @return void
     */
    #[DataProvider('provideGrantMarkers')]
    public function testTheMaintenanceUserDeletesWhatAPruneAndAReleaseDelete(string $marker): void
    {
        $deletes = [];

        foreach (self::privilegesGranted(self::documentedSql($marker)) as $table => $users) {
            foreach ($users as $user => $privileges) {
                if (!in_array('DELETE', $privileges, true)) {
                    continue;
                }

                $deletes[$user][] = $table;
            }
        }

        self::assertEqualsCanonicalizing([...self::PRUNED_TABLES, 'audit_log_holds'], $deletes['audit_maintenance'] ?? []);
        self::assertSame(['audit_log_integrity_state'], $deletes['audit_writer'] ?? []);
        self::assertArrayNotHasKey('audit_verifier', $deletes);
    }

    /**
     * Rows of `[marker, suffixes]`: each engine's triggers, with the suffix of
     * each trigger the entries and the artifacts get.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideEntryLikeTriggers(): iterable
    {
        yield from [
            'mysql'  => ['mysql-triggers', ['no_update', 'no_delete']],
            'pgsql'  => ['pgsql-triggers', ['no_update', 'no_delete', 'no_truncate']],
            'sqlite' => ['sqlite-triggers', ['no_update', 'no_delete']],
        ];
    }

    /**
     * Each engine's artifacts triggers are the entries' own, with only the
     * table's name changed: an update of an artifact is refused always, with no
     * condition and no column list, and a delete is refused but for the
     * maintenance user exactly as an entry's is (on SQLite, refused always).
     *
     * @param  string  $marker
     * @param  list<string>  $suffixes
     * @return void
     */
    #[DataProvider('provideEntryLikeTriggers')]
    public function testTheArtifactTriggersRefuseEveryUpdate(string $marker, array $suffixes): void
    {
        $sql = self::documentedSql($marker);

        foreach ($suffixes as $suffix) {
            $entries = self::statementCreating($sql, 'audit_log_entries_' . $suffix);

            self::assertSame(str_replace('audit_log_entries', 'audit_log_artifacts', $entries), self::statementCreating($sql, 'audit_log_artifacts_' . $suffix));
        }

        $update = self::statementCreating($sql, 'audit_log_artifacts_no_update');

        self::assertDoesNotMatchRegularExpression('/\bWHEN\b|\bUPDATE OF\b|\bIF\b/', $update);

        if ($marker === 'pgsql-triggers') {
            self::assertStringEndsWith('EXECUTE FUNCTION audit_log_refuse()', $update);

            return;
        }

        self::assertStringContainsString('audit_log_artifacts refuses UPDATE', $update);
    }

    /**
     * The script splitter ends a statement at a line ending with the delimiter
     * in force, `;` until a `DELIMITER` line declares another, keeps a body's
     * own semicolons under another delimiter, drops comment lines and empty
     * statements, and keeps a last statement with no delimiter.
     *
     * @return void
     */
    public function testTheScriptSplitterHonoursTheDeclaredDelimiter(): void
    {
        $script = <<<'SQL'
            GRANT SELECT ON t TO u;
            -- a comment
            DELIMITER //

            CREATE TRIGGER t BEFORE UPDATE ON t FOR EACH ROW
            BEGIN
                SIGNAL SQLSTATE '45000';
            END//

            delimiter ;
            SELECT 1;
            ;
            SELECT 2
            SQL;

        self::assertSame([
            'GRANT SELECT ON t TO u',
            "CREATE TRIGGER t BEFORE UPDATE ON t FOR EACH ROW\nBEGIN\n    SIGNAL SQLSTATE '45000';\nEND",
            'SELECT 1',
            'SELECT 2',
        ], self::statementsOf($script));
    }

    /**
     * The MySQL triggers script is split into its sixteen triggers, each whole.
     *
     * @return void
     */
    public function testTheMySqlTriggersSplitIntoTheirTriggers(): void
    {
        $statements = self::statementsOf(self::documentedSql('mysql-triggers'));

        self::assertCount(16, $statements);

        foreach ($statements as $statement) {
            self::assertStringStartsWith('CREATE TRIGGER ', $statement);
            self::assertStringEndsWith('END', $statement);
        }
    }

    /**
     * The names given replace their placeholders as whole words only, quoted or
     * qualified, leave a longer word and any placeholder not given as it is,
     * and with no names the SQL is unchanged.
     *
     * @return void
     */
    public function testTheNamesReplaceWholeWordsOnly(): void
    {
        $sql = 'GRANT SELECT ON app_db.t TO \'audit_writer\'@\'%\'; -- audit_writers app_db_2 \'audit_maintenance\'';

        self::assertSame(
            'GRANT SELECT ON shop.t TO \'writer_1\'@\'%\'; -- audit_writers app_db_2 \'audit_maintenance\'',
            self::withNames($sql, ['app_db' => 'shop', 'audit_writer' => 'writer_1']),
        );
        self::assertSame($sql, self::withNames($sql, []));
    }

    /**
     * A name for anything but a placeholder fails the test, naming it.
     *
     * @return void
     */
    public function testANameForAnythingButAPlaceholderFailsTheTest(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('`root` is not a placeholder of the documented SQL.');

        self::withNames('SELECT 1', ['app_db' => 'shop', 'root' => 'admin']);
    }

    /**
     * Each trigger of the tables, by its name, with the table it is on, for
     * each suffix in order within each table.
     *
     * @param  list<string>  $suffixes
     * @return array<string, string>
     */
    private static function triggersOf(array $suffixes): array
    {
        $triggers = [];

        foreach (self::TABLES as $table) {
            foreach ($suffixes as $suffix) {
                $triggers[$table . '_' . $suffix] = $table;
            }
        }

        return $triggers;
    }

    /**
     * The statement that creates the trigger, from `CREATE TRIGGER` to the end
     * of its body, without the delimiter: the `END` before `//` on MySQL, the
     * `END` that ends a line with `;` on SQLite, and the function call that
     * ends a line with `;` on PostgreSQL.
     *
     * @param  string  $sql
     * @param  string  $trigger
     * @return string
     */
    private static function statementCreating(string $sql, string $trigger): string
    {
        $pattern = '/^CREATE TRIGGER ' . preg_quote($trigger, '/') . '\b.*?(?:\bEND(?=;[ \t]*$|\/\/)|\(\)(?=;[ \t]*$))/ms';

        self::assertSame(1, preg_match($pattern, $sql, $matches), "No statement creates {$trigger}.");

        return $matches[0];
    }

    /**
     * The lists of columns an update trigger compares, as the engine writes
     * them: the old and new columns of each null-safe comparison on MySQL, the
     * old and new rows, or the one old and new column, on PostgreSQL, and the
     * columns of `UPDATE OF` on SQLite.
     *
     * @param  string  $marker
     * @param  string  $trigger
     * @return list<list<string>>
     */
    private static function guardedColumnLists(string $marker, string $trigger): array
    {
        if ($marker === 'mysql-triggers') {
            preg_match_all('/\bOLD\.(\w+) <=> NEW\.(\w+)/', $trigger, $pairs);

            return [$pairs[1], $pairs[2]];
        }

        if ($marker === 'pgsql-triggers' && preg_match('/WHEN \(OLD\.(\w+) IS DISTINCT FROM NEW\.(\w+)\)/', $trigger, $column) === 1) {
            return [[$column[1]], [$column[2]]];
        }

        if ($marker === 'pgsql-triggers') {
            self::assertSame(1, preg_match('/WHEN \(\((.*?)\)\s+IS DISTINCT FROM \((.*?)\)\)/s', $trigger, $rows));

            return [self::listOf((string) preg_replace('/\bOLD\./', '', $rows[1])), self::listOf((string) preg_replace('/\bNEW\./', '', $rows[2]))];
        }

        self::assertSame(1, preg_match('/\bBEFORE UPDATE OF (.*?)\s+ON\s/s', $trigger, $columns));

        return [self::listOf($columns[1])];
    }

    /**
     * The items of a comma-separated list, each trimmed.
     *
     * @param  string  $list
     * @return list<string>
     */
    private static function listOf(string $list): array
    {
        return array_map(trim(...), explode(',', $list));
    }

    /**
     * Every grant the SQL makes, as its privileges, its object and its
     * grantees, each with its whitespace made one space.
     *
     * @param  string  $sql
     * @return list<array{0: string, 1: string, 2: string}>
     */
    private static function grantsIn(string $sql): array
    {
        preg_match_all('/\bGRANT\s+(.+?)\s+ON\s+(.+?)\s+TO\s+(.+?)\s*;/s', $sql, $grants, PREG_SET_ORDER);

        $collapse = static fn (string $text): string => (string) preg_replace('/\s+/', ' ', $text);

        return array_map(static fn (array $grant): array => [$collapse($grant[1]), $collapse($grant[2]), $collapse($grant[3])], $grants);
    }

    /**
     * The names the SQL uses in a user or database position, each once, in
     * order: a MySQL account's user, a grantee, a database a grant or a table
     * name qualifies, a user or role created, and a name a trigger compares the
     * user with.
     *
     * @param  string  $sql
     * @return list<string>
     */
    private static function namesIn(string $sql): array
    {
        $patterns = [
            '/\'(\w+)\'@\'/',
            '/\bON\s+DATABASE\s+(\w+)/i',
            '/\b(\w+)\.audit_log_\w+/',
            '/\b(?:USER|ROLE)\s+(?:IF\s+NOT\s+EXISTS\s+)?\'?(\w+)/i',
            '/(?:<>|!=|\b(?:current_user|session_user|USER\(\))\s*=)\s*\'(\w+)\'/i',
        ];

        $names = [];

        foreach ($patterns as $pattern) {
            preg_match_all($pattern, $sql, $matches);
            array_push($names, ...$matches[1]);
        }

        preg_match_all('/\bTO\s+(\w+(?:\s*,\s*\w+)*)\s*;/i', $sql, $grantees);

        foreach ($grantees[1] as $list) {
            array_push($names, ...self::listOf($list));
        }

        $names = array_values(array_unique($names));

        sort($names);

        return $names;
    }

    /**
     * The delete triggers that let the maintenance user delete, on MySQL and
     * PostgreSQL.
     *
     * @return list<string>
     */
    private static function maintenanceDeleteTriggers(): array
    {
        return array_map(static fn (string $table): string => $table . '_no_delete', self::MAINTENANCE_DELETES);
    }

    /**
     * The rows of the storage note's role matrix, its header first, each as its
     * cells with their whitespace trimmed, without the separator row.
     *
     * @return list<list<string>>
     */
    private static function roleMatrix(): array
    {
        $note = self::note();

        self::assertSame(1, preg_match('/^\| Table +\|.*?\n(?=\n)/ms', $note, $table), 'The storage note has no role matrix.');

        $rows = [];

        foreach (explode("\n", trim($table[0])) as $line) {

            if (preg_match('/^\|[-|]+\|$/', $line) === 1) {
                continue;
            }

            $rows[] = array_map(trim(...), explode('|', trim($line, '|')));
        }

        return $rows;
    }

    /**
     * The privileges a cell of the role matrix lists, in the matrix's order,
     * and none for a cell of grants needed only in outbox mode, which no block
     * makes.
     *
     * @param  string  $cell
     * @return list<string>
     */
    private static function privilegesListed(string $cell): array
    {
        if (str_starts_with($cell, 'outbox mode:')) {
            return [];
        }

        preg_match_all('/`(' . implode('|', self::PRIVILEGES) . ')`/', $cell, $privileges);

        return array_values(array_intersect(self::PRIVILEGES, $privileges[1]));
    }

    /**
     * The privileges the SQL grants, by table, under its name without the
     * database, then by user, each in the role matrix's order; a column grant
     * counts as its privilege, and the database's and the schema's grants are
     * left out.
     *
     * @param  string  $sql
     * @return array<string, array<string, list<string>>>
     */
    private static function privilegesGranted(string $sql): array
    {
        $granted = [];

        foreach (self::grantsIn($sql) as [$privileges, $object, $grantees]) {

            if (preg_match('/^(?:DATABASE|SCHEMA) /', $object) === 1) {
                continue;
            }

            preg_match_all('/\b(' . implode('|', self::PRIVILEGES) . ')\b/', $privileges, $words);

            foreach (self::listOf($object) as $table) {
                foreach (self::listOf($grantees) as $grantee) {

                    $table = (string) preg_replace('/^\w+\./', '', $table);
                    $user  = (string) preg_replace('/^\'(\w+)\'@\'%\'$/', '$1', $grantee);

                    $granted[$table][$user] = array_values(array_intersect(self::PRIVILEGES, [...$granted[$table][$user] ?? [], ...$words[1]]));
                }
            }
        }

        return $granted;
    }

    /**
     * The storage note.
     *
     * @return string
     */
    private static function note(): string
    {
        $note = file_get_contents(dirname(__DIR__, 3) . self::STORAGE_NOTE);

        self::assertIsString($note, 'The storage note cannot be read.');

        return $note;
    }
}
