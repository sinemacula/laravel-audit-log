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
 * A drift guard for the grants and triggers the storage note documents as SQL;
 * the integration tests run the same blocks on each engine.
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
        'audit_log_subject_keys',
        'audit_log_owner_erasures',
        'audit_log_key_uses',
    ];

    /** @var list<string> The key tables, in the order the role matrix lists them and their triggers are created. */
    private const array KEY_TABLES = ['audit_log_subject_keys', 'audit_log_owner_erasures', 'audit_log_key_uses'];

    /** @var list<string> The subject key columns no update may change, in the order the triggers compare them. */
    private const array KEY_IMMUTABLE_COLUMNS = ['id', 'owner_type', 'owner_id', 'tenant_type', 'tenant_id', 'category', 'unit', 'generation', 'created_at', 'key_id', 'hmac'];

    /** @var list<string> The subject key columns the maintenance user updates, in the order the grants name them. */
    private const array KEY_MUTABLE_COLUMNS = ['state', 'wrapped_key', 'wrap_key_id', 'erasure_id'];

    /** @var list<string> What every engine's subject keys update trigger says of the transitions, whitespace made one space. */
    private const array KEY_TRANSITIONS = [
        'OLD.state NOT IN (\'live\', \'superseded\')',
        '(NEW.state = OLD.state OR (OLD.state = \'live\' AND NEW.state = \'superseded\'))',
        'AND NEW.wrapped_key IS NOT NULL AND NEW.wrap_key_id IS NOT NULL AND NEW.erasure_id IS NULL)',
        'OR (NEW.state = \'erased\' AND NEW.wrapped_key IS NULL AND NEW.wrap_key_id',
        'AND OLD.erasure_id IS NULL AND NEW.erasure_id IS NOT NULL))',
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
     * Rows of `[marker]`: the marker of each documented key block.
     *
     * @return array<string, array{0: string}>
     */
    public static function provideKeyMarkers(): array
    {
        return [
            'keys-grants:mysql'    => ['keys-grants:mysql'],
            'keys-triggers:mysql'  => ['keys-triggers:mysql'],
            'keys-grants:pgsql'    => ['keys-grants:pgsql'],
            'keys-triggers:pgsql'  => ['keys-triggers:pgsql'],
            'keys-triggers:sqlite' => ['keys-triggers:sqlite'],
        ];
    }

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
            ...self::provideKeyMarkers(),
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
     * The scanner returns only an SQL block straight after a unique marker.
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
     * A missing marker fails the test, naming the marker.
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
     * Rows of `[marker, names]`: each block's user and database names,
     * placeholders only.
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

            'keys-grants:mysql'    => ['keys-grants:mysql', ['app_db', 'audit_maintenance', 'audit_verifier', 'audit_writer']],
            'keys-triggers:mysql'  => ['keys-triggers:mysql', ['audit_maintenance']],
            'keys-grants:pgsql'    => ['keys-grants:pgsql', ['audit_maintenance', 'audit_verifier', 'audit_writer']],
            'keys-triggers:pgsql'  => ['keys-triggers:pgsql', ['audit_maintenance']],
            'keys-triggers:sqlite' => ['keys-triggers:sqlite', []],
        ];
    }

    /**
     * Every block names no database or user but the placeholders.
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
     * The name scanner finds each user or database name, none in values.
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
     * Rows of `[statement]`: what the note must state of grants and triggers.
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
            'the key tables'          => ['`privacy.key_uses_table` (`audit_log_key_uses`) are always on the storage connection'],
            'the unit\'s uniqueness'  => ['a composite unique index over the nullable tenant columns would let two tenantless rows share a generation on every'
                . ' engine'],
            'the writer\'s keys'    => ['the writer is granted `SELECT` and `INSERT` on the subject keys and the key uses'],
            'no key update'         => ['it updates no key'],
            'the maintenance keys'  => ['`SELECT` on the subject keys with `UPDATE` of `state`, `wrapped_key`, `wrap_key_id` and `erasure_id` alone'],
            'no key delete'         => ['No role has `DELETE` on the subject keys, the owner erasures or the key uses'],
            'the advisory locks'    => ['The advisory locks need no grant'],
            'the key transitions'   => ['it is one of three transitions'],
            'erased never reopens'  => ['An erased key is refused every update, so an erased generation never reopens'],
            'the keys\' guarantees' => ['Database credentials can still destroy keys, key uses and markers'],
            'the keys\' evidence'   => ['detectable by `audit-log:verify`, never impossible'],
            'the key truncates'     => ['and on each of the three key tables in their own block'],
            'never deleted'         => ['A key row is never deleted, by an erasure, a prune or anything else'],
            'key uses stay'         => ['a prune leaves its rows'],
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
     * The grants and triggers section and the seams sit before the
     * implementation anchors.
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
     * The storage note lists exactly the indexes the schema checks expect.
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
     * Each engine's checkpoints update trigger guards the 17 immutable columns.
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
     * Rows of `[marker, triggers]`: each block's triggers, name and table.
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
     * Each engine creates the documented triggers on every table.
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
     * The PostgreSQL triggers call the documented allow and refuse functions.
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
     * Rows of `[marker, grants]`: each grants block's privileges and grantees.
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
     * Each grants block makes exactly the documented grants for each role.
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
     * No grant changes the schema or is grantable; every statement is a grant.
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
     * The SQLite prune drops and recreates the documented delete triggers in
     * one transaction.
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
     * The SQLite prune takes the lifecycle lock before anything else.
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
     * Each engine's import batches update trigger guards the immutable columns.
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
     * Each engine's lock update trigger guards the lock's `id` alone.
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
     * Each engine's journal triggers refuse every update and delete,
     * unconditionally.
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
     * Rows of `[marker, suffixes]`: each engine's triggers for the holds.
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
     * Each engine's holds triggers are the entries' own; SQLite has no holds
     * delete trigger, so a release can delete one.
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
     * Every guarded table's column is guarded or writable, as the schema holds.
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
     * The role matrix has a column per user and a row per shipped table.
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
     * Each engine's grants give each user exactly what the role matrix lists.
     *
     * @param  string  $marker
     * @return void
     */
    #[DataProvider('provideGrantMarkers')]
    public function testEachGrantsBlockGrantsWhatTheRoleMatrixSays(string $marker): void
    {
        $engine  = explode('-', $marker)[0];
        $granted = self::privilegesGranted(self::documentedSql($marker) . "\n" . self::documentedSql('keys-grants:' . $engine));

        self::assertSame([], array_diff(array_keys($granted), self::PACKAGE_TABLES), 'A grant names a table the matrix does not.');

        foreach (array_slice(self::roleMatrix(), 1) as $row) {

            $table = trim($row[0], '`');

            foreach (array_values(self::USERS) as $column => $user) {
                self::assertSame(self::privilegesListed($row[$column + 1]), $granted[$table][$user] ?? [], "{$table}, {$user}");
            }
        }
    }

    /**
     * Only the maintenance user deletes, from pruned tables and holds; the
     * writer deletes only the sweep's state.
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
     * Rows of `[marker, suffixes]`: each engine's entry and artifact triggers.
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
     * Each engine's artifacts triggers are the entries' own, renamed.
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
     * The role matrix has a row per key table, as the key blocks grant.
     *
     * @return void
     */
    public function testTheRoleMatrixHasARowPerKeyTable(): void
    {
        $rows = array_slice(self::roleMatrix(), -3);

        self::assertSame([
            ['`audit_log_subject_keys`', '`SELECT`, `INSERT`', '`SELECT`, `UPDATE` of `state`, `wrapped_key`, `wrap_key_id` and `erasure_id`', '`SELECT`'],
            ['`audit_log_owner_erasures`', '`SELECT`', '`SELECT`, `INSERT`', '`SELECT`'],
            ['`audit_log_key_uses`', '`SELECT`, `INSERT`', '`SELECT`', '`SELECT`'],
        ], $rows);

        preg_match_all('/`([a-z_]+)`/', $rows[0][2], $columns);

        self::assertSame(self::KEY_MUTABLE_COLUMNS, $columns[1]);

        foreach (['keys-grants:mysql', 'keys-grants:pgsql'] as $marker) {
            self::assertSame(1, preg_match('/\bGRANT UPDATE \(([^)]*)\)/', self::documentedSql($marker), $granted), $marker);
            self::assertSame(self::KEY_MUTABLE_COLUMNS, self::listOf($granted[1]), $marker);
        }
    }

    /**
     * Rows of `[marker, grants]`: each key grants block's grants.
     *
     * @return iterable<string, array{0: string, 1: list<array{0: string, 1: string, 2: string}>}>
     */
    public static function provideKeyGrants(): iterable
    {
        $mutable  = 'UPDATE (state, wrapped_key, wrap_key_id, erasure_id)';
        $writer   = '\'audit_writer\'@\'%\'';
        $upkeep   = '\'audit_maintenance\'@\'%\'';
        $verifier = '\'audit_verifier\'@\'%\'';

        yield 'mysql' => ['keys-grants:mysql', [
            ['SELECT, INSERT', 'app_db.audit_log_subject_keys', $writer],
            ['SELECT', 'app_db.audit_log_owner_erasures', $writer],
            ['SELECT, INSERT', 'app_db.audit_log_key_uses', $writer],
            ['SELECT', 'app_db.audit_log_subject_keys', $upkeep],
            [$mutable, 'app_db.audit_log_subject_keys', $upkeep],
            ['SELECT, INSERT', 'app_db.audit_log_owner_erasures', $upkeep],
            ['SELECT', 'app_db.audit_log_key_uses', $upkeep],
            ['SELECT', 'app_db.audit_log_subject_keys', $verifier],
            ['SELECT', 'app_db.audit_log_owner_erasures', $verifier],
            ['SELECT', 'app_db.audit_log_key_uses', $verifier],
        ]];

        yield 'pgsql' => ['keys-grants:pgsql', [
            ['SELECT, INSERT', 'audit_log_subject_keys, audit_log_key_uses', 'audit_writer'],
            ['SELECT', 'audit_log_owner_erasures', 'audit_writer'],
            ['SELECT', 'audit_log_subject_keys, audit_log_key_uses', 'audit_maintenance'],
            [$mutable, 'audit_log_subject_keys', 'audit_maintenance'],
            ['SELECT, INSERT', 'audit_log_owner_erasures', 'audit_maintenance'],
            ['SELECT', 'audit_log_subject_keys, audit_log_owner_erasures, audit_log_key_uses', 'audit_verifier'],
        ]];
    }

    /**
     * Each key grants block grants exactly the documented privileges.
     *
     * @param  string  $marker
     * @param  list<array{0: string, 1: string, 2: string}>  $grants
     * @return void
     */
    #[DataProvider('provideKeyGrants')]
    public function testEachKeyGrantBlockIsDocumentedPerEngine(string $marker, array $grants): void
    {
        $sql    = self::documentedSql($marker);
        $engine = explode(':', $marker)[1];
        $note   = self::note();

        self::assertSame($grants, self::grantsIn($sql));
        self::assertEqualsCanonicalizing(self::KEY_TABLES, array_keys(self::privilegesGranted($sql)));
        self::assertCount(count($grants), array_filter(explode(';', $sql), static fn (string $statement): bool => trim($statement) !== ''));
        self::assertStringNotContainsStringIgnoringCase('GRANT OPTION', $sql);
        self::assertGreaterThan(strpos($note, '<!-- sql: ' . $engine . '-triggers -->'), strpos($note, '<!-- sql: ' . $marker . ' -->'));

        foreach (self::grantsIn($sql) as [$privileges]) {
            self::assertDoesNotMatchRegularExpression('/\b(?:ALL|ALTER|CREATE|DELETE|DROP|INDEX|REFERENCES|SUPER|TRIGGER|TRUNCATE)\b/i', $privileges);
        }
    }

    /**
     * Rows of `[marker, suffixes]`: each engine's key trigger suffixes.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideKeyTriggers(): iterable
    {
        yield from [
            'mysql'  => ['keys-triggers:mysql', ['no_update', 'no_delete']],
            'pgsql'  => ['keys-triggers:pgsql', ['no_update', 'no_delete', 'no_truncate']],
            'sqlite' => ['keys-triggers:sqlite', ['no_update', 'no_delete']],
        ];
    }

    /**
     * Each engine's key triggers freeze key uses and markers, and guard keys.
     *
     * @param  string  $marker
     * @param  list<string>  $suffixes
     * @return void
     */
    #[DataProvider('provideKeyTriggers')]
    public function testEachKeyTriggerBlockIsDocumentedPerEngine(string $marker, array $suffixes): void
    {
        $sql      = self::documentedSql($marker);
        $engine   = explode(':', $marker)[1];
        $triggers = [];

        foreach (self::KEY_TABLES as $table) {
            foreach ($suffixes as $suffix) {
                $triggers[$table . '_' . $suffix] = $table;
            }
        }

        self::assertSame($triggers, self::documentedTriggers($sql));

        $update    = self::statementCreating($sql, 'audit_log_subject_keys_no_update');
        $collapsed = (string) preg_replace('/\s+/', ' ', $update);

        foreach (self::keyGuardedColumnLists($engine, $update) as $list) {
            self::assertSame(self::KEY_IMMUTABLE_COLUMNS, $list);
        }

        foreach (self::KEY_TRANSITIONS as $clause) {
            self::assertStringContainsString($clause, $collapsed);
        }

        self::assertStringContainsString(match ($engine) {
            'mysql' => 'NEW.wrap_key_id <=> OLD.wrap_key_id',
            'pgsql' => 'NEW.wrap_key_id IS NOT DISTINCT FROM OLD.wrap_key_id',
            default => 'NEW.wrap_key_id IS OLD.wrap_key_id',
        }, $collapsed);

        self::assertSame($engine !== 'sqlite', str_contains($update, '\'audit_maintenance\''));
        self::assertSame([], array_values(array_intersect(self::KEY_IMMUTABLE_COLUMNS, self::KEY_MUTABLE_COLUMNS)));
        self::assertSame(array_keys(TableShape::subjectKeys()->columns), array_values(array_filter(
            array_keys(TableShape::subjectKeys()->columns),
            static fn (string $column): bool => in_array($column, [...self::KEY_IMMUTABLE_COLUMNS, ...self::KEY_MUTABLE_COLUMNS], true),
        )));
        self::assertCount(count(TableShape::subjectKeys()->columns), [...self::KEY_IMMUTABLE_COLUMNS, ...self::KEY_MUTABLE_COLUMNS]);

        self::assertRefusesEveryChange($engine, $sql);
    }

    /**
     * The MySQL key triggers script is split into its six triggers, each whole.
     *
     * @return void
     */
    public function testTheMySqlKeyTriggersSplitIntoTheirTriggers(): void
    {
        $statements = self::statementsOf(self::documentedSql('keys-triggers:mysql'));

        self::assertCount(6, $statements);

        foreach ($statements as $statement) {
            self::assertStringStartsWith('CREATE TRIGGER ', $statement);
            self::assertStringEndsWith('END', $statement);
        }
    }

    /**
     * The script splitter honours `DELIMITER`, comments and a final statement.
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
     * Names replace their placeholders as whole words only.
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
     * Assert the key block refuses every key use, marker change and key delete.
     *
     * @param  string  $engine
     * @param  string  $sql
     * @return void
     */
    private static function assertRefusesEveryChange(string $engine, string $sql): void
    {
        $refusing = [
            'audit_log_subject_keys_no_delete',
            'audit_log_owner_erasures_no_update',
            'audit_log_owner_erasures_no_delete',
            'audit_log_key_uses_no_update',
            'audit_log_key_uses_no_delete',
        ];

        if ($engine === 'pgsql') {
            self::assertSame(['audit_log_keys_refuse'], self::documentedFunctions($sql));

            foreach (array_keys(self::documentedTriggers($sql)) as $trigger) {
                $statement = self::statementCreating($sql, $trigger);

                self::assertStringEndsWith('EXECUTE FUNCTION audit_log_keys_refuse()', $statement, $trigger);
                self::assertSame(str_ends_with($trigger, '_no_truncate'), str_contains($statement, 'FOR EACH STATEMENT'), $trigger);
                self::assertSame($trigger === 'audit_log_subject_keys_no_update', str_contains($statement, 'WHEN'), $trigger);
            }

            return;
        }

        $members = self::documentedSql($engine . '-triggers');

        foreach ($refusing as $trigger) {
            $table  = (string) preg_replace('/_no_(?:update|delete)$/', '', $trigger);
            $suffix = substr($trigger, strlen($table));
            $model  = self::statementCreating($members, 'audit_log_checkpoint_members' . $suffix);

            self::assertSame(str_replace('audit_log_checkpoint_members', $table, $model), self::statementCreating($sql, $trigger), $trigger);
        }
    }

    /**
     * The column lists the subject keys' update trigger holds, per engine.
     *
     * @param  string  $engine
     * @param  string  $trigger
     * @return list<list<string>>
     */
    private static function keyGuardedColumnLists(string $engine, string $trigger): array
    {
        if ($engine === 'pgsql') {
            self::assertSame(1, preg_match('/\((OLD\.id,[^()]*)\)\s+IS DISTINCT FROM\s+\((NEW\.id,[^()]*)\)/s', $trigger, $rows));

            return [self::listOf((string) preg_replace('/\bOLD\./', '', $rows[1])), self::listOf((string) preg_replace('/\bNEW\./', '', $rows[2]))];
        }

        $operator = $engine === 'mysql' ? '<=>' : 'IS';

        self::assertSame(1, preg_match('/NOT \((OLD\.id ' . preg_quote($operator, '/') . ' NEW\.id[^()]*)\)/s', $trigger, $group));

        preg_match_all('/\bOLD\.(\w+) ' . preg_quote($operator, '/') . ' NEW\.(\w+)/', $group[1], $pairs);

        return [$pairs[1], $pairs[2]];
    }

    /**
     * Each trigger of the tables by name, with its table, per suffix in order.
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
     * The statement creating the trigger, up to its delimiter.
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
     * The column lists an update trigger compares, as the engine writes them.
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
     * Every grant in the SQL as privileges, object and grantees.
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
     * The user and database names the SQL uses, each once, in order.
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
     * The MySQL and PostgreSQL delete triggers the maintenance user passes.
     *
     * @return list<string>
     */
    private static function maintenanceDeleteTriggers(): array
    {
        return array_map(static fn (string $table): string => $table . '_no_delete', self::MAINTENANCE_DELETES);
    }

    /**
     * The role matrix's rows, header first, as trimmed cells, no separator.
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
     * A matrix cell's privileges in order; none for outbox-only grants.
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
     * The privileges the SQL grants, by table then user; column grants count,
     * database and schema grants are left out.
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
