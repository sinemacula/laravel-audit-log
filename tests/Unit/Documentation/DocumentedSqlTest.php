<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Concerns\RunsDocumentedSql;

/**
 * A drift guard for the grants and triggers the storage note documents as SQL:
 * each of the six blocks is marked and found by its marker alone, names no
 * database or user but the placeholders, grants exactly the documented
 * privileges and nothing that changes the schema, and creates exactly the
 * documented triggers; each engine's checkpoints trigger guards every immutable
 * column and no anchor column; the SQLite prune recreates the very trigger it
 * drops; and the note states what it must, in its own section, in order.
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
    private const array TABLES = ['audit_log_entries', 'audit_log_checkpoints', 'audit_log_checkpoint_members'];

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
            'mysql-grants'    => ['mysql-grants', ['app_db', 'audit_maintenance', 'audit_writer']],
            'mysql-triggers'  => ['mysql-triggers', ['audit_maintenance']],
            'pgsql-grants'    => ['pgsql-grants', ['app_db', 'audit_maintenance', 'audit_writer']],
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
     * blocks use, quoted or not, and none in a message or a column.
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
            'the placeholders'           => ['Replace `app_db`, `audit_writer` and `audit_maintenance` with your database and users.'],
            'the writer\'s grants'       => ['is granted `SELECT` and `INSERT` on the entries, the checkpoints and the members'],
            'the writer\'s anchor grant' => ['`UPDATE` on the checkpoints\' four anchor columns alone, and `SELECT`'],
            'the writer\'s state grants' => ['and `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the integrity state table'],
            'the sweep\'s delete'        => ['the `DELETE` is for the sweep, which forgets its cursor when it completes'],
            'the maintenance user'       => ['the maintenance user is granted `DELETE` on the entries alone, because pruning keeps every checkpoint and member'],
            'no DDL'                     => ['no DDL for the application user'],
            'no documented DDL'          => ['no documented user holds `DROP`, `TRUNCATE`, `TRIGGER` or `ALTER`'],
            'the verify user'            => ['the user that runs `audit-log:verify` also needs `SELECT`, `INSERT` and `UPDATE` on the integrity state table'],
            'the definer'                => ['`CURRENT_USER()` in a trigger is the definer, so the MySQL triggers read `USER()`'],
            'the client\'s name'         => ['`USER()` is the name the client gave, so on MySQL the grants, not the triggers, are the boundary'],
            'grants alone'               => ['or prefer grants alone'],
            'truncate'                   => ['A row trigger never fires on `TRUNCATE`'],
            'truncate on MySQL'          => ['On MySQL `TRUNCATE` needs `DROP`, which no documented user holds, and fires no trigger'],
            'the owner'                  => ['The tables\' owner can drop the triggers: they guard against the application\'s users, not against the owner'],
            'SQLite'                     => ['SQLite has no users, so its triggers refuse every update and delete, with no maintenance exception'],
            'pruning on SQLite'          => ['with no maintenance exception, and pruning on SQLite drops and recreates the delete trigger'],
            'a failed prune'             => ['A prune that fails before `COMMIT` is rolled back, and the rollback restores the trigger'],
            'column grants'              => ['column grants exist on MySQL and PostgreSQL only'],
            'the anchor columns'         => ['The anchor columns are the only ones written after a seal is inserted'],
            'the integrity tables'       => ['are always on the storage connection, beside the entries they describe, and no setting moves them'],
            'the recorded index'         => ['`_recorded_index` over `recorded_at` and `id`'],
            'the existing two tables'    => ['`delivery.deliveries_table` (`audit_log_deliveries` by default) is always on the storage connection'],
            'the existing outbox'        => ['`delivery.outbox.table` (`audit_log_outbox` by default) is on `delivery.outbox.connection`'],
            'the existing outbox grants' => ['In outbox mode the writer also needs'],
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
     * Each engine's checkpoints update trigger guards exactly the 15 immutable
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
        yield from [
            'mysql'        => ['mysql-triggers', self::triggersOf(['no_update', 'no_delete'])],
            'pgsql'        => ['pgsql-triggers', self::triggersOf(['no_update', 'no_delete', 'no_truncate'])],
            'sqlite'       => ['sqlite-triggers', self::triggersOf(['no_update', 'no_delete'])],
            'sqlite prune' => ['sqlite-prune', ['audit_log_entries_no_delete' => 'audit_log_entries']],
        ];
    }

    /**
     * Each engine creates an update and a delete trigger on each of the three
     * tables, and PostgreSQL a truncate trigger on each too, each named after
     * its table; the SQLite prune creates the entries' delete trigger alone.
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
     * The PostgreSQL triggers call the two documented functions: the entries'
     * delete trigger the one that lets the maintenance user through, by
     * `current_user`, and every other trigger the one that refuses everyone;
     * the truncate triggers fire once per statement.
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
            $function  = $trigger === 'audit_log_entries_no_delete' ? 'audit_log_refuse_delete' : 'audit_log_refuse';

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
        $anchor = 'UPDATE (anchor, anchor_receipt, anchored_at, anchor_error_class)';
        $writer = '\'audit_writer\'@\'%\'';
        $upkeep = '\'audit_maintenance\'@\'%\'';

        yield 'mysql' => ['mysql-grants', [
            ['SELECT, INSERT', 'app_db.audit_log_entries', $writer],
            ['SELECT, INSERT', 'app_db.audit_log_checkpoints', $writer],
            [$anchor, 'app_db.audit_log_checkpoints', $writer],
            ['SELECT, INSERT', 'app_db.audit_log_checkpoint_members', $writer],
            ['SELECT, INSERT, UPDATE, DELETE', 'app_db.audit_log_integrity_state', $writer],
            ['SELECT, DELETE', 'app_db.audit_log_entries', $upkeep],
            ['SELECT', 'app_db.audit_log_checkpoints', $upkeep],
            ['SELECT', 'app_db.audit_log_checkpoint_members', $upkeep],
        ]];

        yield 'pgsql' => ['pgsql-grants', [
            ['CONNECT', 'DATABASE app_db', 'audit_writer, audit_maintenance'],
            ['USAGE', 'SCHEMA public', 'audit_writer, audit_maintenance'],
            ['SELECT, INSERT', 'audit_log_entries, audit_log_checkpoints, audit_log_checkpoint_members', 'audit_writer'],
            [$anchor, 'audit_log_checkpoints', 'audit_writer'],
            ['SELECT, INSERT, UPDATE, DELETE', 'audit_log_integrity_state', 'audit_writer'],
            ['SELECT, DELETE', 'audit_log_entries', 'audit_maintenance'],
            ['SELECT', 'audit_log_checkpoints, audit_log_checkpoint_members', 'audit_maintenance'],
        ]];
    }

    /**
     * Each grants block makes exactly the documented grants: the writer may
     * read and insert the entries and the evidence, update the anchor columns
     * alone and keep the state table; the maintenance user may read and delete
     * the entries and read the evidence.
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
     * The SQLite prune runs in one immediate transaction: it drops the entries'
     * delete trigger, leaves the line where the prune's own statements go,
     * recreates the trigger exactly as the triggers block creates it, and
     * commits.
     *
     * @return void
     */
    public function testTheSqlitePruneRecreatesTheDocumentedDeleteTrigger(): void
    {
        $prune     = self::documentedSql('sqlite-prune');
        $statement = self::statementCreating($prune, 'audit_log_entries_no_delete');

        self::assertStringStartsWith("BEGIN IMMEDIATE;\n", $prune);
        self::assertStringEndsWith("COMMIT;\n", $prune);
        self::assertStringContainsString("\nDROP TRIGGER audit_log_entries_no_delete;\n", $prune);
        self::assertStringContainsString("\n" . self::PRUNE_STATEMENTS . "\n", $prune);
        self::assertSame(self::statementCreating(self::documentedSql('sqlite-triggers'), 'audit_log_entries_no_delete'), $statement);
        self::assertLessThan(strpos($prune, $statement), strpos($prune, self::PRUNE_STATEMENTS));
        self::assertLessThan(strpos($prune, self::PRUNE_STATEMENTS), strpos($prune, 'DROP TRIGGER'));
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
     * The MySQL triggers script is split into its six triggers, each whole.
     *
     * @return void
     */
    public function testTheMySqlTriggersSplitIntoTheirTriggers(): void
    {
        $statements = self::statementsOf(self::documentedSql('mysql-triggers'));

        self::assertCount(6, $statements);

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
     * The lists of columns the checkpoints update trigger compares, as the
     * engine writes them: the old and new columns of each null-safe comparison
     * on MySQL, the old and new rows on PostgreSQL, and the columns of `UPDATE
     * OF` on SQLite.
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
            '/(?:<>|!=|=)\s*\'(\w+)\'/',
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
