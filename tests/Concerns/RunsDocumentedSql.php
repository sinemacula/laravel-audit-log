<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;

/**
 * Runs the SQL the storage note documents exactly as it is written there: each
 * block is the fenced `sql` block straight after the HTML comment that names
 * its marker, so the grants and triggers a reader copies are the ones the tests
 * prove.
 *
 * The documented SQL names the database `app_db`, the writer `audit_writer`,
 * the maintenance user `audit_maintenance` and the verifier `audit_verifier`; a
 * test replaces those whole words with its own before it runs a block. A MySQL
 * script is run statement by statement, split on the delimiter it declares, as
 * the `mysql` client splits it; a PostgreSQL or SQLite block is run whole, as
 * one script.
 *
 * On MySQL and PostgreSQL each worker creates logins of its own,
 * `audit_writer_<token>`, `audit_maintenance_<token>` and
 * `audit_verifier_<token>`, which a test drops when it ends, and a test tells a
 * refusal by the grants, the engine's privilege error, from a refusal by a
 * documented trigger, which names its table and statement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RunsDocumentedSql
{
    /** @var string The note the SQL is documented in, from the repository's root. */
    protected const string STORAGE_NOTE = '/docs/design/storage.md';

    /** @var list<string> The names the documented SQL uses, which a test replaces with its own. */
    protected const array PLACEHOLDERS = ['app_db', 'audit_writer', 'audit_maintenance', 'audit_verifier'];

    /** @var array<string, int|string|null> Each immutable checkpoint column, in order, with a value no stored seal has. */
    protected const array IMMUTABLE_COLUMNS = [
        'id'                => '01932b4e-9000-7000-8000-00000000ffff',
        'sequence'          => 99,
        'log_id'            => 'another-log',
        'previous_id'       => '01932b4e-9000-7000-8000-00000000fffe',
        'previous_digest'   => 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        'member_count'      => 99,
        'members_digest'    => 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        'seal_digest'       => 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        'first_recorded_at' => '2026-01-01 00:00:00.000000',
        'last_recorded_at'  => '2026-01-01 00:00:00.000000',
        'sealed_at'         => '2026-01-01 00:00:00.000000',
        'signer'            => 'other',
        'key_id'            => 'other',
        'algorithm_version' => 9,
        'journal_sequence'  => 99,
        'journal_head'      => 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        'signature'         => 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    ];

    /** @var list<string> The checkpoint columns the anchorer writes after a seal is inserted. */
    protected const array ANCHOR_COLUMNS = ['anchor', 'anchor_receipt', 'anchored_at', 'anchor_error_class'];

    /** @var array<string, bool|string> Each immutable import batch column, in order, with a value no stored batch has. */
    protected const array IMMUTABLE_BATCH_COLUMNS = [
        'id'                  => '01932b4e-9000-7000-8000-00000000ffff',
        'source_id'           => 'another-source',
        'source_region'       => 'another-region',
        'input_format'        => 'another-format/v9',
        'importer_type'       => 'another-importer',
        'importer_id'         => 'another-id',
        'reason'              => 'another_reason',
        'external_reference'  => 'another-reference',
        'file_sha256'         => 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        'externally_verified' => true,
        'hold_id'             => '01932b4e-9000-7000-8000-00000000fffe',
        'started_at'          => '2026-01-01 00:00:00.000000',
    ];

    /** @var list<string> The import batch columns the writer updates as an import runs: its status, its counts, its conflict ids and its times. */
    protected const array BATCH_PROGRESS_COLUMNS = ['status', 'lines_read', 'imported', 'duplicates', 'conflicts', 'rejected', 'conflict_ids', 'updated_at', 'finished_at'];

    /** @var list<string> The lifecycle lock columns every lifecycle transaction updates. */
    protected const array LOCK_COLUMNS = ['token', 'locked_at'];

    /** @var string The line of the SQLite prune where the prune's own statements go. */
    protected const string PRUNE_STATEMENTS = '-- the prune\'s deletes (artifacts, receipts, then entries) and its journal row go here';

    /** @var list<int> The MySQL errors that refuse a statement for want of a privilege. */
    protected const array MYSQL_PRIVILEGE_ERRORS = [1142, 1143, 1419];

    /** @var string The password of every login a test creates. */
    protected const string LOGIN_PASSWORD = 'audit-log-documented-password';

    /**
     * The documented block after the marker in the storage note, failing the
     * test when the note has no such block.
     *
     * @param  string  $marker
     * @return string
     */
    protected static function documentedSql(string $marker): string
    {
        $note = file_get_contents(dirname(__DIR__, 2) . self::STORAGE_NOTE);

        self::assertIsString($note, 'The storage note cannot be read.');

        $sql = self::sqlAfterMarker($note, $marker);

        if ($sql === null) {
            self::fail(sprintf('The storage note has no SQL block marked `%s`.', $marker));
        }

        return $sql;
    }

    /**
     * The contents of the fenced `sql` block that follows the marker line in
     * the Markdown, with nothing but blank lines between them, or `null` when
     * the marker is not there exactly once or no such block follows it.
     *
     * @param  string  $markdown
     * @param  string  $marker
     * @return ?string
     */
    protected static function sqlAfterMarker(string $markdown, string $marker): ?string
    {
        $line = '^<!-- sql: ' . preg_quote($marker, '/') . ' -->[ \t]*$';

        if (preg_match_all('/' . $line . '/m', $markdown) !== 1) {
            return null;
        }

        $pattern = '/' . $line . '\n(?:[ \t]*\n)*```sql[ \t]*\n(.*?)^```[ \t]*$/ms';

        return preg_match($pattern, $markdown, $matches) === 1 ? $matches[1] : null;
    }

    /**
     * The documented block after the marker, with each placeholder the names
     * give replaced, as a whole word, by its name.
     *
     * @param  string  $marker
     * @param  array<string, string>  $names
     * @return string
     */
    protected static function documentedSqlFor(string $marker, array $names): string
    {
        return self::withNames(self::documentedSql($marker), $names);
    }

    /**
     * The SQL with each placeholder the names give replaced, as a whole word,
     * by its name, failing the test when the names give anything but a
     * placeholder.
     *
     * @param  string  $sql
     * @param  array<string, string>  $names
     * @return string
     */
    protected static function withNames(string $sql, array $names): string
    {
        $unknown = array_values(array_diff(array_keys($names), self::PLACEHOLDERS));

        if ($unknown !== []) {
            self::fail(sprintf('`%s` is not a placeholder of the documented SQL.', $unknown[0]));
        }

        if ($names === []) {
            return $sql;
        }

        $words = implode('|', array_map(static fn (string $word): string => preg_quote($word, '/'), array_keys($names)));

        return (string) preg_replace_callback('/\b(' . $words . ')\b/', static fn (array $match): string => $names[$match[1]], $sql);
    }

    /**
     * Run the documented block after the marker on the connection, its
     * placeholders replaced by the names given: on MySQL each statement of the
     * script on its own, and on any other engine the whole block at once.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $marker
     * @param  array<string, string>  $names
     * @return void
     */
    protected static function runDocumentedSql(Connection $connection, string $marker, array $names): void
    {
        $sql = self::documentedSqlFor($marker, $names);

        if ($connection->getDriverName() !== 'mysql') {
            self::runScript($connection, $sql);

            return;
        }

        foreach (self::statementsOf($sql) as $statement) {
            self::runScript($connection, $statement);
        }
    }

    /**
     * Run the SQL on the connection's PDO, unprepared, as `unprepared()` does,
     * which takes only literal SQL: this SQL is read from the notes or made
     * from the names they give.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $sql
     * @return void
     */
    protected static function runScript(Connection $connection, string $sql): void
    {
        $connection->getPdo()->exec($sql);
    }

    /**
     * Run the engine's documented grants as an operator runs them: the grants
     * block, then the key block, which grants the owners' key tables, with
     * their placeholders replaced by the names given.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  array<string, string>  $names
     * @return void
     */
    protected static function runDocumentedGrants(Connection $connection, array $names): void
    {
        foreach (self::documentedMarkers($connection, 'grants') as $marker) {
            self::runDocumentedSql($connection, $marker, $names);
        }
    }

    /**
     * Run the engine's documented triggers as an operator runs them: the
     * triggers block, then the key block, which guards the owners' key tables,
     * with their placeholders replaced by the names given.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  array<string, string>  $names
     * @return void
     */
    protected static function runDocumentedTriggers(Connection $connection, array $names): void
    {
        foreach (self::documentedMarkers($connection, 'triggers') as $marker) {
            self::runDocumentedSql($connection, $marker, $names);
        }
    }

    /**
     * Drop every trigger the engine's documented triggers create, the key
     * tables' included, by its documented name, when it exists, and on
     * PostgreSQL the functions they call too.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     */
    protected static function dropDocumentedTriggers(Connection $connection): void
    {
        $driver = $connection->getDriverName();

        foreach (self::documentedMarkers($connection, 'triggers') as $marker) {
            $sql = self::documentedSql($marker);

            foreach (self::documentedTriggers($sql) as $trigger => $table) {
                self::runScript($connection, sprintf($driver === 'pgsql' ? 'DROP TRIGGER IF EXISTS %s ON %s' : 'DROP TRIGGER IF EXISTS %s', $trigger, $table));
            }

            foreach (self::documentedFunctions($sql) as $function) {
                self::runScript($connection, sprintf('DROP FUNCTION IF EXISTS %s() CASCADE', $function));
            }
        }
    }

    /**
     * The markers of the engine's documented blocks of the kind, `grants` or
     * `triggers`, in the order they are run: the engine's block, then its key
     * block.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  'grants'|'triggers'  $kind
     * @return list<string>
     */
    protected static function documentedMarkers(Connection $connection, string $kind): array
    {
        $driver = $connection->getDriverName();

        return [$driver . '-' . $kind, 'keys-' . $kind . ':' . $driver];
    }

    /**
     * Each trigger the SQL creates, by its name, with the table it is on, in
     * the order they are created.
     *
     * @param  string  $sql
     * @return array<string, string>
     */
    protected static function documentedTriggers(string $sql): array
    {
        preg_match_all('/\bCREATE\s+TRIGGER\s+(\w+)\s.*?\bON\s+(\w+)/is', $sql, $matches);

        return array_combine($matches[1], $matches[2]);
    }

    /**
     * The name of each function the SQL creates, in the order they are created.
     *
     * @param  string  $sql
     * @return list<string>
     */
    protected static function documentedFunctions(string $sql): array
    {
        preg_match_all('/\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(\w+)\s*\(/i', $sql, $matches);

        return $matches[1];
    }

    /**
     * The statements of a MySQL script, as the `mysql` client splits them: a
     * statement ends at a line that ends with the delimiter in force, which is
     * `;` until a `DELIMITER` line declares another, and a line that is only a
     * comment is dropped, as are empty statements.
     *
     * @param  string  $script
     * @return list<string>
     */
    protected static function statementsOf(string $script): array
    {
        $delimiter  = ';';
        $statements = [];
        $current    = '';

        foreach (explode("\n", $script) as $line) {

            if (preg_match('/^\s*DELIMITER\s+(\S+)\s*$/i', $line, $declared) === 1) {
                $delimiter = $declared[1];

                continue;
            }

            if (preg_match('/^\s*--/', $line) === 1) {
                continue;
            }

            $trimmed = rtrim($line);

            if (!str_ends_with($trimmed, $delimiter)) {
                $current .= $line . "\n";

                continue;
            }

            $statements[] = $current . substr($trimmed, 0, -strlen($delimiter));
            $current      = '';
        }

        $statements[] = $current;

        return array_values(array_filter(array_map(trim(...), $statements), static fn (string $statement): bool => $statement !== ''));
    }

    /**
     * The names this worker gives the placeholders: the database the root
     * connection is on, and logins named after the writer, the maintenance user
     * and the verifier with the worker's token, `0` outside paratest.
     *
     * @param  \Illuminate\Database\Connection  $root
     * @return array{app_db: string, audit_writer: string, audit_maintenance: string, audit_verifier: string}
     */
    protected static function documentedNames(Connection $root): array
    {
        $token  = getenv('TEST_TOKEN');
        $suffix = '_' . ($token === false || $token === '' ? '0' : $token);

        return [
            'app_db'            => $root->getDatabaseName(),
            'audit_writer'      => 'audit_writer' . $suffix,
            'audit_maintenance' => 'audit_maintenance' . $suffix,
            'audit_verifier'    => 'audit_verifier' . $suffix,
        ];
    }

    /**
     * Create the login, with no privilege at all, dropping one left under its
     * name first: on MySQL a user of any host, on PostgreSQL a role that may
     * log in.
     *
     * @param  \Illuminate\Database\Connection  $root
     * @param  string  $login
     * @return void
     */
    protected static function createLogin(Connection $root, string $login): void
    {
        self::dropLogin($root, $login);

        $root->statement(sprintf(
            $root->getDriverName() === 'mysql' ? 'CREATE USER \'%s\'@\'%%\' IDENTIFIED BY \'%s\'' : 'CREATE ROLE "%s" LOGIN PASSWORD \'%s\'',
            $login,
            self::LOGIN_PASSWORD,
        ));
    }

    /**
     * Drop the login and every privilege it holds, when it exists.
     *
     * @param  \Illuminate\Database\Connection  $root
     * @param  string  $login
     * @return void
     */
    protected static function dropLogin(Connection $root, string $login): void
    {
        if ($root->getDriverName() === 'mysql') {
            $root->statement(sprintf('DROP USER IF EXISTS \'%s\'@\'%%\'', $login));

            return;
        }

        if ($root->scalar('select count(*) from pg_roles where rolname = ?', [$login]) === 0) {
            return;
        }

        $root->statement(sprintf('DROP OWNED BY "%s"', $login));
        $root->statement(sprintf('DROP ROLE "%s"', $login));
    }

    /**
     * Configure a connection that reaches the base connection's database as the
     * login.
     *
     * @param  string  $connection
     * @param  string  $base
     * @param  string  $login
     * @return void
     */
    protected static function connectAs(string $connection, string $base, string $login): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . $connection, [
            ...$config->array('database.connections.' . $base),
            'username' => $login,
            'password' => self::LOGIN_PASSWORD,
        ]);
    }

    /**
     * Run the statement and assert the engine refuses it for want of a
     * privilege: on PostgreSQL SQLSTATE `42501`, and on MySQL a command denied
     * for a table (1142) or a column (1143), or a trigger created without
     * `SUPER` while binary logging is on (1419), never another error under the
     * same SQLSTATE, such as a syntax error.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $statement
     * @param  string  $driver
     * @param  string  $what
     * @return void
     */
    protected static function assertRefusedByTheGrants(\Closure $statement, string $driver, string $what): void
    {
        $refusal = self::refusalOf($statement, $what);
        $message = sprintf('%s is not refused by the grants.', $what);

        if ($driver === 'mysql') {
            self::assertContains($refusal->errorInfo[1] ?? null, self::MYSQL_PRIVILEGE_ERRORS, $message);

            return;
        }

        self::assertSame('42501', $refusal->getCode(), $message);
    }

    /**
     * Run the statement and assert a documented trigger refuses it, naming the
     * table and the statement.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $statement
     * @param  string  $table
     * @param  'DELETE'|'TRUNCATE'|'UPDATE'  $operation
     * @return void
     */
    protected static function assertRefusedByATrigger(\Closure $statement, string $table, string $operation): void
    {
        $refusal = self::refusalOf($statement, sprintf('The %s on %s', $operation, $table));

        self::assertStringContainsString(sprintf('%s refuses %s', $table, $operation), $refusal->getMessage());
    }

    /**
     * The database exception the statement fails with, a query exception or,
     * for a script run on the PDO, the PDO's own, failing the test when it
     * succeeds.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $statement
     * @param  string  $what
     * @return \PDOException
     */
    private static function refusalOf(\Closure $statement, string $what): \PDOException
    {
        try {
            $statement();
        } catch (\PDOException $refusal) {
            return $refusal;
        }

        self::fail(sprintf('%s is not refused.', $what));
    }
}
