<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;

/**
 * The schema checks of `audit-log:check`: the entries table exists on the
 * storage connection with the shape the shipped migration gives it.
 *
 * The table's prefixed name must fit every index name. Each column the package
 * writes must exist with its type family, its length or precision (which SQLite
 * does not record), and its nullability, and on MySQL with the binary, NO PAD
 * collation `utf8mb4_0900_bin`; a column the package does not write is reported
 * too, because no entry's HMAC covers it. The primary key must be `id` alone,
 * and each index the migration creates must exist under its name, over its
 * columns in order, unique or not as the migration made it; an index the
 * application added is its own. A missing table is one problem, and nothing
 * else is checked. The checks read the table's existence, its columns and its
 * indexes, whatever the table holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SchemaChecks
{
    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each column the package writes, in order, with its type family, its length or precision, and its nullability. */
    private const array COLUMNS = [
        'id'                => ['uuid', 36, false],
        'record_version'    => ['smallint', null, false],
        'event'             => ['string', 191, false],
        'event_version'     => ['smallint', null, false],
        'category'          => ['string', 64, false],
        'outcome'           => ['string', 16, false],
        'reason'            => ['string', 64, true],
        'actor_type'        => ['string', 191, true],
        'actor_id'          => ['string', 191, true],
        'subject_type'      => ['string', 191, true],
        'subject_id'        => ['string', 191, true],
        'principal_type'    => ['string', 191, true],
        'principal_id'      => ['string', 191, true],
        'tenant_type'       => ['string', 191, true],
        'tenant_id'         => ['string', 191, true],
        'credential_id'     => ['string', 191, true],
        'guard'             => ['string', 64, true],
        'session_id'        => ['string', 191, true],
        'request_id'        => ['string', 64, true],
        'trace_id'          => ['string', 32, true],
        'correlation_id'    => ['string', 191, true],
        'origin'            => ['string', 16, true],
        'provenance'        => ['string', 16, false],
        'source_id'         => ['string', 64, false],
        'source_region'     => ['string', 32, true],
        'source_record_id'  => ['string', 191, true],
        'import_batch_id'   => ['uuid', 36, true],
        'ip'                => ['string', 255, true],
        'user_agent'        => ['string', 512, true],
        'context'           => ['json', null, true],
        'properties'        => ['json', null, true],
        'occurred_at'       => ['datetime', 6, false],
        'recorded_at'       => ['datetime', 6, false],
        'integrity_version' => ['smallint', null, false],
        'key_id'            => ['string', 32, false],
        'hmac'              => ['string', 64, false],
    ];

    /** @var array<string, array<string, string>> The type name each engine reports for each type family. */
    private const array FAMILIES = [
        'uuid'     => ['mysql' => 'char', 'pgsql' => 'uuid', 'sqlite' => 'varchar'],
        'string'   => ['mysql' => 'varchar', 'pgsql' => 'varchar', 'sqlite' => 'varchar'],
        'smallint' => ['mysql' => 'smallint', 'pgsql' => 'int2', 'sqlite' => 'integer'],
        'json'     => ['mysql' => 'json', 'pgsql' => 'json', 'sqlite' => 'text'],
        'datetime' => ['mysql' => 'datetime', 'pgsql' => 'timestamp', 'sqlite' => 'datetime'],
    ];

    /** @var array<string, array{0: non-empty-list<string>, 1: bool}> Each index the migration creates, by its name's suffix, with its columns in order and its uniqueness. */
    private const array INDEXES = [
        '_actor_index'     => [['actor_type', 'actor_id', 'occurred_at'], false],
        '_subject_index'   => [['subject_type', 'subject_id', 'occurred_at'], false],
        '_principal_index' => [['principal_type', 'principal_id', 'occurred_at'], false],
        '_tenant_index'    => [['tenant_type', 'tenant_id', 'occurred_at'], false],
        '_event_index'     => [['event', 'occurred_at'], false],
        '_category_index'  => [['category', 'occurred_at'], false],
        '_correlate_index' => [['correlation_id'], false],
        '_occurred_index'  => [['occurred_at'], false],
        '_source_unique'   => [['source_id', 'source_record_id'], true],
    ];

    /** @var string The collation every character column must use on MySQL: binary, and NO PAD. */
    private const string COLLATION = 'utf8mb4_0900_bin';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** The connections the checks read. */
        private DatabaseManager $database,
    ) {}

    /**
     * Every problem of the entries table on the connection, or none when it has
     * the shipped migration's shape; a missing table is the one problem.
     *
     * @param  string  $connection
     * @param  string  $table
     * @return list<string>
     */
    public function problems(string $connection, string $table): array
    {
        $database = $this->database->connection($connection);
        $schema   = $database->getSchemaBuilder();

        if (!$schema->hasTable($table)) {
            $message = sprintf('The entries table `%s` does not exist on connection [%s]; ', $table, $connection)
                . 'publish and run the migrations (`vendor:publish --tag=audit-log-migrations`, then `migrate`).';

            return [$message];
        }

        $prefixed = $database->getTablePrefix() . $table;
        $driver   = $database->getDriverName();

        return [
            ...self::nameProblems($prefixed),
            ...self::columnProblems($driver, $schema->getColumns($table)),
            ...self::indexProblems($table, $schema->getIndexes($table)),
        ];
    }

    /**
     * The problem of a prefixed table name too long for every index name to
     * fit, or none.
     *
     * @param  string  $prefixed
     * @return list<string>
     */
    private static function nameProblems(string $prefixed): array
    {
        if (strlen($prefixed) <= EntrySettings::MAX_TABLE_CHARACTERS) {
            return [];
        }

        return [sprintf('The prefixed table name `%s` is %d characters; at most %d fit every index name.', $prefixed, strlen($prefixed), EntrySettings::MAX_TABLE_CHARACTERS)];
    }

    /**
     * The problems of the table's columns: each column the package writes that
     * is missing or defined otherwise, then each column it does not write.
     *
     * @param  string  $driver
     * @param  list<array{name: string, type: string, type_name: string, collation: ?string, nullable: bool}>  $columns
     * @return list<string>
     */
    private static function columnProblems(string $driver, array $columns): array
    {
        $actual   = array_column($columns, null, 'name');
        $problems = [];

        foreach (self::COLUMNS as $name => [$family, $size, $nullable]) {

            if (!isset($actual[$name])) {
                $problems[] = sprintf('Column `%s` is missing.', $name);

                continue;
            }

            $problems = [...$problems, ...self::definitionProblems($driver, $actual[$name], self::expectedType($driver, $family, $size), $nullable)];
        }

        foreach (array_keys(array_diff_key($actual, self::COLUMNS)) as $name) {
            $problems[] = sprintf('Column `%s` is not one the package writes, so no entry\'s HMAC covers it.', $name);
        }

        return $problems;
    }

    /**
     * The problems of one column the package writes: its type, its nullability
     * and, on MySQL, its collation.
     *
     * @param  string  $driver
     * @param  array{name: string, type: string, type_name: string, collation: ?string, nullable: bool}  $column
     * @param  string  $type
     * @param  bool  $nullable
     * @return list<string>
     */
    private static function definitionProblems(string $driver, array $column, string $type, bool $nullable): array
    {
        $problems = [];
        $actual   = self::actualType($driver, $column);

        if ($actual !== $type) {
            $problems[] = sprintf('Column `%s` is %s; expected %s.', $column['name'], $actual, $type);
        }

        if ($column['nullable'] !== $nullable) {
            $problems[] = sprintf($nullable ? 'Column `%s` is not nullable; it must be.' : 'Column `%s` is nullable; it must not be.', $column['name']);
        }

        if ($driver === 'mysql' && $column['collation'] !== null && $column['collation'] !== self::COLLATION) {
            $problems[] = sprintf('Column `%s` uses collation %s; expected %s.', $column['name'], $column['collation'], self::COLLATION);
        }

        return $problems;
    }

    /**
     * The problems of the table's indexes: a primary key other than `id` alone,
     * then those of each index the migration creates.
     *
     * @param  string  $table
     * @param  list<array{name: string, columns: list<string>, unique: bool, primary: bool}>  $indexes
     * @return list<string>
     */
    private static function indexProblems(string $table, array $indexes): array
    {
        $primary  = array_values(array_filter($indexes, static fn (array $index): bool => $index['primary']));
        $actual   = array_column($indexes, null, 'name');
        $problems = count($primary) === 1 && $primary[0]['columns'] === ['id'] ? [] : ['The primary key must be (`id`).'];

        foreach (self::INDEXES as $suffix => [$columns, $unique]) {
            $problems = [...$problems, ...self::problemsOfIndex($table . $suffix, $actual[$table . $suffix] ?? null, $columns, $unique)];
        }

        return $problems;
    }

    /**
     * The problems of one index the migration creates: it is missing, covers
     * other columns or another order, or differs in uniqueness.
     *
     * @param  string  $name
     * @param  ?array{columns: list<string>, unique: bool}  $index
     * @param  non-empty-list<string>  $columns
     * @param  bool  $unique
     * @return list<string>
     */
    private static function problemsOfIndex(string $name, ?array $index, array $columns, bool $unique): array
    {
        if ($index === null) {
            return [sprintf('Index `%s` is missing.', $name)];
        }

        $uniqueness = $unique ? 'Index `%s` must be unique.' : 'Index `%s` must not be unique.';

        return [
            ...($index['columns'] === $columns ? [] : [sprintf('Index `%s` covers (%s); expected (%s).', $name, self::listed($index['columns']), self::listed($columns))]),
            ...($index['unique'] === $unique ? [] : [sprintf($uniqueness, $name)]),
        ];
    }

    /**
     * The type a column is expected to have on the driver: the family's type
     * name, with its length or precision where the engine records one (SQLite
     * records none, and PostgreSQL's native `uuid` has none).
     *
     * @param  string  $driver
     * @param  string  $family
     * @param  ?int  $size
     * @return string
     */
    private static function expectedType(string $driver, string $family, ?int $size): string
    {
        $type = self::FAMILIES[$family][$driver] ?? $family;

        return $size === null || $driver === 'sqlite' || $type === 'uuid' ? $type : "{$type}({$size})";
    }

    /**
     * The type a column has, in the form `expectedType()` gives: the type name
     * the engine reports, with the length or precision its full type carries,
     * except on SQLite.
     *
     * @param  string  $driver
     * @param  array{type: string, type_name: string}  $column
     * @return string
     */
    private static function actualType(string $driver, array $column): string
    {
        if ($driver === 'sqlite' || preg_match('/\(\s*\d+\s*(?:,\s*\d+\s*)?\)/', $column['type'], $matches) !== 1) {
            return $column['type_name'];
        }

        return $column['type_name'] . str_replace(' ', '', $matches[0]);
    }

    /**
     * The columns, each in backticks, separated by commas.
     *
     * @param  list<string>  $columns
     * @return string
     */
    private static function listed(array $columns): string
    {
        return implode(', ', array_map(static fn (string $column): string => "`{$column}`", $columns));
    }
}
