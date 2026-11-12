<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;

/**
 * The schema checks of `audit-log:check`: a package table exists on its
 * connection with the shape its shipped migration gives it (see `TableShape`).
 *
 * A column the package does not write is reported too, since no HMAC or seal
 * covers it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SchemaChecks
{
    /** @var array<string, array<string, string>> The type name each engine reports for each type family. */
    private const array FAMILIES = [
        'uuid'     => ['mysql' => 'char', 'pgsql' => 'uuid', 'sqlite' => 'varchar'],
        'string'   => ['mysql' => 'varchar', 'pgsql' => 'varchar', 'sqlite' => 'varchar'],
        'smallint' => ['mysql' => 'smallint', 'pgsql' => 'int2', 'sqlite' => 'integer'],
        'json'     => ['mysql' => 'json', 'pgsql' => 'json', 'sqlite' => 'text'],
        'datetime' => ['mysql' => 'datetime', 'pgsql' => 'timestamp', 'sqlite' => 'datetime'],
        'longtext' => ['mysql' => 'longtext', 'pgsql' => 'text', 'sqlite' => 'text'],
        'integer'  => ['mysql' => 'int', 'pgsql' => 'int4', 'sqlite' => 'integer'],
        'bigint'   => ['mysql' => 'bigint', 'pgsql' => 'int8', 'sqlite' => 'integer'],
        'text'     => ['mysql' => 'text', 'pgsql' => 'text', 'sqlite' => 'text'],
        'boolean'  => ['mysql' => 'tinyint(1)', 'pgsql' => 'bool', 'sqlite' => 'tinyint'],
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
     * Every problem of the table on the connection, against the entries table's
     * shape unless another is given; a missing table is the one problem.
     *
     * @param  string  $connection
     * @param  string  $table
     * @param  ?\SineMacula\Laravel\AuditLog\Console\TableShape  $shape
     * @return list<string>
     */
    public function problems(string $connection, string $table, ?TableShape $shape = null): array
    {
        $shape ??= TableShape::entries();

        $database = $this->database->connection($connection);
        $schema   = $database->getSchemaBuilder();

        if (!$schema->hasTable($table)) {
            $message = sprintf('The %s table `%s` does not exist on connection [%s]; ', $shape->label, $table, $connection)
                . 'publish and run the migrations (`vendor:publish --tag=audit-log-migrations`, then `migrate`).';

            return [$message];
        }

        $prefixed = $database->getTablePrefix() . $table;
        $driver   = $database->getDriverName();

        return [
            ...self::nameProblems($prefixed),
            ...self::columnProblems($shape, $driver, $schema->getColumns($table)),
            ...self::indexProblems($shape, $table, $schema->getIndexes($table)),
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
     * @param  \SineMacula\Laravel\AuditLog\Console\TableShape  $shape
     * @param  string  $driver
     * @param  list<array{name: string, type: string, type_name: string, collation: ?string, nullable: bool}>  $columns
     * @return list<string>
     */
    private static function columnProblems(TableShape $shape, string $driver, array $columns): array
    {
        $actual   = array_column($columns, null, 'name');
        $problems = [];

        foreach ($shape->columns as $name => [$family, $size, $nullable]) {

            if (!isset($actual[$name])) {
                $problems[] = sprintf('Column `%s` is missing.', $name);

                continue;
            }

            $problems = [...$problems, ...self::definitionProblems($driver, $actual[$name], self::expectedType($driver, $family, $size), $nullable)];
        }

        foreach (array_keys(array_diff_key($actual, $shape->columns)) as $name) {
            $problems[] = sprintf($shape->unknownColumn, $name);
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
     * The problems of the primary key, then of each index the migration
     * creates.
     *
     * @param  \SineMacula\Laravel\AuditLog\Console\TableShape  $shape
     * @param  string  $table
     * @param  list<array{name: string, columns: list<string>, unique: bool, primary: bool}>  $indexes
     * @return list<string>
     */
    private static function indexProblems(TableShape $shape, string $table, array $indexes): array
    {
        $primary  = array_values(array_filter($indexes, static fn (array $index): bool => $index['primary']));
        $actual   = array_column($indexes, null, 'name');
        $problems = count($primary) === 1 && $primary[0]['columns'] === $shape->primary ? [] : [sprintf('The primary key must be (%s).', self::listed($shape->primary))];

        foreach ($shape->indexes as $suffix => [$columns, $unique]) {
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
     * The type a column should have on the driver, with its length or precision
     * where the engine records one: never on SQLite or PostgreSQL's `uuid`.
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
     * The type a column has, in `expectedType()`'s form: the engine's type name
     * with its length or precision, except on SQLite.
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
