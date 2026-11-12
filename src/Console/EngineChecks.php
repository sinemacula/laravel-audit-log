<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;

/**
 * The engine checks of `audit-log:check`: a supported driver and server, a
 * connection that opens and, on MySQL, strict mode and an InnoDB entries table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EngineChecks
{
    /** @var list<string> The drivers the package supports. */
    private const array DRIVERS = ['sqlite', 'mysql', 'pgsql'];

    /** @var string The earliest MySQL version the package supports. */
    private const string MYSQL_FLOOR = '8.4.0';

    /** @var list<string> The SQL modes, either of which makes MySQL refuse a value that does not fit. */
    private const array STRICT_MODES = ['STRICT_TRANS_TABLES', 'STRICT_ALL_TABLES'];

    /** @var string The storage engine the entries table must use on MySQL. */
    private const string ENGINE = 'InnoDB';

    /** @var string The problem of a connection that cannot be built or opened. */
    private const string UNOPENED = 'The %s connection [%s] could not be opened (%s).';

    /** @var string Why a driver the package does not support is a problem. */
    private const string UNSUPPORTED_DRIVER = 'The %s connection [%s] uses the %s driver, which is not supported; use SQLite, MySQL 8.4 or later, or PostgreSQL.';

    /** @var string Why a MySQL server older than 8.4, or MariaDB, is a problem. */
    private const string UNSUPPORTED_MYSQL = 'The %s connection [%s] runs MySQL %s, which is not supported; use MySQL 8.4 or later (MariaDB is not supported).';

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
     * Whether a MySQL server version is supported: 8.4.0 or later, and never
     * MariaDB, whose versions MySQL's numbering does not describe.
     *
     * @param  string  $version
     * @return bool
     */
    public static function supportsMySqlVersion(string $version): bool
    {
        if (stripos($version, 'mariadb') !== false || preg_match('/\A\d+\.\d+\.\d+/', $version, $matches) !== 1) {
            return false;
        }

        return version_compare($matches[0], self::MYSQL_FLOOR, '>=');
    }

    /**
     * Every engine problem of the connection: the blocking one, or on MySQL the
     * strict mode and the entries table's engine.
     *
     * @param  string  $connection
     * @param  string  $table
     * @return list<string>
     */
    public function problems(string $connection, string $table): array
    {
        $blocking = $this->blockingProblem($connection);

        if ($blocking !== null) {
            return [$blocking];
        }

        $database = $this->database->connection($connection);

        return $database->getDriverName() === 'mysql' ? self::mySqlProblems($database, $table) : [];
    }

    /**
     * The problem that stops anything else being checked on the connection, or
     * `null`; the message names the connection by its role.
     *
     * @param  string  $connection
     * @param  'outbox'|'storage'  $role
     * @return ?string
     */
    public function blockingProblem(string $connection, string $role = 'storage'): ?string
    {
        // Building or opening a connection throws undeclared exceptions whose
        // message can hold a host or user, so only the class is reported
        try {
            $database = $this->database->connection($connection);
            $driver   = $database->getDriverName();
            $version  = in_array($driver, self::DRIVERS, true) ? self::serverVersion($database) : null;
        } catch (\Throwable $exception) { // @phpstan-ignore catch.neverThrown
            return sprintf(self::UNOPENED, $role, $connection, get_debug_type($exception));
        }

        return match (true) {
            $version === null                                             => sprintf(self::UNSUPPORTED_DRIVER, $role, $connection, $driver),
            $driver  === 'mysql' && !self::supportsMySqlVersion($version) => sprintf(self::UNSUPPORTED_MYSQL, $role, $connection, $version),
            default                                                       => null,
        };
    }

    /**
     * The version as the server reports it; Laravel's `getServerVersion()`
     * strips the MariaDB markers on the `mysql` driver.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return string
     */
    private static function serverVersion(Connection $connection): string
    {
        $version = $connection->getPdo()->getAttribute(\PDO::ATTR_SERVER_VERSION);

        return is_string($version) ? $version : '';
    }

    /**
     * The MySQL strict mode and engine problems, read on the writer since a
     * replica's can differ; a missing table is left to the schema checks.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @return list<string>
     */
    private static function mySqlProblems(Connection $connection, string $table): array
    {
        $problems = [];

        $modes = $connection->scalar('select @@session.sql_mode', [], false);

        if (array_intersect(self::STRICT_MODES, explode(',', is_string($modes) ? $modes : '')) === []) {
            $problems[] = 'The storage connection does not run in strict mode; set `strict` to true on the connection, so a value that does not fit fails instead of being cut.';
        }

        $engine = $connection->scalar(
            'select engine from information_schema.tables where table_schema = database() and table_name = ?',
            [$connection->getTablePrefix() . $table],
            false,
        );

        if (is_string($engine) && strcasecmp($engine, self::ENGINE) !== 0) {
            $problems[] = sprintf('The entries table uses the %s engine; it must use InnoDB.', $engine);
        }

        return $problems;
    }
}
