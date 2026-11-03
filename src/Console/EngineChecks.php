<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;

/**
 * The engine checks of `audit-log:check`: the storage connection's driver is
 * one the package supports (SQLite, MySQL 8.4 or later, PostgreSQL), the
 * connection opens, and on MySQL it runs in strict mode and keeps the entries
 * table on InnoDB.
 *
 * The driver is read from the connection's configuration before anything is
 * opened, so an unsupported driver is reported without a connection. A
 * connection that cannot be opened is reported by the class of what was thrown
 * and never by its message, which can hold a host, a user or a statement.
 * MariaDB is not supported, whether it is configured with its own driver or
 * reached through the `mysql` one: the version is the one the server reports,
 * read from the connection's PDO, because Laravel's `getServerVersion()` strips
 * the MariaDB markers from it on the `mysql` driver. On MySQL the checks read
 * the session's SQL mode and the table's engine, one statement each, whatever
 * the table holds, on the connection's writer, which is the one the store
 * writes through and whose mode decides whether a value that does not fit is
 * refused.
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

    /** @var string Why a connection that cannot be built or opened is a problem, named by the class of what was thrown. */
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
     * Every engine problem of the connection, or none when it is supported: the
     * problem that stops it being checked at all, or on MySQL the strict mode
     * and the entries table's engine.
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
     * The problem that stops anything else being checked on the connection: a
     * driver the package does not support, a connection that cannot be built or
     * opened, or a MySQL server older than 8.4 or MariaDB; `null` when there is
     * none. The message names the connection by its role.
     *
     * @param  string  $connection
     * @param  'outbox'|'storage'  $role
     * @return ?string
     */
    public function blockingProblem(string $connection, string $role = 'storage'): ?string
    {
        // The framework declares nothing for building or opening a connection,
        // though both throw: for a driver it has no connection for, a missing
        // database file or a server that refuses the connection
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
     * The version the connection's server reports, as it reports it: MariaDB
     * keeps its markers (`5.5.5-10.11.6-MariaDB`), which Laravel's
     * `getServerVersion()` strips on the `mysql` driver.
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
     * The MySQL problems of a connection that opens: a session that is not in
     * strict mode, and an entries table on another engine than InnoDB; a
     * missing table is left to the schema checks. Both are read on the writer,
     * never a replica, whose mode and table can differ from those the store
     * writes to.
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
