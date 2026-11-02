<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\MySqlConnection;
use Illuminate\Database\PostgresConnection;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\SQLiteConnection;
use Illuminate\Database\SQLiteDatabaseDoesNotExistException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\EngineChecks;
use Tests\Fixtures\Database\VersionReportingPdo;
use Tests\TestCase;

/**
 * Feature tests for the engine checks of `audit-log:check`: the drivers and
 * MySQL versions the package supports, a connection that cannot be opened,
 * named without its message, and on MySQL strict mode and the entries table's
 * engine.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EngineChecks::class)]
final class EngineChecksTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The entries table the shipped migration creates. */
    private const string TABLE = 'audit_log_entries';

    /** @var string A table a test creates on another engine than InnoDB. */
    private const string MYISAM_TABLE = 'audit_myisam_entries';

    /** @var string What a MySQL session that is not in strict mode is reported as. */
    private const string NOT_STRICT = 'The storage connection does not run in strict mode; set `strict` to true on the connection,'
        . ' so a value that does not fit fails instead of being cut.';

    /** @var string What a MySQL server too old to support, or MariaDB, is reported as, given its version. */
    private const string UNSUPPORTED_MYSQL = 'MySQL %s is not supported; use MySQL 8.4 or later (MariaDB is not supported).';

    /** @var string What a table on MyISAM is reported as. */
    private const string NOT_INNODB = 'The entries table uses the MyISAM engine; it must use InnoDB.';

    /**
     * Rows of `[a server version, whether it is supported]`: MySQL 8.4 and
     * later only, and never MariaDB, however it reports itself.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideMySqlVersions(): iterable
    {
        yield from [
            'the first 8.4 release'              => ['8.4.0', true],
            'a later 8.4 release'                => ['8.4.11', true],
            'an innovation release'              => ['9.1.0', true],
            'a release with a suffix'            => ['8.4.3-log', true],
            'the last 8.0 release line'          => ['8.0.36', false],
            'an 8.3 innovation release'          => ['8.3.0', false],
            'MariaDB'                            => ['10.11.6-MariaDB', false],
            'MariaDB behind the 5.5.5 prefix'    => ['5.5.5-10.11.6-MariaDB', false],
            'MariaDB in lower case'              => ['11.4.2-mariadb-log', false],
            'a version that is not one'          => ['unknown', false],
            'a version without its patch number' => ['8.4', false],
        ];
    }

    /**
     * Only MySQL 8.4 or later is supported.
     *
     * @param  string  $version
     * @param  bool  $supported
     * @return void
     */
    #[DataProvider('provideMySqlVersions')]
    public function testOnlyMySql84OrLaterIsSupported(string $version, bool $supported): void
    {
        self::assertSame($supported, EngineChecks::supportsMySqlVersion($version));
    }

    /**
     * The engine the suite runs against is supported, opens, and on MySQL is
     * strict and keeps the table on InnoDB.
     *
     * @return void
     */
    public function testTheTestEngineIsSupported(): void
    {
        self::assertNull($this->checks()->blockingProblem(self::CONNECTION));
        self::assertSame([], $this->checks()->problems(self::CONNECTION, self::TABLE));
    }

    /**
     * A table that does not exist is left to the schema checks, so the engine
     * has no problem with it.
     *
     * @return void
     */
    public function testAMissingTableIsNoEngineProblem(): void
    {
        self::assertSame([], $this->checks()->problems(self::CONNECTION, 'audit_absent_entries'));
    }

    /**
     * On MySQL a connection that is not in strict mode is a problem, since a
     * value that does not fit would be cut instead of refused.
     *
     * @return void
     */
    public function testOnMySqlANonStrictConnectionIsAProblem(): void
    {
        $this->onlyOnMySql();

        $config = app(ConfigRepository::class);

        $config->set('database.connections.loose', [...$config->array('database.connections.' . self::CONNECTION), 'strict' => false]);

        self::assertSame([
            'The storage connection does not run in strict mode; set `strict` to true on the connection, so a value that does not fit fails instead of being cut.',
        ], $this->checks()->problems('loose', self::TABLE));
    }

    /**
     * On MySQL a connection in strict mode by `STRICT_ALL_TABLES` alone is
     * strict.
     *
     * @return void
     */
    public function testOnMySqlEitherStrictModeIsStrict(): void
    {
        $this->onlyOnMySql();

        $config = app(ConfigRepository::class);

        $config->set('database.connections.all', [...$config->array('database.connections.' . self::CONNECTION), 'modes' => ['STRICT_ALL_TABLES']]);

        self::assertSame([], $this->checks()->problems('all', self::TABLE));
    }

    /**
     * On MySQL an entries table on another engine than InnoDB is a problem,
     * since its writes would not be transactional.
     *
     * @return void
     */
    public function testOnMySqlATableOnAnotherEngineIsAProblem(): void
    {
        $this->onlyOnMySql();

        Schema::create(self::MYISAM_TABLE, static function (Blueprint $table): void {
            $table->string('id', 36);
            $table->engine('MyISAM');
        });

        try {
            self::assertSame(['The entries table uses the MyISAM engine; it must use InnoDB.'], $this->checks()->problems(self::CONNECTION, self::MYISAM_TABLE));
        } finally {
            Schema::dropIfExists(self::MYISAM_TABLE);
        }
    }

    /**
     * On MySQL the table's engine is read under the connection's prefix.
     *
     * @return void
     */
    public function testOnMySqlTheEngineIsReadUnderThePrefix(): void
    {
        $this->onlyOnMySql();

        $config = app(ConfigRepository::class);

        $config->set('database.connections.prefixed', [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'audit_']);

        Schema::create(self::MYISAM_TABLE, static function (Blueprint $table): void {
            $table->string('id', 36);
            $table->engine('MyISAM');
        });

        try {
            self::assertSame(['The entries table uses the MyISAM engine; it must use InnoDB.'], $this->checks()->problems('prefixed', 'myisam_entries'));
        } finally {
            Schema::dropIfExists(self::MYISAM_TABLE);
        }
    }

    /**
     * Rows of `[a driver the package does not support]`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnsupportedDrivers(): iterable
    {
        yield from [
            'SQL Server' => ['sqlsrv'],
            'MariaDB'    => ['mariadb'],
        ];
    }

    /**
     * A connection on a driver the package does not support is the one problem,
     * and the connection is never opened to find it.
     *
     * @param  string  $driver
     * @return void
     */
    #[DataProvider('provideUnsupportedDrivers')]
    public function testAnUnsupportedDriverIsAProblem(string $driver): void
    {
        app(ConfigRepository::class)->set('database.connections.legacy', [
            'driver'   => $driver,
            'host'     => '127.0.0.1',
            'port'     => '1',
            'database' => 'audit',
            'username' => 'audit',
            'password' => 'audit',
        ]);

        self::assertSame(
            [sprintf('The storage connection uses the %s driver, which is not supported; use SQLite, MySQL 8.4 or later, or PostgreSQL.', $driver)],
            $this->checks()->problems('legacy', self::TABLE),
        );
        self::assertInstanceOf(\Closure::class, DB::connection('legacy')->getRawPdo());
    }

    /**
     * A connection that cannot be opened is the one problem, naming the class
     * of what was thrown and never its message, which holds the path.
     *
     * @return void
     */
    public function testAnUnreachableConnectionIsReportedWithoutItsMessage(): void
    {
        $path = sys_get_temp_dir() . '/audit-log-missing-' . getmypid() . '.sqlite';

        app(ConfigRepository::class)->set('database.connections.unreachable', ['driver' => 'sqlite', 'database' => $path, 'prefix' => '']);

        $problems = $this->checks()->problems('unreachable', self::TABLE);

        self::assertSame(['The storage connection [unreachable] could not be opened (' . SQLiteDatabaseDoesNotExistException::class . ').'], $problems);
        self::assertSame($problems[0], $this->checks()->blockingProblem('unreachable'));
        self::assertStringNotContainsString($path, $problems[0]);
    }

    /**
     * A server that refuses the connection is named by the class of what was
     * thrown, never by the host or the user its message holds.
     *
     * @return void
     */
    public function testARefusedConnectionIsReportedWithoutItsHostOrUser(): void
    {
        app(ConfigRepository::class)->set('database.connections.refused', [
            'driver'   => 'pgsql',
            'host'     => '127.0.0.1',
            'port'     => '1',
            'database' => 'audit',
            'username' => 'audit_writer_user',
            'password' => 'audit-writer-password',
        ]);

        $problems = $this->checks()->problems('refused', self::TABLE);

        self::assertSame(['The storage connection [refused] could not be opened (PDOException).'], $problems);
    }

    /**
     * A connection that cannot even be built, on a driver Laravel has no
     * connection for, is a problem named by its class, never a crash.
     *
     * @return void
     */
    public function testAConnectionThatCannotBeBuiltIsAProblem(): void
    {
        app(ConfigRepository::class)->set('database.connections.unknown', ['driver' => 'oracle', 'database' => 'audit']);

        self::assertSame(['The storage connection [unknown] could not be opened (InvalidArgumentException).'], $this->checks()->problems('unknown', self::TABLE));
    }

    /**
     * Rows of
     * `[the server's version, the session's SQL mode, the table's engine, the problems a MySQL server answering so has]`,
     * checked on any engine the suite runs against through a MySQL connection
     * whose PDO reports the version as a server would, so Laravel's stripping
     * of MariaDB's markers is part of every row.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: ?string, 3: list<string>}>
     */
    public static function provideMySqlAnswers(): iterable
    {
        yield from [
            'a strict 8.4 server keeping the table on InnoDB' => ['8.4.11', 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION', 'InnoDB', []],
            'strict by STRICT_ALL_TABLES alone'               => ['8.4.11', 'ONLY_FULL_GROUP_BY,STRICT_ALL_TABLES', 'InnoDB', []],
            'an engine named in lower case'                   => ['8.4.11', 'STRICT_TRANS_TABLES', 'innodb', []],
            'a table that is missing'                         => ['8.4.11', 'STRICT_TRANS_TABLES', null, []],
            'a session without strict mode'                   => ['8.4.11', 'NO_ENGINE_SUBSTITUTION', 'InnoDB', [self::NOT_STRICT]],
            'a session without any mode'                      => ['8.4.11', '', 'InnoDB', [self::NOT_STRICT]],
            'no answer for the mode'                          => ['8.4.11', null, 'InnoDB', [self::NOT_STRICT]],
            'a table on MyISAM'                               => ['8.4.11', 'STRICT_TRANS_TABLES', 'MyISAM', [self::NOT_INNODB]],
            'both at once'                                    => ['9.1.0', '', 'MyISAM', [self::NOT_STRICT, self::NOT_INNODB]],
            'MySQL 8.0, which nothing else is checked on'     => ['8.0.36', '', 'MyISAM', [sprintf(self::UNSUPPORTED_MYSQL, '8.0.36')]],
            'MariaDB through the mysql driver'                => self::refusedVersion('5.5.5-10.11.6-MariaDB'),
            'MariaDB 11 without the 5.5.5 prefix'             => self::refusedVersion('11.4.2-MariaDB'),
            'MariaDB with a log suffix'                       => self::refusedVersion('11.4.2-MariaDB-log'),
            'a server that reports no version'                => [null, 'STRICT_TRANS_TABLES', 'InnoDB', [sprintf(self::UNSUPPORTED_MYSQL, '')]],
        ];
    }

    /**
     * A MySQL connection's problems are those of its server's version, then of
     * its session's SQL mode and its table's engine.
     *
     * @param  ?string  $version
     * @param  ?string  $modes
     * @param  ?string  $engine
     * @param  list<string>  $problems
     * @return void
     */
    #[DataProvider('provideMySqlAnswers')]
    public function testAMySqlConnectionIsCheckedForItsVersionModeAndEngine(?string $version, ?string $modes, ?string $engine, array $problems): void
    {
        $this->fake('mysql', [$version, $modes, $engine]);

        self::assertSame($problems, $this->checks()->problems('fake', self::TABLE));
    }

    /**
     * Only a MySQL server too old to support, or MariaDB, stops the other
     * checks; strict mode and the engine do not.
     *
     * @return void
     */
    public function testOnlyAnUnsupportedVersionBlocksAMySqlConnection(): void
    {
        $this->fake('mysql', ['8.4.0', '', 'MyISAM']);

        self::assertNull($this->checks()->blockingProblem('fake'));

        $this->app?->make(DatabaseManager::class)->purge('fake');

        $this->fake('mysql', ['8.3.0', 'STRICT_TRANS_TABLES', 'InnoDB']);

        self::assertSame(sprintf(self::UNSUPPORTED_MYSQL, '8.3.0'), $this->checks()->blockingProblem('fake'));
    }

    /**
     * MariaDB reached through the `mysql` driver is refused by the version its
     * server reports, although Laravel's `getServerVersion()` strips the
     * markers that name it on that driver, which a check reading it would pass
     * as MySQL 10.11.
     *
     * @return void
     */
    public function testMariaDbThroughTheMySqlDriverIsRefusedThoughLaravelStripsItsVersion(): void
    {
        $this->fake('mysql', ['5.5.5-10.11.6-MariaDB', 'STRICT_TRANS_TABLES', 'InnoDB']);

        self::assertSame('10.11.6', DB::connection('fake')->getServerVersion());
        self::assertSame(sprintf(self::UNSUPPORTED_MYSQL, '5.5.5-10.11.6-MariaDB'), $this->checks()->blockingProblem('fake'));
    }

    /**
     * On MySQL a connection split between a writer and a replica is checked on
     * its writer: a strict replica does not hide a writer that is not, since
     * the writer is where the store's values are cut or refused.
     *
     * @return void
     */
    public function testOnMySqlTheWriterIsCheckedNotTheReplica(): void
    {
        $this->onlyOnMySql();

        $config = app(ConfigRepository::class);
        $base   = $config->array('database.connections.' . self::CONNECTION);

        $config->set('database.connections.split_loose', [...$base, 'read' => ['strict' => true], 'write' => ['strict' => false]]);
        $config->set('database.connections.split_strict', [...$base, 'read' => ['strict' => false], 'write' => ['strict' => true]]);

        self::assertSame([self::NOT_STRICT], $this->checks()->problems('split_loose', self::TABLE));
        self::assertSame([], $this->checks()->problems('split_strict', self::TABLE));
    }

    /**
     * On MySQL the session's SQL mode and the table's engine are one statement
     * each, both asked of the writer and never of a replica, the engine read
     * for the table under the connection's prefix.
     *
     * @return void
     */
    public function testAMySqlConnectionIsAskedOneStatementForEachCheck(): void
    {
        $asked = $this->fake('mysql', ['8.4.11', 'STRICT_TRANS_TABLES', 'InnoDB'], 'app_');

        $this->checks()->problems('fake', self::TABLE);

        self::assertSame([
            ['select @@session.sql_mode', [], false],
            ['select engine from information_schema.tables where table_schema = database() and table_name = ?', ['app_audit_log_entries'], false],
        ], $asked->getArrayCopy());
    }

    /**
     * Rows of `[a supported driver other than MySQL]`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOtherDrivers(): iterable
    {
        yield from [
            'PostgreSQL' => ['pgsql'],
            'SQLite'     => ['sqlite'],
        ];
    }

    /**
     * A connection on another supported driver is not asked about a SQL mode or
     * an engine, and its server's version is not read as MySQL's.
     *
     * @param  string  $driver
     * @return void
     */
    #[DataProvider('provideOtherDrivers')]
    public function testAnotherSupportedDriverIsAskedNothingOfMySql(string $driver): void
    {
        $asked = $this->fake($driver, ['8.0.36', '', 'MyISAM']);

        self::assertSame([], $this->checks()->problems('fake', self::TABLE));
        self::assertSame([], $asked->getArrayCopy());
    }

    /**
     * The engine checks on the application's connections.
     *
     * @return \SineMacula\Laravel\AuditLog\Console\EngineChecks
     */
    private function checks(): EngineChecks
    {
        $database = $this->app?->make(DatabaseManager::class);

        assert($database instanceof DatabaseManager);

        return new EngineChecks($database);
    }

    /**
     * Register a connection named `fake` of the driver's own connection class,
     * whose PDO reports the server's version as given and which answers the
     * session's SQL mode and the table's engine as given, with no server behind
     * it, and return the statements it is asked, each with whether it was asked
     * of a replica.
     *
     * @param  string  $driver
     * @param  array{0: ?string, 1: ?string, 2: ?string}  $answers
     * @param  string  $prefix
     * @return \ArrayObject<int, array{0: string, 1: array<array-key, scalar|null>, 2: bool}>
     */
    private function fake(string $driver, array $answers, string $prefix = ''): \ArrayObject
    {
        /** @var \ArrayObject<int, array{0: string, 1: array<array-key, scalar|null>, 2: bool}> $asked */
        $asked = new \ArrayObject;

        $class = match ($driver) {
            'mysql' => MySqlConnection::class,
            'pgsql' => PostgresConnection::class,
            default => SQLiteConnection::class,
        };

        /** @var \Illuminate\Database\Connection&\Mockery\MockInterface $connection */
        $connection = \Mockery::mock($class . '[scalar]', [new VersionReportingPdo($answers[0]), '', $prefix, ['driver' => $driver]]);

        $connection->shouldReceive('scalar')->andReturnUsing(static function (string $query, array $bindings = [], bool $useReadPdo = true) use ($answers, $asked): ?string {
            $asked->append([$query, $bindings, $useReadPdo]);

            return str_contains($query, 'sql_mode') ? $answers[1] : $answers[2];
        });

        app(ConfigRepository::class)->set('database.connections.fake', ['driver' => $driver, 'database' => ':memory:', 'prefix' => $prefix]);

        $this->app?->make(DatabaseManager::class)->extend('fake', static fn (): Connection => $connection);

        return $asked;
    }

    /**
     * The row of a strict server keeping the table on InnoDB whose version
     * alone is refused.
     *
     * @param  string  $version
     * @return array{0: string, 1: string, 2: string, 3: list<string>}
     */
    private static function refusedVersion(string $version): array
    {
        return [$version, 'STRICT_TRANS_TABLES', 'InnoDB', [sprintf(self::UNSUPPORTED_MYSQL, $version)]];
    }

    /**
     * Skip the test unless the suite runs against MySQL.
     *
     * @return void
     */
    private function onlyOnMySql(): void
    {
        if (DB::connection(self::CONNECTION)->getDriverName() === 'mysql') {
            return;
        }

        self::markTestSkipped('Only MySQL has a strict mode and a storage engine per table.');
    }
}
