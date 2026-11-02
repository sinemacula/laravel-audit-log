<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Command;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `audit-log:check`: reads every setting the package stores entries with, the
 * connections they name, the entries table and the integrity keys, and exits
 * non-zero on a problem, for deploy pipelines and readiness probes.
 *
 * Every check runs, so one run lists every problem, each as
 * `[<subject>] <message>`, and a subject without one as `[<subject>] OK`, in
 * this order: `[config]` (the storage and maintenance connection settings, the
 * entries table's name and the integrity settings, each named by its full
 * path), `[connections]` (the storage and maintenance connections are each
 * configured in `database.connections`, and use the same driver; skipped when a
 * connection setting is malformed), `[schema]` (the storage connection's engine
 * and the entries table's shape; see `EngineChecks` and `SchemaChecks`, skipped
 * when the storage connection or the table's name is malformed or the
 * connection is not configured) and `[integrity]` (a key signs; skipped when
 * the integrity settings are malformed). It does not warn about a storage
 * connection shared with the application, which every default install would
 * trip. The command writes nothing and prints no secret, statement or binding:
 * a connection that cannot be opened or read is named with the class of what
 * was thrown, never its message.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[AsCommand(name: 'audit-log:check')]
final class CheckCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'audit-log:check';

    /** @var string The console command description. */
    protected $description = 'Check the audit log settings, connections, schema and integrity keys';

    /**
     * Run every check, then report each problem, or that a subject has none.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @return int
     */
    public function handle(ConfigRepository $config, DatabaseManager $database): int
    {
        $found = [];

        foreach ($this->checks($config, $database) as $subject => $checks) {

            $problems = [];

            foreach ($checks as $check) {
                $problems = [...$problems, ...self::problemsOf($check)];
            }

            $found[$subject] = self::prefixed($subject, array_keys(array_flip($problems)));
        }

        foreach ($found as $subject => $problems) {

            if ($problems === []) {
                $this->info("[{$subject}] OK");
            }

            foreach ($problems as $problem) {
                $this->error($problem);
            }
        }

        return array_merge(...array_values($found)) === [] ? self::SUCCESS : self::FAILURE;
    }

    /**
     * The checks, by subject, in the order they are reported, leaving out a
     * subject whose settings `config` already reports as malformed.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @return array<string, list<\Closure(): list<string>>>
     */
    private function checks(ConfigRepository $config, DatabaseManager $database): array
    {
        [$storageCheck, $maintenanceCheck, $tableCheck, $integrityCheck] = self::settingChecks($config);

        $checks  = ['config' => [$storageCheck, $maintenanceCheck, $tableCheck, $integrityCheck]];
        $storage = !self::fails($storageCheck);

        if ($storage && !self::fails($maintenanceCheck)) {
            $checks['connections'] = [self::connectionCheck($config)];
        }

        $configured = static fn (): array => self::unconfigured($config, 'storage.connection', StorageConnection::resolvedName());

        if ($storage && !self::fails($tableCheck) && !self::fails($configured)) {
            $checks['schema'] = [self::schemaCheck($database)];
        }

        if (!self::fails($integrityCheck)) {
            $checks['integrity'] = [
                static function () use ($config): array {
                    (new KeyRing(new IntegritySettings($config)))->signingKey();

                    return [];
                },
            ];
        }

        return $checks;
    }

    /**
     * The checks of the settings themselves, in order: the storage connection,
     * the maintenance connection, the entries table's name and the integrity
     * settings.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return array{0: \Closure(): list<string>, 1: \Closure(): list<string>, 2: \Closure(): list<string>, 3: \Closure(): list<string>}
     */
    private static function settingChecks(ConfigRepository $config): array
    {
        return [
            static function (): array {
                StorageConnection::name();

                return [];
            },
            static function (): array {
                StorageConnection::forMaintenance();

                return [];
            },
            static function (): array {
                EntrySettings::table();

                return [];
            },
            static function () use ($config): array {
                (new IntegritySettings($config))->validate();

                return [];
            },
        ];
    }

    /**
     * The check of the connections the settings name: each is configured in
     * `database.connections`, and a maintenance connection of its own uses the
     * storage connection's driver. It reads configuration only.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return \Closure(): list<string>
     */
    private static function connectionCheck(ConfigRepository $config): \Closure
    {
        return static function () use ($config): array {
            $storage     = StorageConnection::resolvedName();
            $maintenance = StorageConnection::resolvedMaintenanceName();
            $own         = $maintenance !== $storage;

            $problems = [
                ...self::unconfigured($config, 'storage.connection', $storage),
                ...($own ? self::unconfigured($config, 'storage.maintenance_connection', $maintenance) : []),
            ];

            return $problems === [] && $own ? self::driverProblems($config, $maintenance, $storage) : $problems;
        };
    }

    /**
     * The check of the storage connection's engine and the entries table on it;
     * the table is checked only when the engine is supported and the connection
     * opens, and a statement that fails is named by its class.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @return \Closure(): list<string>
     */
    private static function schemaCheck(DatabaseManager $database): \Closure
    {
        return static function () use ($database): array {
            $connection = StorageConnection::resolvedName();
            $table      = EntrySettings::table();
            $engine     = new EngineChecks($database);

            // The framework declares nothing for a statement that fails, though
            // it throws a `QueryException`, whose message holds the statement
            try {
                $blocking = $engine->blockingProblem($connection);

                if ($blocking !== null) {
                    return [$blocking];
                }

                return [...$engine->problems($connection, $table), ...(new SchemaChecks($database))->problems($connection, $table)];
            } catch (\PDOException $exception) { // @phpstan-ignore catch.neverThrown
                return [sprintf('The storage connection [%s] could not be read (%s).', $connection, $exception::class)];
            }
        };
    }

    /**
     * The problem of a maintenance connection on another driver than the
     * storage connection, which cannot reach the same database, or none.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  string  $maintenance
     * @param  string  $storage
     * @return list<string>
     */
    private static function driverProblems(ConfigRepository $config, string $maintenance, string $storage): array
    {
        [$theirs, $ours] = [self::driverOf($config, $maintenance), self::driverOf($config, $storage)];

        if ($theirs === $ours) {
            return [];
        }

        $message = sprintf('The maintenance connection [%s] uses the %s driver and the storage connection [%s] the %s driver;', $maintenance, $theirs, $storage, $ours)
            . ' both must reach the same database.';

        return [$message];
    }

    /**
     * The problem of a connection a setting names that is not configured in
     * `database.connections`, or none.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  string  $setting
     * @param  string  $connection
     * @return list<string>
     */
    private static function unconfigured(ConfigRepository $config, string $setting, string $connection): array
    {
        if (is_array($config->get("database.connections.{$connection}"))) {
            return [];
        }

        return [sprintf('The connection [%s] that `audit-log.%s` names is not configured in `database.connections`.', $connection, $setting)];
    }

    /**
     * The driver a configured connection names, or the type of what it names
     * instead.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  string  $connection
     * @return string
     */
    private static function driverOf(ConfigRepository $config, string $connection): string
    {
        $driver = $config->get("database.connections.{$connection}.driver");

        return is_string($driver) ? $driver : get_debug_type($driver);
    }

    /**
     * Whether a check finds a problem.
     *
     * @param  \Closure(): list<string>  $check
     * @return bool
     */
    private static function fails(\Closure $check): bool
    {
        return self::problemsOf($check) !== [];
    }

    /**
     * The problems a check finds: those it returns, or the message of the
     * exception it throws.
     *
     * @param  \Closure(): list<string>  $check
     * @return list<string>
     */
    private static function problemsOf(\Closure $check): array
    {
        try {
            return $check();
        } catch (\Exception $exception) {
            return [$exception->getMessage()];
        }
    }

    /**
     * The problems, each prefixed with the subject checked.
     *
     * @param  string  $subject
     * @param  list<string>  $problems
     * @return list<string>
     */
    private static function prefixed(string $subject, array $problems): array
    {
        return array_map(static fn (string $problem): string => "[{$subject}] {$problem}", $problems);
    }
}
