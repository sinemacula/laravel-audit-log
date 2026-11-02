<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Command;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Definitions\DefinitionSettings;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Privacy\RedactionSettings;
use SineMacula\Laravel\AuditLog\Records\SourceSettings;
use SineMacula\Laravel\AuditLog\Runtime\ContextSettings;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `audit-log:check`: reads every setting the package stores entries and
 * captures records with, the connections and guards they name, the entries
 * table and the integrity keys, and exits non-zero on a problem, for deploy
 * pipelines and readiness probes.
 *
 * Every check runs, so one run lists every problem, each as `[<subject>]
 * <message>`, and a subject without one as `[<subject>] OK`, in this order:
 * `[config]` (the storage and maintenance connection settings, the entries
 * table's name and the integrity, context, source and definition settings, each
 * named by its full path, with `app.key` and `app.previous_keys` read together
 * as the one key ring they make; then the guards the actor is read from, or the
 * default guard when no list is set, each configured in `auth.guards`, skipped
 * when the list is malformed; then the redaction settings, with `app.key` read
 * for them only beside an explicit ring and an empty `audit-log.redaction.key`,
 * since otherwise the integrity settings read it and it is listed once),
 * `[connections]` (the storage and maintenance connections are each configured
 * in `database.connections`, and use the same driver; skipped when a connection
 * setting is malformed), `[schema]` (the storage connection's engine and the
 * entries table's shape; see `EngineChecks` and `SchemaChecks`, skipped when
 * the storage connection or the table's name is malformed or the connection is
 * not configured) and `[integrity]` (a key signs; skipped when the integrity
 * settings are malformed). A malformed context, source, definition or redaction
 * setting skips nothing, since no later subject reads it. It does not warn
 * about a storage connection shared with the application, which every default
 * install would trip. The command writes nothing and prints no secret,
 * statement or binding: a malformed setting is named by its key and never its
 * value, only the name of a connection or guard that is not configured is
 * printed, and a connection that cannot be opened or read is named with the
 * class of what was thrown, never its message.
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

        $checks  = ['config' => [$storageCheck, $maintenanceCheck, $tableCheck, ...self::integritySettingChecks($config), ...self::captureSettingChecks($config)]];
        $storage = !self::fails($storageCheck);

        if ($storage && !self::fails($maintenanceCheck)) {
            $checks['connections'] = [self::connectionCheck($config)];
        }

        $configured = static fn (): array => self::unconfigured($config, 'storage.connection', StorageConnection::resolvedName());

        if ($storage && !self::fails($tableCheck) && !self::fails($configured)) {
            $checks['schema'] = [self::schemaCheck($database)];
        }

        // Integrity settings that pass always give a key that signs, so the
        // subject has no check of its own: it is listed exactly when they pass
        if (!self::fails($integrityCheck)) {
            $checks['integrity'] = [];
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
     * The checks of the integrity settings, one for each, so one run reports
     * every malformed setting: the current key's id, the explicit ring and,
     * when no ring is set, the application's keys it would be derived from. A
     * setting two of them read is listed once, since a run lists a problem
     * once.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<\Closure(): list<string>>
     */
    private static function integritySettingChecks(ConfigRepository $config): array
    {
        $integrity = new IntegritySettings($config);

        return [
            self::reading($integrity->currentKeyId(...)),
            self::reading($integrity->explicitKeys(...)),
            self::reading(static fn (): array => $integrity->explicitKeys() === [] ? $integrity->applicationKeys() : []),
        ];
    }

    /**
     * The checks of the settings records are captured with, one for each, so
     * one run reports every malformed setting: the context settings, the source
     * settings, the definition setting, the guards the actor is read from and
     * the redaction settings. No other subject depends on them.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<\Closure(): list<string>>
     */
    private static function captureSettingChecks(ConfigRepository $config): array
    {
        $context = new ContextSettings($config);
        $source  = new SourceSettings($config);

        return [
            self::reading($context->guards(...)),
            self::reading($context->trustsRequestId(...)),
            self::reading($context->requestIdHeader(...)),
            self::reading($context->trustsTraceparent(...)),
            self::reading($source->id(...)),
            self::reading($source->region(...)),
            self::reading((new DefinitionSettings($config))->requiresRegistered(...)),
            static fn (): array => self::guardProblems($config),
            ...self::redactionSettingChecks($config),
        ];
    }

    /**
     * The checks of the redaction settings, one for each, so one run reports
     * every malformed setting: the configured key names, what is kept of an
     * identifier and of an IP address, the two byte budgets, the explicit key
     * and, beside an explicit ring, the application key the hashes would derive
     * from. A malformed explicit key or ring has the same message as its own
     * check, so a run lists it once.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<\Closure(): list<string>>
     */
    private static function redactionSettingChecks(ConfigRepository $config): array
    {
        $redaction = new RedactionSettings($config);
        $integrity = new IntegritySettings($config);

        return [
            self::reading($redaction->keys(...)),
            self::reading($redaction->identifierMode(...)),
            self::reading($redaction->ipMode(...)),
            self::reading($redaction->maxBytes(...)),
            self::reading($redaction->maxContextBytes(...)),
            self::reading($redaction->explicitKey(...)),
            // Without an integrity ring the integrity checks already read
            // `app.key`, so it is listed once
            static function () use ($redaction, $integrity): array {
                if ($integrity->explicitKeys() !== []) {
                    $redaction->rootKey();
                }

                return [];
            },
        ];
    }

    /**
     * The check that a setting can be read, which its reader refuses with an
     * exception when it is malformed.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(): mixed  $read
     * @return \Closure(): list<string>
     */
    private static function reading(\Closure $read): \Closure
    {
        return static function () use ($read): array {
            $read();

            return [];
        };
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
     * The problem of each guard the actor would be read from that is not
     * configured in `auth.guards`, which `AuthManager` refuses with an
     * exception the capture lets through, or none when the list itself is
     * malformed, the problem the context settings' check reports.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<string>
     */
    private static function guardProblems(ConfigRepository $config): array
    {
        try {
            $guards = (new ContextSettings($config))->guards();
        } catch (\InvalidArgumentException) {
            return [];
        }

        if ($guards === null) {
            return self::defaultGuardProblems($config);
        }

        $problems = [];

        foreach ($guards as $guard) {

            if (self::isGuardConfigured($config, $guard)) {
                continue;
            }

            $problems[] = sprintf('The guard [%s] that `audit-log.actor.guards` names is not configured in `auth.guards`.', $guard);
        }

        return $problems;
    }

    /**
     * The problem of a default guard that is not configured in `auth.guards`,
     * named by its type when it is not a name, or none.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<string>
     */
    private static function defaultGuardProblems(ConfigRepository $config): array
    {
        $guard = $config->get('auth.defaults.guard');

        if (is_string($guard) && self::isGuardConfigured($config, $guard)) {
            return [];
        }

        return [sprintf('The default guard [%s] is not configured in `auth.guards`, and the actor is read from it.', is_string($guard) ? $guard : get_debug_type($guard))];
    }

    /**
     * Whether the guard is configured, looked up by the same dotted path
     * `AuthManager` resolves it by.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  string  $guard
     * @return bool
     */
    private static function isGuardConfigured(ConfigRepository $config, string $guard): bool
    {
        return is_array($config->get("auth.guards.{$guard}"));
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
