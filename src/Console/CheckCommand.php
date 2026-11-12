<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Command;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Definitions\DefinitionSettings;
use SineMacula\Laravel\AuditLog\Delivery\DeliverySettings;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorSettings;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Privacy\RedactionSettings;
use SineMacula\Laravel\AuditLog\Records\SourceSettings;
use SineMacula\Laravel\AuditLog\Runtime\ContextSettings;
use SineMacula\Laravel\AuditLog\Stores\FailureSettings;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `audit-log:check`: reports every malformed setting and every connection,
 * schema, integrity, delivery, lifecycle and privacy problem.
 *
 * A setting is named by its key and a failure by its exception class, never a
 * value.
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
    protected $signature = <<<'EOD'
        audit-log:check
                {--freshness : Check only that sealing, the sweep, verification, retention, anchoring and the outbox are still running}
                {--json : With --freshness, write each signal as one JSON object}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Check the audit log settings, connections, schema, integrity keys, tables and anchor, delivery, lifecycle and privacy';

    /**
     * Run every check and report each subject's problems, then the notes; or,
     * with `--freshness`, run the freshness checks alone.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Console\DeliveryChecks  $delivery
     * @param  \SineMacula\Laravel\AuditLog\Console\IntegrityChecks  $integrity
     * @param  \SineMacula\Laravel\AuditLog\Console\LifecycleChecks  $lifecycle
     * @param  \SineMacula\Laravel\AuditLog\Console\PrivacyChecks  $privacy
     * @param  \SineMacula\Laravel\AuditLog\Console\ProductionChecks  $production
     * @param  \SineMacula\Laravel\AuditLog\Console\FreshnessChecks  $freshness
     * @return int
     *
     * @throws \JsonException
     */
    public function handle(
        ConfigRepository $config,
        DatabaseManager $database,
        DeliveryChecks $delivery,
        IntegrityChecks $integrity,
        LifecycleChecks $lifecycle,
        PrivacyChecks $privacy,
        ProductionChecks $production,
        FreshnessChecks $freshness,
    ): int {
        if ($this->option('freshness') === true) {
            return $this->freshness($freshness);
        }

        if ($this->option('json') === true) {
            $this->error('`--json` is given only with `--freshness`.');

            return self::INVALID;
        }

        $found = [];

        foreach ([...$this->checks($config, $database, $delivery, $integrity, $lifecycle, $privacy), ...$production->subject()] as $subject => $checks) {

            $problems = array_merge(...array_map(self::problemsOf(...), $checks));

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

        $this->notes($delivery, $lifecycle, $privacy, $production);

        return array_merge(...array_values($found)) === [] ? self::SUCCESS : self::FAILURE;
    }

    /**
     * The checks, by subject, in the order they are reported, leaving out a
     * subject whose settings `config` already reports as malformed.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Console\DeliveryChecks  $delivery
     * @param  \SineMacula\Laravel\AuditLog\Console\IntegrityChecks  $integrity
     * @param  \SineMacula\Laravel\AuditLog\Console\LifecycleChecks  $lifecycle
     * @param  \SineMacula\Laravel\AuditLog\Console\PrivacyChecks  $privacy
     * @return array<string, list<\Closure(): list<string>>>
     */
    private function checks(
        ConfigRepository $config,
        DatabaseManager $database,
        DeliveryChecks $delivery,
        IntegrityChecks $integrity,
        LifecycleChecks $lifecycle,
        PrivacyChecks $privacy,
    ): array {
        [$storageCheck, $maintenanceCheck, $tableCheck, $integrityCheck, $deliveryCheck, $sealCheck, $lifecycleCheck] = self::settingChecks($config);

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
        // subject is listed even when its table checks are skipped
        $sealing = $storage && !self::fails($sealCheck) ? [$integrity->problems(...)] : [];

        if (!self::fails($integrityCheck)) {
            $checks['integrity'] = $sealing;
        }

        if (!self::fails($deliveryCheck)) {
            $checks['delivery'] = [$delivery->problems(...)];
        }

        if (!self::fails($lifecycleCheck)) {
            $checks['lifecycle'] = [$lifecycle->problems(...)];
        }

        return [...$checks, ...$privacy->subject()];
    }

    /**
     * The checks later subjects depend on: storage, maintenance, entries table,
     * integrity keys, delivery, sealing and lifecycle, in that order.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return array{0: \Closure(): list<string>, 1: \Closure(): list<string>, 2: \Closure(): list<string>, 3: \Closure(): list<string>, 4: \Closure(): list<string>, 5: \Closure(): list<string>, 6: \Closure(): list<string>}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
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
            static function () use ($config): array {
                StorageConnection::name();

                (new FailureSettings($config))->validate();
                (new DeliverySettings($config))->validate();

                return [];
            },
            static function () use ($config): array {
                (new SealSettings($config))->validate();
                (new AnchorSettings($config))->validate();

                IntegrityTables::checkpointsTable();
                IntegrityTables::membersTable();
                IntegrityTables::stateTable();

                return [];
            },
            static function () use ($config): array {
                LifecycleTables::validate();

                (new IntegritySettings($config))->validate();
                (new SealSettings($config))->logId();

                IntegrityTables::checkpointsTable();
                IntegrityTables::stateTable();

                return self::unconfigured($config, 'storage.connection', StorageConnection::resolvedName());
            },
        ];
    }

    /**
     * The checks of the integrity settings, one each; the application keys are
     * read only when no ring is set.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<\Closure(): list<string>>
     */
    private static function integritySettingChecks(ConfigRepository $config): array
    {
        $integrity = new IntegritySettings($config);
        $seals     = new SealSettings($config);
        $anchors   = new AnchorSettings($config);

        return [
            self::reading($integrity->currentKeyId(...)),
            self::reading($integrity->explicitKeys(...)),
            self::reading(static fn (): array => $integrity->explicitKeys() === [] ? $integrity->applicationKeys() : []),
            self::reading($seals->logId(...)),
            self::reading(IntegrityTables::checkpointsTable(...)),
            self::reading(IntegrityTables::membersTable(...)),
            self::reading(IntegrityTables::stateTable(...)),
            self::reading($seals->batch(...)),
            self::reading($seals->maxBatches(...)),
            self::reading($seals->lookbackSeconds(...)),
            self::reading($seals->settleSeconds(...)),
            self::reading($seals->maxAttempts(...)),
            self::reading($seals->maxUnsealedAgeSeconds(...)),
            self::reading($seals->sealSchedule(...)),
            self::reading($seals->sweepSchedule(...)),
            self::reading($seals->verifySchedule(...)),
            self::reading($anchors->driver(...)),
            self::reading($anchors->disk(...)),
            self::reading($anchors->path(...)),
            self::reading($anchors->batch(...)),
        ];
    }

    /**
     * The checks of every other setting, one each.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<\Closure(): list<string>>
     */
    private static function captureSettingChecks(ConfigRepository $config): array
    {
        $context  = new ContextSettings($config);
        $source   = new SourceSettings($config);
        $failure  = new FailureSettings($config);
        $delivery = new DeliverySettings($config);

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
            self::reading($failure->mode(...)),
            self::reading($failure->logChannel(...)),
            self::reading($delivery->mode(...)),
            self::reading($delivery->leaseSeconds(...)),
            self::reading($delivery->maxAttempts(...)),
            self::reading($delivery->backoffSeconds(...)),
            self::reading(DeliveryTables::outboxTable(...)),
            self::reading(DeliveryTables::deliveriesTable(...)),
            self::reading(DeliveryTables::outboxConnection(...)),
            ...array_map(self::reading(...), CaptureChecks::readers($config)),
            static fn (): array => CaptureChecks::guardProblems($config),
            ...array_map(self::reading(...), ReadChecks::readers($config)),
            ...array_map(self::reading(...), LifecycleChecks::readers($config)),
            ...array_map(self::reading(...), PrivacyChecks::readers($config)),
            ...array_map(self::reading(...), FreshnessChecks::readers($config)),
        ];
    }

    /**
     * The checks of the redaction settings, one each.
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
     * The check that a setting's reader does not throw.
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
     * The check that each connection the settings name is configured, and that
     * a separate maintenance connection uses the storage connection's driver.
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
     * The check of the storage connection's engine, then, once it is supported
     * and opens, the entries and artifacts tables.
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
            $schemas    = new SchemaChecks($database);

            // A failed statement throws an undeclared `QueryException`, whose
            // message holds the statement
            try {
                $blocking = $engine->blockingProblem($connection);

                if ($blocking !== null) {
                    return [$blocking];
                }

                return [...$engine->problems($connection, $table), ...$schemas->problems($connection, $table), ...self::artifactsProblems($schemas, $connection)];
            } catch (\PDOException $exception) { // @phpstan-ignore catch.neverThrown
                return [sprintf('The storage connection [%s] could not be read (%s).', $connection, $exception::class)];
            }
        };
    }

    /**
     * The problems of the artifacts table, or none while its name is malformed,
     * which `config` reports.
     *
     * @param  \SineMacula\Laravel\AuditLog\Console\SchemaChecks  $schemas
     * @param  string  $connection
     * @return list<string>
     */
    private static function artifactsProblems(SchemaChecks $schemas, string $connection): array
    {
        try {
            $table = EntrySettings::artifactsTable();
        } catch (\InvalidArgumentException) {
            return [];
        }

        return $schemas->problems($connection, $table, TableShape::artifacts());
    }

    /**
     * Run the freshness checks alone and report each signal as a line or, with
     * `--json`, a JSON object.
     *
     * @param  \SineMacula\Laravel\AuditLog\Console\FreshnessChecks  $freshness
     * @return int
     *
     * @throws \JsonException
     */
    private function freshness(FreshnessChecks $freshness): int
    {
        try {
            $signals = $freshness->signals();
        } catch (\InvalidArgumentException $exception) {
            $this->error('[config] ' . $exception->getMessage());

            return self::FAILURE;
        } catch (\PDOException|\UnexpectedValueException $exception) { // @phpstan-ignore catch.neverThrown
            // A `QueryException`'s message holds the statement
            $this->error(sprintf('[freshness] The progress could not be read (%s).', $exception::class));

            return self::FAILURE;
        }

        foreach ($signals as $signal) {
            if ($this->option('json') === true) {
                $this->line(json_encode($signal->toArray(), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));

                continue;
            }

            $signal->problem ? $this->error($signal->line()) : $this->info($signal->line());
        }

        return array_filter($signals, static fn (FreshnessSignal $signal): bool => $signal->problem) === [] ? self::SUCCESS : self::FAILURE;
    }

    /**
     * Report the spill channel's note, unless its setting is malformed, then
     * each lifecycle, privacy and production note.
     *
     * @param  \SineMacula\Laravel\AuditLog\Console\DeliveryChecks  $delivery
     * @param  \SineMacula\Laravel\AuditLog\Console\LifecycleChecks  $lifecycle
     * @param  \SineMacula\Laravel\AuditLog\Console\PrivacyChecks  $privacy
     * @param  \SineMacula\Laravel\AuditLog\Console\ProductionChecks  $production
     * @return void
     */
    private function notes(DeliveryChecks $delivery, LifecycleChecks $lifecycle, PrivacyChecks $privacy, ProductionChecks $production): void
    {
        try {
            $note = $delivery->spillNote();

            $note === null ? $this->info('[spill] OK') : $this->warn("[spill] {$note}");
        } catch (\InvalidArgumentException) {
            // The malformed setting is listed under `config`
        }

        foreach ($lifecycle->notes() as $lifecycleNote) {
            $this->warn("[lifecycle] note: {$lifecycleNote}");
        }

        foreach ($privacy->notes() as $privacyNote) {
            $this->warn("[privacy] note: {$privacyNote}");
        }

        foreach ($production->notes() as $productionNote) {
            $this->warn("[production] note: {$productionNote}");
        }
    }

    /**
     * The problem of each actor guard not configured in `auth.guards`, which
     * `AuthManager` refuses; none for a malformed list.
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

            if (is_array($config->get("auth.guards.{$guard}"))) {
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

        // Looked up by the same dotted path `AuthManager` resolves it by
        if (is_string($guard) && is_array($config->get("auth.guards.{$guard}"))) {
            return [];
        }

        return [sprintf('The default guard [%s] is not configured in `auth.guards`, and the actor is read from it.', is_string($guard) ? $guard : get_debug_type($guard))];
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
