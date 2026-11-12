<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Monolog\Formatter\LineFormatter;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\DeliverySettings;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Delivery\StoreCapabilities;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode;
use SineMacula\Laravel\AuditLog\Stores\FailureSettings;

/**
 * The delivery checks of `audit-log:check`: the spill channel, the store's
 * durability when a failure is thrown, and in outbox mode the outbox tables.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeliveryChecks
{
    /** @var list<string> The drivers of the documented spill channel. */
    private const array FILE_DRIVERS = ['single', 'daily'];

    /** @var string The format of the documented spill channel: the message alone, one line per record. */
    private const string DOCUMENTED_FORMAT = "%message%\n";

    /** @var int The permission bits of group and others, none of which a file of plaintext records may have. */
    private const int GROUP_AND_OTHER_BITS = 0077;

    /** @var int The permission bits of a file, which `fileperms()` gives with its type. */
    private const int PERMISSION_BITS = 0777;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Delivery\StoreCapabilities  $capabilities
     */
    public function __construct(

        /** The configuration the settings and the channels are read from. */
        private ConfigRepository $config,

        /** The connections the outbox and deliveries tables are read on. */
        private DatabaseManager $database,

        /** What the bound store says of itself. */
        private StoreCapabilities $capabilities,
    ) {}

    /**
     * Every delivery problem: the spill channel's, the store's when a failure
     * is thrown in sync mode, and in outbox mode the outbox tables'.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function problems(): array
    {
        $failure = new FailureSettings($this->config);
        $outbox  = (new DeliverySettings($this->config))->mode() === DeliveryMode::OUTBOX;

        return [
            ...$this->channelProblems($failure->logChannel(), $outbox),
            ...($failure->mode() === FailureMode::THROW && !$outbox ? $this->durabilityProblems() : []),
            ...($outbox ? $this->outboxProblems() : []),
        ];
    }

    /**
     * The note on the spill channel, or `null` when it is the documented
     * channel with a permission that keeps out group and others.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function spillNote(): ?string
    {
        $name    = $this->spillChannel();
        $channel = $this->channel($name);

        if (!self::isDocumentedChannel($channel)) {
            $note = 'The channel [%s] is not the documented file format, so replaying what it holds is unverified,'
                . ' and whole records in plaintext go to it and to everything it feeds.';

            return sprintf($note, $name);
        }

        return self::permissionNote($name, $channel);
    }

    /**
     * The problems of the spill channel: unconfigured, or a `database` channel
     * on the storage or, in outbox mode, the outbox connection.
     *
     * @param  ?string  $setting
     * @param  bool  $outbox
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function channelProblems(?string $setting, bool $outbox): array
    {
        if ($setting !== null && !is_array($this->config->get("logging.channels.{$setting}"))) {
            return [sprintf('The channel [%s] that `audit-log.failure.log_channel` names is not configured in `logging.channels`.', $setting)];
        }

        $storage  = StorageConnection::resolvedName();
        $outboxOn = $outbox ? DeliveryTables::resolvedOutboxConnection() : null;
        $problems = [];

        foreach ($this->databaseChannels($this->spillChannel()) as $name => $connection) {
            $problem = match ($connection) {
                $storage  => 'The spill channel [%s] writes to the storage connection [%s], so it would fail together with the store.',
                $outboxOn => 'The spill channel [%s] writes to the outbox connection [%s], so it would fail together with the outbox.',
                default   => null,
            };

            if ($problem === null) {
                continue;
            }

            $problems[] = sprintf($problem, $name, $connection);
        }

        return $problems;
    }

    /**
     * Each `database` channel the channel is or reaches through nested `stack`
     * members, with its connection; each is visited once, so a cycle ends.
     *
     * @param  string  $name
     * @return array<string, string>
     */
    private function databaseChannels(string $name): array
    {
        $pending = [$name];
        $visited = [];
        $found   = [];

        while ($pending !== []) {

            $current = array_shift($pending);

            if (in_array($current, $visited, true)) {
                continue;
            }

            $visited[] = $current;
            $channel   = $this->channel($current);
            $driver    = $channel['driver'] ?? null;

            if ($driver === 'stack') {
                array_push($pending, ...self::members($channel));

                continue;
            }

            if ($driver !== 'database') {
                continue;
            }

            $found[$current] = $this->connectionOf($channel);
        }

        return $found;
    }

    /**
     * The problem of a store not marked durable; none while the integrity
     * settings are malformed, since resolving the store builds the key ring.
     *
     * @return list<string>
     */
    private function durabilityProblems(): array
    {
        if (!$this->isIntegrityReadable()) {
            return [];
        }

        try {
            $durable = $this->capabilities->isDurable();
            $store   = $this->capabilities->storeClass();
        } catch (\Throwable $exception) {
            return [sprintf('The bound store could not be resolved (%s).', get_debug_type($exception))];
        }

        return $durable ? [] : [sprintf('`audit-log.failure.mode` is `throw`, and the store %s does not say it is durable, so a return could not mean a record is kept.', $store)];
    }

    /**
     * Whether the integrity settings can be read, so the store can be resolved.
     *
     * @return bool
     */
    private function isIntegrityReadable(): bool
    {
        try {
            (new IntegritySettings($this->config))->validate();
        } catch (\InvalidArgumentException) {
            return false;
        }

        return true;
    }

    /**
     * The problems of outbox mode: its own connection, then the outbox and
     * deliveries tables.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function outboxProblems(): array
    {
        $storage = StorageConnection::resolvedName();
        $outbox  = DeliveryTables::resolvedOutboxConnection();

        return [
            ...($outbox === $storage ? [] : $this->outboxConnectionProblems($outbox)),
            ...$this->tableProblems('outbox', $outbox, DeliveryTables::outboxTable(), TableShape::outbox()),
            ...$this->tableProblems('storage', $storage, DeliveryTables::deliveriesTable(), TableShape::deliveries()),
        ];
    }

    /**
     * The problem of an outbox connection of its own: it is not configured, or
     * its driver or server is not supported or it cannot be opened; or none.
     *
     * @param  string  $connection
     * @return list<string>
     */
    private function outboxConnectionProblems(string $connection): array
    {
        if (!$this->isConfigured($connection)) {
            return [sprintf('The connection [%s] that `audit-log.delivery.outbox.connection` names is not configured in `database.connections`.', $connection)];
        }

        $blocking = (new EngineChecks($this->database))->blockingProblem($connection, 'outbox');

        return $blocking === null ? [] : [$blocking];
    }

    /**
     * The schema problems of a delivery table, or none when its connection is
     * unconfigured or cannot be checked, which the subject naming it reports.
     *
     * @param  'outbox'|'storage'  $role
     * @param  string  $connection
     * @param  string  $table
     * @param  \SineMacula\Laravel\AuditLog\Console\TableShape  $shape
     * @return list<string>
     */
    private function tableProblems(string $role, string $connection, string $table, TableShape $shape): array
    {
        if (!$this->isConfigured($connection) || (new EngineChecks($this->database))->blockingProblem($connection) !== null) {
            return [];
        }

        // A failed statement throws an undeclared `QueryException`, whose
        // message holds the statement
        try {
            return (new SchemaChecks($this->database))->problems($connection, $table, $shape);
        } catch (\PDOException $exception) { // @phpstan-ignore catch.neverThrown
            return [sprintf('The %s connection [%s] could not be read (%s).', $role, $connection, get_debug_type($exception))];
        }
    }

    /**
     * The name of the spill channel: the one the setting names, or the default
     * channel, named by its type when it is not a name.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function spillChannel(): string
    {
        $default = $this->config->get('logging.default');

        return (new FailureSettings($this->config))->logChannel() ?? (is_string($default) ? $default : get_debug_type($default));
    }

    /**
     * The configuration of a channel, looked up by the same dotted path the log
     * manager resolves it by, or an empty map when it is not configured.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $name
     * @return array<array-key, mixed>
     */
    private function channel(string $name): array
    {
        $channel = $this->config->get("logging.channels.{$name}");

        return is_array($channel) ? $channel : [];
    }

    /**
     * The connection a `database` channel writes to: the one it names, or the
     * default connection, named by its type when it is not a name.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $channel
     * @return string
     */
    private function connectionOf(array $channel): string
    {
        $connection = $channel['connection'] ?? $this->config->get('database.default');

        return is_string($connection) ? $connection : get_debug_type($connection);
    }

    /**
     * Whether a connection is configured in `database.connections`.
     *
     * @param  string  $connection
     * @return bool
     */
    private function isConfigured(string $connection): bool
    {
        return is_array($this->config->get("database.connections.{$connection}"));
    }

    /**
     * The members of a `stack` channel as the log manager reads them: a list or
     * a comma-separated string of names; anything else names none.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $channel
     * @return list<string>
     */
    private static function members(array $channel): array
    {
        $members = $channel['channels'] ?? [];

        if (is_string($members)) {
            $members = explode(',', $members);
        }

        $names = [];

        foreach (is_array($members) ? $members : [] as $member) {

            if (!is_string($member) && !is_int($member)) {
                continue;
            }

            $names[] = trim((string) $member);
        }

        return $names;
    }

    /**
     * The note on a documented channel's permission, or `null` when it and any
     * existing file are private; Monolog applies it only on creating the file.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $name
     * @param  array<array-key, mixed>  $channel
     * @return ?string
     */
    private static function permissionNote(string $name, array $channel): ?string
    {
        $permission = $channel['permission'] ?? null;

        if (!is_int($permission)) {
            return sprintf('The channel [%s] sets no `permission`, so its file of plaintext records takes the umask; set `permission` to 0600.', $name);
        }

        if (($permission & self::GROUP_AND_OTHER_BITS) !== 0) {
            return sprintf('The channel [%s] has the `permission` %04o, so group or others can read its plaintext records; set it to 0600.', $name, $permission);
        }

        return self::fileNote($name, $channel);
    }

    /**
     * The note on a file the channel has already written whose mode lets group
     * or others in, or `null` when none does.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $name
     * @param  array<array-key, mixed>  $channel
     * @return ?string
     */
    private static function fileNote(string $name, array $channel): ?string
    {
        foreach (self::filesOf($channel) as $file) {
            $mode = fileperms($file);

            if ($mode === false || ($mode & self::GROUP_AND_OTHER_BITS) === 0) {
                continue;
            }

            $note = 'A file of the channel [%s] has the permission %04o, so group or others can read its plaintext records; change it to 0600.';

            return sprintf($note, $name, $mode & self::PERMISSION_BITS);
        }

        return null;
    }

    /**
     * The files a documented channel has written so far: a `single` channel's
     * path, or a `daily` channel's dated files beside it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $channel
     * @return list<string>
     */
    private static function filesOf(array $channel): array
    {
        $path = $channel['path'] ?? null;

        if (!is_string($path)) {
            return [];
        }

        if (($channel['driver'] ?? null) !== 'daily') {
            return is_file($path) ? [$path] : [];
        }

        $extension = pathinfo($path, PATHINFO_EXTENSION);
        $pattern   = substr($path, 0, $extension === '' ? null : -strlen($extension) - 1) . '-*' . ($extension === '' ? '' : '.' . $extension);

        return glob($pattern) ?: [];
    }

    /**
     * Whether the channel is the documented spill channel: a file driver and
     * `LineFormatter` writing the message alone, without inline line breaks.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $channel
     * @return bool
     */
    private static function isDocumentedChannel(array $channel): bool
    {
        $with = $channel['formatter_with'] ?? null;

        if (!is_array($with) || ($channel['formatter'] ?? null) !== LineFormatter::class) {
            return false;
        }

        return in_array($channel['driver'] ?? null, self::FILE_DRIVERS, true)
            && ($with['format'] ?? null)                 === self::DOCUMENTED_FORMAT
            && ($with['allowInlineLineBreaks'] ?? false) === false;
    }
}
