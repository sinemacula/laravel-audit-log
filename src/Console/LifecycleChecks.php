<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Database\InstallationMismatchException;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldProjection;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSettings;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleLockException;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionSettings;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * The lifecycle checks of `audit-log:check`: a reader for each lifecycle,
 * retention and import setting; the problems of the journal, the holds
 * projection, the lifecycle lock and the import batches tables, of the bound
 * retention policy, of the installation's identity and of the journal itself;
 * and the notes on holds past their review date and imports that stopped
 * moving.
 *
 * The four tables are checked as `SchemaChecks` checks any of the package's
 * tables; once they have their shape, the lock's one row must be there, the
 * journal must verify, read-only and outside any lock, and the holds projection
 * must hold exactly the holds the verified journal holds active, each drifted
 * hold named by its id. The policy is resolved from the container, its settings
 * well formed, and its version must be 1 to 64 characters of clean text. The
 * installation id, which the migrations seed, must be read through the storage
 * connection, well formed, and the maintenance connection must read the same
 * one. A storage connection that cannot be opened is left to the `schema`
 * subject, and each failure to read is named by the class of what was thrown,
 * never its message.
 *
 * The notes are no problems and leave the exit code as it is: they are read
 * from the holds projection by review date and from the import batches table by
 * status and time, each listing at most 100 ids, and are left out when they
 * cannot be read. The checks write nothing, and print no value of an entry, a
 * journal row or a setting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LifecycleChecks
{
    /** @var int The most ids a problem or a note lists; the rest are counted. */
    public const int MAX_LISTED = 100;

    /** @var string A failure to read, by what could not be read and the class of what was thrown. */
    private const string UNREADABLE = '%s could not be read (%s).';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Console\SchemaChecks  $schemas
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     */
    public function __construct(

        /** The configuration the settings are read from. */
        private ConfigRepository $config,

        /** The connections the tables are read on. */
        private DatabaseManager $database,

        /** The checks of each table's shape. */
        private SchemaChecks $schemas,

        /** The container the policy and the journal's collaborators are resolved from on every call. */
        private Container $container,

        /** The time the policy is asked at and the notes are judged at. */
        private Clock $clock,
    ) {}

    /**
     * A reader for each lifecycle, retention and import setting, in the order
     * the settings are listed, and last the check that no category is kept for
     * less than it is preserved; each throws when what it reads is malformed.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<\Closure(): mixed>
     */
    public static function readers(ConfigRepository $config): array
    {
        $retention = new RetentionSettings($config);
        $import    = new ImportSettings($config);

        return [
            LifecycleTables::journalTable(...),
            LifecycleTables::holdsTable(...),
            LifecycleTables::lockTable(...),
            LifecycleTables::importBatchesTable(...),
            $retention->afterDays(...),
            $retention->categories(...),
            $retention->preserve(...),
            $retention->batch(...),
            $retention->maxSeconds(...),
            $retention->schedule(...),
            $retention->validate(...),
            $import->chunk(...),
            $import->maxSkewSeconds(...),
            $import->maxLineBytes(...),
        ];
    }

    /**
     * Every lifecycle problem, in order: the four tables' shapes, the lock's
     * row, the policy's version, the installation's identity, the journal's
     * verification and the projection's drift. What reads a table is checked
     * only once the four have their shape, and the installation's identity only
     * on a maintenance connection the `connections` subject finds no fault
     * with; nothing is checked on a storage connection the `schema` subject
     * reports.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public function problems(): array
    {
        $name = StorageConnection::resolvedName();

        if ((new EngineChecks($this->database))->blockingProblem($name) !== null) {
            return [];
        }

        $connection = $this->database->connection($name);

        // The framework declares nothing for a statement that fails, though it
        // throws a `QueryException`, whose message holds the statement
        try {
            $tables = $this->tableProblems($name);
        } catch (\PDOException $exception) { // @phpstan-ignore catch.neverThrown
            return [sprintf('The storage connection [%s] could not be read (%s).', $name, get_debug_type($exception))];
        }

        $shaped = $tables === [];

        return [
            ...$tables,
            ...($shaped ? $this->lockProblems($connection) : []),
            ...($this->hasValidRetentionSettings() ? $this->policyProblems() : []),
            ...($shaped && $this->isMaintenanceCheckable() ? $this->installationProblems() : []),
            ...($shaped ? $this->journalProblems($connection) : []),
        ];
    }

    /**
     * The notes, which are no problems: the holds past their review date, and
     * the import batches still running that have not moved for an hour. A note
     * that cannot be read is left out, since the problems name what is wrong.
     *
     * @return list<string>
     */
    public function notes(): array
    {
        try {
            $connection = $this->database->connection(StorageConnection::resolvedName());

            return [...$this->reviewNotes($connection), ...$this->staleNotes($connection)];
        } catch (\Exception) {
            // A malformed setting, a connection that cannot be opened or a
            // table that cannot be read is a problem, reported as one
            return [];
        }
    }

    /**
     * The schema problems of the four lifecycle tables on the storage
     * connection.
     *
     * @param  string  $connection
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function tableProblems(string $connection): array
    {
        return [
            ...$this->schemas->problems($connection, LifecycleTables::journalTable(), TableShape::journal()),
            ...$this->schemas->problems($connection, LifecycleTables::holdsTable(), TableShape::holds()),
            ...$this->schemas->problems($connection, LifecycleTables::lockTable(), TableShape::lock()),
            ...$this->schemas->problems($connection, LifecycleTables::importBatchesTable(), TableShape::importBatches()),
        ];
    }

    /**
     * The problem of a lock table without its one row, which no lifecycle
     * operation could lock, or none.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return list<string>
     */
    private function lockProblems(Connection $connection): array
    {
        try {
            $present = $connection->table(LifecycleTables::lockTable())->useWritePdo()->where('id', 1)->exists();
        } catch (\Exception $exception) {
            return [sprintf(self::UNREADABLE, 'The lifecycle lock row', get_debug_type($exception))];
        }

        return $present ? [] : [LifecycleLockException::missing()->getMessage()];
    }

    /**
     * The problem of a bound retention policy that cannot be resolved, or whose
     * version is not 1 to 64 characters of clean text, or none.
     *
     * @return list<string>
     */
    private function policyProblems(): array
    {
        $read = 'The bound retention policy';

        try {
            $policy = $this->container->make(RetentionPolicy::class);
            $read   = 'The bound retention policy\'s version';

            (new RetentionDecisions($policy, $this->clock->now()))->version();
        } catch (\Throwable $exception) {
            // The refusal of a malformed version names the policy's class and
            // what the version must be, never the version
            return [$exception instanceof \UnexpectedValueException ? $exception->getMessage() : sprintf(self::UNREADABLE, $read, get_debug_type($exception))];
        }

        return [];
    }

    /**
     * Whether the retention settings are well formed; while they are not, which
     * `config` reports, the policy the package binds cannot be asked.
     *
     * @return bool
     */
    private function hasValidRetentionSettings(): bool
    {
        try {
            (new RetentionSettings($this->config))->validate();
        } catch (\InvalidArgumentException) {
            return false;
        }

        return true;
    }

    /**
     * The problem of an installation the two connections do not agree on: the
     * storage connection reads no id, or a malformed one, or the maintenance
     * connection reads none or another; or none. The id is only read, never
     * written.
     *
     * @return list<string>
     */
    private function installationProblems(): array
    {
        try {
            $this->container->make(InstallationIdentity::class)->check();
        } catch (\Throwable $exception) {
            // A mismatch and an absent or malformed id are the package's own
            // refusals, which name no id and no setting's value
            $own = $exception instanceof InstallationMismatchException || $exception instanceof \UnexpectedValueException;

            return [$own ? $exception->getMessage() : sprintf(self::UNREADABLE, 'The installation id', get_debug_type($exception))];
        }

        return [];
    }

    /**
     * Whether the maintenance connection can be checked: its setting is well
     * formed, and it is configured with the storage connection's driver; any
     * other, `config` or `connections` reports.
     *
     * @return bool
     */
    private function isMaintenanceCheckable(): bool
    {
        try {
            $maintenance = StorageConnection::resolvedMaintenanceName();
            $storage     = StorageConnection::resolvedName();
        } catch (\InvalidArgumentException) {
            return false;
        }

        $driver = $this->config->get("database.connections.{$maintenance}.driver");

        return is_string($driver) && $driver === $this->config->get("database.connections.{$storage}.driver");
    }

    /**
     * The problem of a journal that fails verification, naming the finding and
     * the row it was found at, or else those of the holds projection against
     * the verified journal.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return list<string>
     */
    private function journalProblems(Connection $connection): array
    {
        try {
            $logId  = $this->container->make(SealSettings::class)->logId();
            $replay = JournalReplay::start($this->container->make(JournalSigner::class), $logId)->verify($connection);
        } catch (\Throwable $exception) {
            if (!$exception instanceof JournalBrokenException) {
                return [sprintf(self::UNREADABLE, 'The lifecycle journal', get_debug_type($exception))];
            }

            $at      = $exception->rowId === null ? '' : sprintf(' at `%s`', $exception->rowId);
            $message = 'The lifecycle journal fails verification (`%s`)%s; run `audit-log:verify`, and nothing destructive runs until it is'
                . ' investigated.';

            return [sprintf($message, $exception->finding->value, $at)];
        }

        return $this->driftProblems($connection, $replay);
    }

    /**
     * The problem of a holds projection that drifted from the holds the
     * verified journal holds active, naming each hold, or none.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @return list<string>
     */
    private function driftProblems(Connection $connection, JournalReplay $replay): array
    {
        try {
            $projection = $this->container->make(HoldProjection::class);
            $drifted    = $projection->drift($replay->holds(), $projection->rows($connection));
        } catch (\Throwable $exception) {
            return [sprintf(self::UNREADABLE, 'The holds projection', get_debug_type($exception))];
        }

        $problem = 'The holds projection differs from the journal for %s; rebuild it with `audit-log:holds --rebuild`.';

        return $drifted === [] ? [] : [sprintf($problem, self::listed($drifted, count($drifted)))];
    }

    /**
     * The note on the holds past their review date, read from the projection by
     * review date, or none.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function reviewNotes(Connection $connection): array
    {
        $query = $connection->table(LifecycleTables::holdsTable())->useWritePdo()->where('review_by', '<', $this->now());
        $ids   = (clone $query)->orderBy('review_by')->orderBy('hold_id')->limit(self::MAX_LISTED + 1)->pluck('hold_id')->all();
        $count = count($ids) > self::MAX_LISTED ? $query->count() : count($ids);

        if ($count === 0) {
            return [];
        }

        $note = '%d %s past %s review date: %s; review each, and release it once nothing obliges keeping it.';

        return [sprintf($note, $count, $count === 1 ? 'hold is' : 'holds are', $count === 1 ? 'its' : 'their', self::listed($ids, $count))];
    }

    /**
     * The note on the import batches still running that have not moved for an
     * hour, read from the batches table by status and time, or none.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function staleNotes(Connection $connection): array
    {
        $before = StoredTime::toStorage(StoredTime::format($this->clock->now()->subSeconds(ImportSettings::STALE_SECONDS)));
        $query  = $connection->table(LifecycleTables::importBatchesTable())->useWritePdo()->where('status', ImportStatus::RUNNING->value)->where('updated_at', '<', $before);
        $ids    = (clone $query)->orderBy('updated_at')->orderBy('id')->limit(self::MAX_LISTED + 1)->pluck('id')->all();
        $count  = count($ids) > self::MAX_LISTED ? $query->count() : count($ids);

        if ($count === 0) {
            return [];
        }

        $note = '%d import %s running with nothing written for over an hour: %s; close an interrupted one with `audit-log:import --close=<batch>`.';

        return [sprintf($note, $count, $count === 1 ? 'batch is' : 'batches are', self::listed($ids, $count))];
    }

    /**
     * The clock's instant as the database stores one.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function now(): string
    {
        return StoredTime::toStorage(StoredTime::format($this->clock->now()));
    }

    /**
     * The ids, each in backticks, at most 100 of them and only those that are a
     * lower-case UUID, so no byte a table holds reaches a console, followed by
     * how many more there are of the count given, when there are more.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $ids
     * @param  int  $count
     * @return string
     */
    private static function listed(array $ids, int $count): string
    {
        $uuids = array_filter($ids, static fn (mixed $id): bool => is_string($id) && preg_match(SealEnvelope::UUID_PATTERN, $id) === 1);
        $shown = array_slice(array_values($uuids), 0, self::MAX_LISTED);
        $more  = $count - count($shown);
        $text  = implode(', ', array_map(static fn (string $id): string => "`{$id}`", $shown));

        return match (true) {
            $shown === [] => sprintf('%d %s', $count, $count === 1 ? 'id' : 'ids'),
            $more > 0     => sprintf('%s and %d more', $text, $more),
            default       => $text,
        };
    }
}
