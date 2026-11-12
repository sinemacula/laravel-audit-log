<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\ConfigurationUrlParser;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Database\DedicatedSession;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * The one consistent snapshot an export is read in, on a dedicated session so
 * the snapshot and every statement share one PDO, on the reader if any.
 *
 * In-memory SQLite, invisible to a second PDO, is read on the storage
 * connection. Laravel's testing transaction is read inside, beginning nothing.
 *
 * On SQLite in rollback-journal mode the snapshot's shared lock holds back
 * every writer's commit until it ends; WAL mode does not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExportSnapshot
{
    /** @var array<'mysql'|'pgsql'|'sqlite', non-empty-list<string>> Each engine's snapshot statements. */
    public const array BEGIN = [
        'pgsql'  => ['START TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'],
        'mysql'  => ['SET TRANSACTION ISOLATION LEVEL REPEATABLE READ', 'START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY'],
        'sqlite' => ['BEGIN DEFERRED'],
    ];

    /** @var array<'mysql'|'pgsql'|'sqlite', string> Each engine's consistency name in the manifest. */
    public const array CONSISTENCY = [
        'pgsql'  => 'repeatable_read_read_only',
        'mysql'  => 'consistent_snapshot_read_only',
        'sqlite' => 'deferred_read_transaction',
    ];

    /** @var string The consistency of a read inside the testing manager's base transaction. */
    public const string TESTING_TRANSACTION = 'testing_transaction';

    /** @var string What every dedicated session's name starts with. */
    private const string SESSION_PREFIX = 'audit_log_export_';

    /** @var bool Whether the snapshot has ended, committed or rolled back. */
    private bool $ended = false;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \Illuminate\Database\Connection  $session
     * @param  ?string  $dedicated
     * @param  string  $storage
     * @param  string  $consistency
     */
    private function __construct(

        /** The manager the dedicated session is purged from. */
        private readonly DatabaseManager $database,

        /** The connection the snapshot is read on. */
        private readonly Connection $session,

        /** The dedicated session's name, or `null` on the storage connection. */
        private readonly ?string $dedicated,

        /** The storage connection's resolved name. */
        private readonly string $storage,

        /** The name of the snapshot's consistency. */
        private readonly string $consistency,
    ) {}

    /**
     * Open the snapshot, refusing an engine an export cannot read and any open
     * transaction but the testing one.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     * @throws \UnexpectedValueException
     */
    public static function open(DatabaseManager $database): self
    {
        $name    = StorageConnection::resolvedName();
        $storage = $database->connection($name);
        $driver  = self::driverOf($name, $storage);

        if ($storage->transactionLevel() > 0) {
            self::refuseAnyButTheTestingTransaction($name, $storage);

            return new self($database, $storage, null, $name, self::TESTING_TRANSACTION);
        }

        if (DedicatedSession::isInMemory($storage)) {
            self::begin($storage, $driver);

            return new self($database, $storage, null, $name, self::CONSISTENCY[$driver]);
        }

        $dedicated = self::SESSION_PREFIX . str_replace('-', '', Str::uuid7()->toString());

        $database->connectUsing($dedicated, self::sessionConfig($name, $storage));

        $session = $database->connection($dedicated);
        $begun   = false;

        try {
            self::begin($session, $driver);

            $begun = true;
        } finally {
            if (!$begun) {
                $database->purge($dedicated);
            }
        }

        return new self($database, $session, $dedicated, $name, self::CONSISTENCY[$driver]);
    }

    /**
     * Refuse an engine an export cannot read, without running a statement.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function check(DatabaseManager $database): void
    {
        $name = StorageConnection::resolvedName();

        self::driverOf($name, $database->connection($name));
    }

    /**
     * The connection the snapshot is read on.
     *
     * @return \Illuminate\Database\Connection
     */
    public function connection(): Connection
    {
        return $this->session;
    }

    /**
     * What the manifest says of the snapshot.
     *
     * @return array{connection: string, consistency: string, database: string, engine: string, table: string}
     *
     * @throws \InvalidArgumentException
     */
    public function semantics(): array
    {
        return [
            'connection'  => $this->storage,
            'consistency' => $this->consistency,
            'database'    => $this->session->getDatabaseName(),
            'engine'      => $this->session->getDriverName(),
            'table'       => EntrySettings::table(),
        ];
    }

    /**
     * Commit the snapshot and purge the session, even when the commit fails.
     *
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    public function close(): void
    {
        $this->end('COMMIT');
    }

    /**
     * Roll back the snapshot of a failing export and purge the session.
     *
     * @return void
     */
    public function abandon(): void
    {
        try {
            $this->end('ROLLBACK');
        } catch (\Throwable) {
            // The snapshot wrote nothing, so a failed rollback leaves nothing
        }
    }

    /**
     * End the snapshot once with the statement, then purge the session.
     *
     * @param  'COMMIT'|'ROLLBACK'  $statement
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private function end(string $statement): void
    {
        if ($this->ended) {
            return;
        }

        $this->ended = true;

        try {
            if ($this->consistency !== self::TESTING_TRANSACTION) {
                self::run($this->session, $statement);
            }
        } finally {
            if ($this->dedicated !== null) {
                $this->database->purge($this->dedicated);
            }
        }
    }

    /**
     * Begin the engine's snapshot on the connection.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  'mysql'|'pgsql'|'sqlite'  $driver
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private static function begin(Connection $connection, string $driver): void
    {
        foreach (self::BEGIN[$driver] as $statement) {
            self::run($connection, $statement);
        }
    }

    /**
     * Run the statement unprepared, refusing one a silent connection says did
     * not run.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  literal-string  $statement
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private static function run(Connection $connection, string $statement): void
    {
        if (!$connection->unprepared($statement)) {
            throw new \UnexpectedValueException(sprintf('The export\'s snapshot could not run %s.', $statement));
        }
    }

    /**
     * The engine of the storage connection, refusing one an export cannot read.
     *
     * @param  string  $name
     * @param  \Illuminate\Database\Connection  $storage
     * @return 'mysql'|'pgsql'|'sqlite'
     *
     * @throws \LogicException
     */
    private static function driverOf(string $name, Connection $storage): string
    {
        $driver = $storage->getDriverName();

        return match ($driver) {
            'mysql', 'pgsql', 'sqlite' => $driver,
            default                    => throw new \LogicException(sprintf('An export reads MySQL, PostgreSQL or SQLite, and the [%s] connection is %s.', $name, $driver)),
        };
    }

    /**
     * Refuse the storage connection's open transaction unless it is the base
     * one Laravel's testing manager wraps a test in.
     *
     * @param  string  $name
     * @param  \Illuminate\Database\Connection  $storage
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private static function refuseAnyButTheTestingTransaction(string $name, Connection $storage): void
    {
        if (!DedicatedSession::isTheTestingTransaction($storage)) {
            throw AuditReadRefusedException::inTransaction($name);
        }
    }

    /**
     * The storage connection's configuration, URLs resolved and a random `read`
     * entry merged in as Laravel does, on a non-persistent handle.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $name
     * @param  \Illuminate\Database\Connection  $storage
     * @return array<array-key, mixed>
     */
    private static function sessionConfig(string $name, Connection $storage): array
    {
        $parser = new ConfigurationUrlParser;
        $config = Config::get('database.connections.' . $name);
        $config = $parser->parseConfiguration(self::settingsOf(is_array($config) ? $config : (array) $storage->getConfig()));
        $read   = $config['read'] ?? [];

        if (is_array($read) && array_is_list($read) && $read !== []) {
            $read = $read[array_rand($read)];
        }

        $config = array_merge($config, is_array($read) ? $parser->parseConfiguration(self::settingsOf($read)) : []);

        unset($config['read'], $config['write'], $config['name']);

        return DedicatedSession::sessionOptions($config);
    }

    /**
     * The settings under string keys.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $config
     * @return array<string, mixed>
     */
    private static function settingsOf(array $config): array
    {
        return array_filter($config, is_string(...), ARRAY_FILTER_USE_KEY);
    }
}
