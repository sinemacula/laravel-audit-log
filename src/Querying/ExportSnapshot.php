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
 * The one consistent snapshot an export is read in, from its bound to its last
 * chunk, on a session of its own: a connection made from the storage
 * connection's configuration, with any `read` settings merged over the base and
 * `read` and `write` removed, so the snapshot and every statement of the
 * extraction share one PDO, on the reader where there is one. The session is
 * purged when the snapshot ends.
 *
 * Each engine begins its own snapshot, each statement through `unprepared()`:
 * PostgreSQL a repeatable read, read-only transaction; MySQL a consistent
 * snapshot, read-only, at repeatable read; SQLite a deferred transaction, which
 * reads and never writes, so it never takes a writer's lock. No write is ever
 * issued on the session. In-memory SQLite, which a second PDO cannot see, is
 * read on the storage connection itself, in a deferred transaction of its own.
 * A storage connection holding the base transaction Laravel's testing manager
 * wraps a test in, whose rows no other session could see on any engine, is read
 * inside that transaction, beginning and committing nothing, and its
 * consistency is named `testing_transaction`, never a snapshot it did not take.
 * Any other open transaction on the storage connection is refused, as the read
 * gate refuses it.
 *
 * On SQLite in rollback-journal mode the snapshot's shared lock holds back
 * every writer's commit on the database file until the snapshot ends, as a
 * sealer's read does; in WAL mode a writer commits while it is open, which is
 * why the operations guidance advises WAL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExportSnapshot
{
    /** @var array<'mysql'|'pgsql'|'sqlite', non-empty-list<string>> The statements each engine begins its snapshot with, in order. */
    public const array BEGIN = [
        'pgsql'  => ['START TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'],
        'mysql'  => ['SET TRANSACTION ISOLATION LEVEL REPEATABLE READ', 'START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY'],
        'sqlite' => ['BEGIN DEFERRED'],
    ];

    /** @var array<'mysql'|'pgsql'|'sqlite', string> The name of each engine's snapshot, as the manifest gives it. */
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

        /** The name of the dedicated session, or `null` when the snapshot is read on the storage connection. */
        private readonly ?string $dedicated,

        /** The storage connection's resolved name. */
        private readonly string $storage,

        /** The name of the snapshot's consistency. */
        private readonly string $consistency,
    ) {}

    /**
     * Open the snapshot: refuse an engine other than MySQL, PostgreSQL and
     * SQLite before anything, then read inside the testing manager's base
     * transaction, or begin a snapshot on the storage connection for in-memory
     * SQLite and on a dedicated session otherwise.
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
     * Refuse, before anything, an engine other than MySQL, PostgreSQL and
     * SQLite on the storage connection: the check `open()` makes first, so an
     * export can make it before anything else. No statement is run.
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
     * What the manifest says of the snapshot: the storage connection's name,
     * the snapshot's consistency, the database it read, the engine and the
     * entries table.
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
     * End the snapshot: commit what it began, then purge the dedicated session,
     * which is purged even when the commit fails, and the failure thrown.
     * Ending it again does nothing.
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
     * End the snapshot of a failing export: roll back what it began and purge
     * the dedicated session, never throwing. Ending it again does nothing.
     *
     * @return void
     */
    public function abandon(): void
    {
        try {
            $this->end('ROLLBACK');
        } catch (\Throwable) {
            // The export is already failing, and the session is purged; a
            // rollback that fails has nothing left to undo, since the snapshot
            // wrote nothing
        }
    }

    /**
     * End the snapshot with the statement, unless it began nothing, then purge
     * the dedicated session however the statement went, once.
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
     * Run the statement on the connection, unprepared, and refuse one the
     * connection says did not run, as a connection that reports errors silently
     * says it, so a snapshot is never claimed that was not begun.
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
     * The dedicated session's configuration: the storage connection's, its
     * `url` resolved over the other keys as the database manager resolves it,
     * so the session reaches the very database the connection does, with its
     * `read` settings, one picked at random from a list as Laravel picks a
     * reader, each with its own `url` resolved, merged over the base, and
     * `read`, `write` and the name removed, and a handle of its own forced,
     * never a persistent one the storage connection shares. A connection with
     * no configuration of its own is made from the settings it was made with.
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
     * The connection settings, each under its name; an entry under an integer
     * key names no setting.
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
