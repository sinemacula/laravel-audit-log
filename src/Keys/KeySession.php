<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Database\DedicatedSession;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * The session a key is created on: a connection of its own to the storage
 * connection's writer, a second PDO that commits on its own, so a key never
 * disappears with a host transaction that rolls back while a spill, the outbox
 * or an in-flight write already holds ciphertext under it.
 *
 * The session is made from the storage connection's own configuration, which
 * the framework has already resolved from its `url` and made from its `write`
 * settings over the base, with `read` and `write` gone, so it reaches exactly
 * the writer the storage connection writes through and never a replica; only
 * the name is dropped, so the session takes its own,
 * `audit_log_keys_<uuid hex>`. It is connected through the database manager,
 * never the configuration, and purged when the session closes; closing again
 * does nothing.
 *
 * Where a second PDO could not see or write what the storage connection does,
 * the storage connection itself is the session: in-memory SQLite, a storage
 * connection holding the testing manager's base transaction, and SQLite
 * whenever the storage connection is inside a transaction, since a second
 * SQLite writer would wait for the host's own lock. There a key created inside
 * a host transaction rolls back with it. An engine other than MySQL, PostgreSQL
 * and SQLite is refused before anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KeySession
{
    /** @var string What every dedicated session's name starts with. */
    public const string SESSION_PREFIX = 'audit_log_keys_';

    /** @var list<string> The engines a key is created on. */
    private const array ENGINES = ['mysql', 'pgsql', 'sqlite'];

    /** @var bool Whether the session has been closed. */
    private bool $closed = false;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \Illuminate\Database\Connection  $session
     * @param  ?string  $dedicated
     */
    private function __construct(

        /** The manager the dedicated session is purged from. */
        private readonly DatabaseManager $database,

        /** The connection keys are created on. */
        private readonly Connection $session,

        /** The name of the dedicated session, or `null` when the storage connection is the session. */
        private readonly ?string $dedicated,
    ) {}

    /**
     * Open the session: refuse an engine a key is not created on, then use the
     * storage connection itself where a second PDO could not see or write what
     * it does, and a dedicated session on its writer otherwise.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @return self
     *
     * @throws \LogicException
     */
    public static function open(DatabaseManager $database): self
    {
        $name    = StorageConnection::resolvedName();
        $storage = $database->connection($name);
        $driver  = $storage->getDriverName();

        if (!in_array($driver, self::ENGINES, true)) {
            throw new \LogicException(sprintf('A key is created on MySQL, PostgreSQL or SQLite, and the [%s] connection is %s.', $name, $driver));
        }

        if (self::sharesTheStorageConnection($storage, $driver)) {
            return new self($database, $storage, null);
        }

        $dedicated = self::SESSION_PREFIX . str_replace('-', '', Str::uuid7()->toString());

        return new self($database, $database->connectUsing($dedicated, self::sessionConfig($storage)), $dedicated);
    }

    /**
     * The connection keys are created on.
     *
     * @return \Illuminate\Database\Connection
     */
    public function connection(): Connection
    {
        return $this->session;
    }

    /**
     * Whether the session is a connection of its own, rather than the storage
     * connection itself.
     *
     * @return bool
     */
    public function isDedicated(): bool
    {
        return $this->dedicated !== null;
    }

    /**
     * Close the session: purge a dedicated one, which disconnects it and
     * releases whatever it held; the storage connection is left as it is.
     * Closing again does nothing.
     *
     * @return void
     */
    public function close(): void
    {
        if ($this->closed) {
            return;
        }

        $this->closed = true;

        if ($this->dedicated === null) {
            return;
        }

        $this->database->purge($this->dedicated);
    }

    /**
     * Whether a second PDO could not see or write what the storage connection
     * does: in-memory SQLite, the testing manager's base transaction, and
     * SQLite inside any transaction.
     *
     * @param  \Illuminate\Database\Connection  $storage
     * @param  string  $driver
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function sharesTheStorageConnection(Connection $storage, string $driver): bool
    {
        if (DedicatedSession::isInMemory($storage)) {
            return true;
        }

        return $storage->transactionLevel() > 0
            && ($driver === 'sqlite' || DedicatedSession::isTheTestingTransaction($storage));
    }

    /**
     * The dedicated session's configuration: the storage connection's own,
     * which is its write configuration, as the framework made its writer from
     * it, with its name and its isolation level removed and a handle of its own
     * forced, never a persistent one the storage connection shares. The
     * isolation of a creation is the key creator's to set, never the storage
     * connection's.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Database\Connection  $storage
     * @return array<array-key, mixed>
     */
    private static function sessionConfig(Connection $storage): array
    {
        $config = (array) $storage->getConfig();

        unset($config['read'], $config['write'], $config['name'], $config['isolation_level']);

        return DedicatedSession::sessionOptions($config);
    }
}
