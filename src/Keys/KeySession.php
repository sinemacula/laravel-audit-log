<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Database\DedicatedSession;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * A second PDO to the storage writer that keys are created on, so a key never
 * rolls back with a host transaction after ciphertext is sealed under it.
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

        /** The dedicated connection's name, or `null` when the storage connection is used. */
        private readonly ?string $dedicated,
    ) {}

    /**
     * Open the session: the storage connection itself where a second PDO could
     * not see its writes, and a dedicated connection to its writer otherwise.
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

        $database->connectUsing($dedicated, self::sessionConfig($storage));

        return new self($database, $database->connection($dedicated), $dedicated);
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
     * Whether the session is a connection of its own.
     *
     * @return bool
     */
    public function isDedicated(): bool
    {
        return $this->dedicated !== null;
    }

    /**
     * Close the session, purging a dedicated connection; closing again does
     * nothing.
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
     * Whether the storage connection must be the session: a second PDO cannot
     * see in-memory SQLite or the testing transaction, and a second SQLite
     * writer would wait on the host's lock.
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
     * The storage connection's write configuration without its name or
     * isolation level, on a handle of its own; the key creator sets the
     * isolation.
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
