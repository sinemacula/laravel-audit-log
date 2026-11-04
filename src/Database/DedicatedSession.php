<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseTransactionsManager;

/**
 * When a session of its own, a second PDO on the storage connection's database,
 * could not see or write what the storage connection does: the database is
 * in-memory SQLite, which no other PDO can open, or the storage connection
 * holds the base transaction Laravel's testing manager wraps a test in, whose
 * rows no other session could see on any engine.
 *
 * The export's snapshot and the key session both ask, and each decides for
 * itself what it does instead. Both connect with `sessionOptions()`, so a
 * storage connection configured with persistent PDO connections never hands a
 * session the very handle it is using itself. The testing transaction is judged
 * by the transactions manager the container holds, as the read gate judges it,
 * which is why the question lives here, outside the domain, and neither caller
 * resolves the container itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DedicatedSession
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The configuration a session of its own connects with: the one given, its
     * PDO options kept, with `PDO::ATTR_PERSISTENT` forced off. A persistent
     * handle for the same DSN and credentials is the one the storage connection
     * already holds, so a session that reused it would run its transactions on
     * the storage connection's own and disconnect it when purged.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $config
     * @return array<array-key, mixed>
     */
    public static function sessionOptions(array $config): array
    {
        $options = is_array($config['options'] ?? null) ? $config['options'] : [];

        $options[\PDO::ATTR_PERSISTENT] = false;

        $config['options'] = $options;

        return $config;
    }

    /**
     * Whether the connection is an in-memory SQLite database, which no other
     * PDO can see: `:memory:`, or a URI whose mode is `memory`.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    public static function isInMemory(Connection $connection): bool
    {
        $database = $connection->getDatabaseName();

        return $connection->getDriverName() === 'sqlite'
            && ($database === ':memory:' || str_contains($database, '?mode=memory') || str_contains($database, '&mode=memory'));
    }

    /**
     * Whether the connection's open transaction is the base one Laravel's
     * testing manager wraps a test in: the bound manager would run the
     * callbacks of a commit at the connection's level, as the read gate judges
     * it. With no transaction open, no manager bound, or the framework's own,
     * it never is.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function isTheTestingTransaction(Connection $connection): bool
    {
        $container = Container::getInstance();
        $manager   = $container->bound('db.transactions') ? $container->make('db.transactions') : null;

        return $connection->transactionLevel() > 0
            && $manager instanceof DatabaseTransactionsManager
            && $manager->afterCommitCallbacksShouldBeExecuted($connection->transactionLevel());
    }
}
