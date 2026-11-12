<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseTransactionsManager;

/**
 * Whether a second PDO on the storage connection's database could not see what
 * it does: in-memory SQLite, or inside the testing manager's base transaction.
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
     * The configuration with `PDO::ATTR_PERSISTENT` forced off, since a
     * persistent handle would be the storage connection's own.
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
     * Whether the connection is in-memory SQLite: `:memory:` or a URI with
     * `mode=memory`.
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
     * testing manager wraps a test in.
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
