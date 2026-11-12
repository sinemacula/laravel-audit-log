<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\DatabaseManager;

/**
 * The connections with a transaction open, read before anything is attempted,
 * since Laravel forgets a transaction whose connection is lost.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OpenTransactions
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     */
    public function __construct(

        /** Resolves connections; only a database manager says which it holds. */
        private ConnectionResolverInterface $connections,
    ) {}

    /**
     * Each connection with a transaction open, by the name it gives itself;
     * none when the resolver is not a database manager.
     *
     * @return list<string>
     */
    public function names(): array
    {
        if (!$this->connections instanceof DatabaseManager) {
            return [];
        }

        $names = [];

        foreach ($this->connections->getConnections() as $key => $connection) {
            if ($connection->transactionLevel() <= 0) {
                continue;
            }

            $names[] = $connection->getName() ?? $key;
        }

        return array_values(array_unique($names));
    }
}
