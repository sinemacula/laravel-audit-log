<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\DatabaseManager;

/**
 * Which connections have a transaction open, read from every connection the
 * database manager holds, without opening one.
 *
 * It is read before anything is attempted, because Laravel forgets an open
 * transaction when its connection is lost. A deadlock or a lost connection on
 * any of these has ended a transaction the application is still inside, even
 * when the audit log writes to a connection of its own.
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
     * The name of each connection with a transaction open, as the connection
     * gives it, so a name that selects a reader or a writer is compared as the
     * connection; none when the resolver does not say which it holds.
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
