<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Connection;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager;

/**
 * Runs a test inside the wrapping transaction `DatabaseTransactions` opens,
 * under the testing transaction manager.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RunsInsideTheTestingWrapper
{
    /**
     * Install the testing manager on the connection, open its wrapping
     * transaction as `DatabaseTransactions` does, run the test inside it, then
     * roll the wrapper back.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \Closure(\Illuminate\Database\Connection, \Illuminate\Foundation\Testing\DatabaseTransactionsManager): void  $test
     * @return void
     */
    protected function insideTheTestingWrapper(Connection $connection, \Closure $test): void
    {
        $manager = new DatabaseTransactionsManager([$connection->getName()]);

        $this->app?->instance('db.transactions', $manager);

        $connection->setTransactionManager($manager);

        $dispatcher = $connection->getEventDispatcher();

        self::assertNotNull($dispatcher);

        $connection->unsetEventDispatcher();
        $connection->beginTransaction();
        $connection->setEventDispatcher($dispatcher);

        try {
            $test($connection, $manager);
        } finally {
            $connection->unsetEventDispatcher();
            $connection->rollBack();
            $connection->setEventDispatcher($dispatcher);
        }
    }
}
