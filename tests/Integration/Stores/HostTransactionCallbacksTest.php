<?php

declare(strict_types = 1);

namespace Tests\Integration\Stores;

use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for the host's after-commit callbacks around the store, on
 * the engine the suite runs against: a callback the host registers before the
 * store runs is kept through a stored record, a failed audit insert and a
 * resolved duplicate, runs once when the host commits, and is dropped with the
 * entry when the host rolls back; under Laravel's own transaction manager and
 * under the one its `DatabaseTransactions` testing trait installs, whose
 * wrapping transaction a host commit never reaches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAuditStore::class)]
final class HostTransactionCallbacksTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string The id records are pinned to. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /** @var int How many times the host's callback has run. */
    private int $callbacks = 0;

    /**
     * Roll back any transaction a test left open, then drop the probe table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = $this->storageConnection();

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        $this->removeProbeTable();

        parent::tearDown();
    }

    /**
     * A callback registered inside a nested host transaction is kept through a
     * stored record and through the inner commit, and runs once, at the outer
     * commit, with the entry committed.
     *
     * @return void
     */
    public function testAHostCallbackRunsOnceAtTheOuterCommitAfterAStoredRecord(): void
    {
        $connection = $this->storageConnection();

        $connection->beginTransaction();
        $connection->beginTransaction();

        $this->registerHostCallback($connection);

        $this->store()->store($this->finalised());

        self::assertSame(0, $this->callbacks);

        $connection->commit();

        self::assertSame(0, $this->callbacks);

        $connection->commit();

        self::assertSame(1, $this->callbacks);
        self::assertSame(1, $this->entryCount());
    }

    /**
     * A callback is kept when an audit insert fails on the probe table's
     * `NOT NULL` column and rolls back to its savepoint, and runs once at the
     * host's commit.
     *
     * @return void
     */
    public function testAHostCallbackSurvivesAFailedAuditInsert(): void
    {
        $this->pointAtProbeTable();

        $connection = $this->storageConnection();

        $connection->beginTransaction();

        $this->registerHostCallback($connection);
        $this->assertTheStoreFails();

        self::assertSame(1, $connection->transactionLevel());

        $connection->commit();

        self::assertSame(1, $this->callbacks);
        self::assertSame(0, $this->probeCount());
    }

    /**
     * A callback is kept when a duplicate's insert rolls back to its savepoint
     * and the duplicate is resolved, and runs once at the host's commit.
     *
     * @return void
     */
    public function testAHostCallbackSurvivesAResolvedDuplicate(): void
    {
        $finalised  = $this->finalised();
        $connection = $this->storageConnection();

        $this->store()->store($finalised);

        $connection->beginTransaction();

        $this->registerHostCallback($connection);

        $this->store()->store($finalised);

        $connection->commit();

        self::assertSame(1, $this->callbacks);
        self::assertSame(1, $this->entryCount());
    }

    /**
     * A host that rolls back drops its callback, which never runs, and the
     * entry the store wrote within it.
     *
     * @return void
     */
    public function testARolledBackHostDropsItsCallbackAndTheEntry(): void
    {
        $connection = $this->storageConnection();

        $connection->beginTransaction();

        $this->registerHostCallback($connection);

        $this->store()->store($this->finalised());

        $connection->rollBack();

        self::assertSame(0, $this->callbacks);
        self::assertSame(0, $this->entryCount());
    }

    /**
     * Under the testing manager, inside its wrapping transaction, a host's
     * callback is kept through a stored record and runs once when the host
     * commits, though the wrapper never does.
     *
     * @return void
     */
    public function testUnderTheTestingManagerAHostCallbackRunsOnceAtTheHostCommit(): void
    {
        $this->insideTheTestingWrapper(function (Connection $connection): void {
            $connection->beginTransaction();

            $this->registerHostCallback($connection);

            $this->store()->store($this->finalised());

            self::assertSame(0, $this->callbacks);

            $connection->commit();

            self::assertSame(1, $this->callbacks);
            self::assertSame(1, $this->entryCount());
        });

        self::assertSame(1, $this->callbacks);
        self::assertSame(0, $this->entryCount());
    }

    /**
     * Under the testing manager a host's callback is kept when an audit insert
     * fails and rolls back to its savepoint, and runs once when the host
     * commits.
     *
     * @return void
     */
    public function testUnderTheTestingManagerAFailedAuditInsertKeepsTheHostCallback(): void
    {
        $this->pointAtProbeTable();

        $this->insideTheTestingWrapper(function (Connection $connection): void {
            $connection->beginTransaction();

            $this->registerHostCallback($connection);
            $this->assertTheStoreFails();

            self::assertSame(2, $connection->transactionLevel());

            $connection->commit();

            self::assertSame(1, $this->callbacks);
        });

        self::assertSame(1, $this->callbacks);
    }

    /**
     * Install the testing manager on the storage connection, open its wrapping
     * transaction as `DatabaseTransactions` does, run the test inside it, and
     * roll the wrapper back however the test ends.
     *
     * @param  \Closure(\Illuminate\Database\Connection): void  $test
     * @return void
     */
    private function insideTheTestingWrapper(\Closure $test): void
    {
        $connection = $this->storageConnection();
        $manager    = new DatabaseTransactionsManager([$connection->getName()]);

        $this->app?->instance('db.transactions', $manager);

        $connection->setTransactionManager($manager);

        $dispatcher = $connection->getEventDispatcher();

        $connection->unsetEventDispatcher();
        $connection->beginTransaction();
        $connection->setEventDispatcher($dispatcher);

        try {
            $test($connection);
        } finally {
            $connection->unsetEventDispatcher();
            $connection->rollBack();
            $connection->setEventDispatcher($dispatcher);
        }
    }

    /**
     * Register the host's after-commit callback on the connection.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     */
    private function registerHostCallback(Connection $connection): void
    {
        $connection->afterCommit(function (): void {
            $this->callbacks++;
        });
    }

    /**
     * Store a record into the probe table, which fails on its `NOT NULL` column
     * with the engine's own `QueryException`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function assertTheStoreFails(): void
    {
        try {
            $this->store()->store($this->finalised());

            self::fail('Expected the audit insert to fail.');
        } catch (QueryException $exception) {
            self::assertStringStartsWith('insert into', $exception->getSql());
        }
    }

    /**
     * The captured record of an approved invoice under the pinned id, finalised
     * on the frozen clock.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function finalised(): FinalisedRecord
    {
        return $this->finaliser()->finalise(RecordFactory::captured(id: self::ID));
    }
}
