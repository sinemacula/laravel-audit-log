<?php

declare(strict_types = 1);

namespace Tests\Integration\Stores;

use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\RunsInsideTheTestingWrapper;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for a host's after-commit callbacks around the store.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAuditStore::class)]
final class HostTransactionCallbacksTest extends TestCase
{
    use InteractsWithAuditStore, RunsInsideTheTestingWrapper;

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
     * A host callback survives a stored record and runs once at outer commit.
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
     * A host callback survives a failed audit insert and runs once at commit.
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
     * A host callback survives a resolved duplicate and runs once at commit.
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
     * A rolled-back host drops its callback and the stored entry.
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
     * Under the testing manager a host callback runs once at the host's commit.
     *
     * @return void
     */
    public function testUnderTheTestingManagerAHostCallbackRunsOnceAtTheHostCommit(): void
    {
        $this->insideTheTestingWrapper($this->storageConnection(), function (Connection $connection): void {
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
     * Under the testing manager a failed audit insert keeps the host callback.
     *
     * @return void
     */
    public function testUnderTheTestingManagerAFailedAuditInsertKeepsTheHostCallback(): void
    {
        $this->pointAtProbeTable();

        $this->insideTheTestingWrapper($this->storageConnection(), function (Connection $connection): void {
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
     * Store a record into the probe table, failing on its `NOT NULL` column.
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
     * An approved invoice under the pinned id, finalised on the frozen clock.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function finalised(): FinalisedRecord
    {
        return $this->finaliser()->finalise(RecordFactory::captured(id: self::ID));
    }
}
