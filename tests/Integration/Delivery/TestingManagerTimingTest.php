<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseTransactionsManager as LaravelManager;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\AfterCommit;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\TestCase;

/**
 * Integration tests for the default timing under Laravel's own transaction
 * manager and the one `DatabaseTransactions` installs, whose wrapping
 * transaction no record selects.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AfterCommit::class)]
#[CoversClass(RecordDelivery::class)]
#[CoversClass(Recorder::class)]
final class TestingManagerTimingTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string A second connection a host transacts on. */
    private const string OTHER = 'audit_other';

    /**
     * Roll back any transaction a test left open, then drop the probe table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (DB::getConnections() as $connection) {
            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }

        $this->removeProbeTable();

        parent::tearDown();
    }

    /**
     * With only the wrapper open, no transaction is selected by default or by
     * name, and neither record waits.
     *
     * @return void
     */
    public function testTheWrapperIsNotSelected(): void
    {
        $this->insideTheTestingWrapper(function (Connection $connection, DatabaseTransactionsManager $manager): void {
            self::assertCount(1, $manager->getPendingTransactions());
            self::assertCount(0, $manager->callbackApplicableTransactions());

            AuditLog::record(self::CODE);
            AuditLog::event(self::CODE)->afterCommit(self::CONNECTION)->record();

            self::assertSame(1, $connection->transactionLevel());
            self::assertSame(2, $this->entryCount());
        });
    }

    /**
     * A record inside only the wrapper is written at once, and the wrapper's
     * rollback takes it.
     *
     * @return void
     */
    public function testARecordInsideOnlyTheWrapperIsWrittenAtOnce(): void
    {
        $this->insideTheTestingWrapper(function (): void {
            $record = AuditLog::record(self::CODE);

            self::assertSame($record->id, $this->storedRow($record->id)['id']);
        });

        self::assertSame(0, $this->entryCount());
    }

    /**
     * A transaction opened inside the wrapper is selected, and its commit
     * writes the record.
     *
     * @return void
     */
    public function testANestedTransactionDefersToItsCommit(): void
    {
        $this->insideTheTestingWrapper(function (Connection $connection): void {
            $connection->beginTransaction();

            AuditLog::record(self::CODE);

            self::assertSame(0, $this->entryCount());

            $connection->commit();

            self::assertSame(1, $connection->transactionLevel());
            self::assertSame(1, $this->entryCount());
        });

        self::assertSame(0, $this->entryCount());
    }

    /**
     * A transaction two levels inside the wrapper waits for the first level's
     * commit.
     *
     * @return void
     */
    public function testAnInnerCommitInsideTheWrapperWaitsForTheHostsOuterCommit(): void
    {
        $this->insideTheTestingWrapper(function (Connection $connection): void {
            $connection->beginTransaction();
            $connection->beginTransaction();

            AuditLog::record(self::CODE);

            $connection->commit();

            self::assertSame(0, $this->entryCount());

            $connection->commit();

            self::assertSame(1, $this->entryCount());
        });
    }

    /**
     * A transaction inside the wrapper drops the record when it rolls back, and
     * the wrapper stays open.
     *
     * @return void
     */
    public function testANestedRollbackDropsTheRecord(): void
    {
        $this->insideTheTestingWrapper(function (Connection $connection): void {
            $connection->beginTransaction();

            AuditLog::record(self::CODE);

            $connection->rollBack();

            self::assertSame(1, $connection->transactionLevel());
            self::assertSame(0, $this->entryCount());
        });
    }

    /**
     * A recorder resolved before the manager was swapped consults the new
     * manager.
     *
     * @return void
     */
    public function testAManagerSwappedAfterTheRecorderIsResolvedIsConsulted(): void
    {
        $recorder = AuditLog::recorder();

        $recorder->record(self::CODE);

        self::assertSame(1, $this->entryCount());

        $this->insideTheTestingWrapper(function (Connection $connection) use ($recorder): void {
            $connection->beginTransaction();

            $recorder->record(self::CODE);

            self::assertSame(1, $this->entryCount());

            $connection->commit();

            self::assertSame(2, $this->entryCount());
        });

        self::assertSame(1, $this->entryCount());
    }

    /**
     * Under Laravel's own manager a record is written on a single transaction's
     * commit and dropped on its rollback.
     *
     * @return void
     */
    public function testTheSameBehaviourUnderLaravelsOwnManager(): void
    {
        $connection = $this->storageConnection();

        self::assertSame(LaravelManager::class, get_debug_type($this->app?->make('db.transactions')));

        $connection->beginTransaction();

        AuditLog::record(self::CODE);

        self::assertSame(0, $this->entryCount());

        $connection->commit();

        self::assertSame(1, $this->entryCount());

        $connection->beginTransaction();

        AuditLog::record(self::CODE);

        $connection->rollBack();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A transaction on a connection the wrapper does not cover is selected, and
     * its commit writes the record.
     *
     * @return void
     */
    public function testATransactionOnAnotherConnectionIsSelected(): void
    {
        $this->insideTheTestingWrapper(function (): void {
            $other = DB::connection(self::OTHER);

            $other->beginTransaction();

            AuditLog::record(self::CODE);
            AuditLog::event(self::CODE)->afterCommit(self::OTHER)->record();

            self::assertSame(0, $this->entryCount());

            $other->commit();

            self::assertSame(2, $this->entryCount());
        });
    }

    /**
     * Pinning the wrapped connection while another is transacting writes the
     * record now.
     *
     * @return void
     */
    public function testPinningTheWrappedConnectionWritesNowWhileAnotherIsOpen(): void
    {
        $this->insideTheTestingWrapper(function (): void {
            DB::connection(self::OTHER)->beginTransaction();

            AuditLog::event(self::CODE)->afterCommit(self::CONNECTION)->record();

            self::assertSame(1, $this->entryCount());

            DB::connection(self::OTHER)->rollBack();

            self::assertSame(1, $this->entryCount());
        });
    }

    /**
     * The wrapper counts as open for `transactional()`, which asks the
     * connection, and its rollback takes the record.
     *
     * @return void
     */
    public function testATransactionalRecordIsAcceptedInsideOnlyTheWrapper(): void
    {
        $this->insideTheTestingWrapper(function (): void {
            AuditLog::event(self::CODE)->transactional()->record();

            self::assertSame(1, $this->entryCount());
        });

        self::assertSame(0, $this->entryCount());
    }

    /**
     * Under the `throw` mode a failed write surfaces at the nested commit, and
     * the wrapper stays usable on every engine.
     *
     * @return void
     */
    public function testAFailedWriteSurfacesAtTheNestedCommitAndTheWrapperStaysUsable(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        $this->pointAtProbeTable();

        $this->insideTheTestingWrapper(function (Connection $connection): void {
            $connection->beginTransaction();

            AuditLog::record(self::CODE);

            try {
                $connection->commit();

                self::fail('Expected the deferred audit insert to fail.');
            } catch (AuditWriteFailedException $exception) {
                self::assertSame(QueryException::class, $exception->exceptionClass);
                self::assertNotNull($exception->sqlState);
            }

            self::assertSame(1, $connection->transactionLevel());
            self::assertSame(0, $this->probeCount());
        });
    }

    /**
     * Register the second transacting connection with its own table prefix.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        $config->set('database.connections.' . self::OTHER, [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'other_']);
    }

    /**
     * Install the testing manager on the storage connection, open its wrapping
     * transaction as `DatabaseTransactions` does, run the test inside it, then
     * roll the wrapper back.
     *
     * @param  \Closure(\Illuminate\Database\Connection, \Illuminate\Foundation\Testing\DatabaseTransactionsManager): void  $test
     * @return void
     */
    private function insideTheTestingWrapper(\Closure $test): void
    {
        $connection = $this->storageConnection();
        $manager    = new DatabaseTransactionsManager([$connection->getName()]);

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
