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
 * Integration tests for the default timing under both transaction managers, on
 * the engine the suite runs against: the manager Laravel's
 * `DatabaseTransactions` testing trait installs, whose wrapping transaction no
 * record ever selects, and Laravel's own, under which a host's outermost
 * transaction is selected. The current manager is the one consulted, however
 * long ago the recorder was resolved.
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
     * With only the wrapper open there is no transaction to select, by default
     * or by naming its connection: the manager has it pending and leaves it out
     * of those callbacks apply to, and neither record waits for it.
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
     * A record inside only the wrapper is written at once, the way a test
     * expects to read it back, and the wrapper's rollback takes it away.
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
     * A transaction the test opens inside the wrapper is selected, and its
     * commit writes the record though the wrapper never commits.
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
     * A transaction two levels inside the wrapper waits for the commit of the
     * first level, as it does one level above under Laravel's own manager.
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
     * A transaction the test opens inside the wrapper drops the record when it
     * rolls back, and the wrapper stays open.
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
     * A record made through a recorder resolved, and used, before the manager
     * was swapped still defers to the new manager's transaction: the old
     * manager knows of none, so consulting it would write the record at once.
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
     * Under Laravel's own manager the same single transaction is selected, and
     * nothing is left out: a record is written on its commit and dropped on its
     * rollback.
     *
     * @return void
     */
    public function testTheSameBehaviourUnderLaravelsOwnManager(): void
    {
        $connection = $this->storageConnection();

        self::assertSame(LaravelManager::class, get_class($this->app?->make('db.transactions')));

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
     * A transaction on a connection the wrapper does not cover is selected by
     * default and by name, and its commit writes the record inside the wrapper.
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
     * Naming the wrapped connection while another connection is transacting
     * finds the wrapper alone on it, which is not selected, so the record is
     * written now.
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
     * The wrapper counts as an open transaction for `transactional()`, which
     * asks the connection and not the manager: a test can exercise the timing
     * inside it, and the wrapper's rollback takes the record away.
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
     * Under the `throw` mode a failed write surfaces from the nested commit in
     * a savepoint of the wrapper, which stays usable on every engine.
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
     * Register the second transacting connection, with a table prefix of its
     * own.
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
     * transaction as `DatabaseTransactions` does, run the test inside it, and
     * roll the wrapper back however the test ends.
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
