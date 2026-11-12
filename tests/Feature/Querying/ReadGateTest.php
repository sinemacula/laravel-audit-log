<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\ReadGate;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Runtime\ReadGuard;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\NullAuditStore;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Feature tests for the gate every read passes before anything is queried.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReadGate::class)]
final class ReadGateTest extends TestCase
{
    /** @var string A second connection, on an in-memory SQLite database whatever the engine under test. */
    private const string OTHER = 'audit_other';

    /** @var string What a re-entered read is refused with. */
    private const string REENTRANT = 'The audit trail was read while a read of it, an audit record\'s write or its failure, or an event mapper was running,'
        . ' so the read was refused.';

    /**
     * Roll back any transaction a test left open.
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

        parent::tearDown();
    }

    /**
     * With nothing open, the gate lets a read in, in either delivery mode.
     *
     * @return void
     */
    public function testNothingOpenEnters(): void
    {
        $this->gate()->enter();

        $this->deliveryMode('outbox');

        $this->gate()->enter();

        $this->addToAssertionCount(2);
    }

    /**
     * A storage transaction refuses the read: its rows could still roll back.
     *
     * @return void
     */
    public function testAnOpenTransactionOnTheStorageConnectionRefusesTheRead(): void
    {
        DB::connection(self::CONNECTION)->beginTransaction();

        $this->assertRefused(AuditReadRefusedException::inTransaction(self::CONNECTION)->getMessage(), fn () => $this->gate()->enter());
    }

    /**
     * In outbox mode, an outbox transaction refuses the read it acknowledges.
     *
     * @return void
     */
    public function testAnOpenTransactionOnTheOutboxConnectionRefusesAQueuedRead(): void
    {
        $this->deliveryMode('outbox');
        $this->outboxOn(self::OTHER);

        DB::connection(self::OTHER)->beginTransaction();

        $this->assertRefused(AuditReadRefusedException::inTransaction(self::OTHER)->getMessage(), fn () => $this->gate()->enter());
    }

    /**
     * A transaction on an unrelated connection refuses nothing.
     *
     * @return void
     */
    public function testAnotherConnectionsTransactionDoesNotRefuse(): void
    {
        $this->outboxOn(self::OTHER);

        DB::connection(self::OTHER)->beginTransaction();

        $this->gate()->enter();

        $this->deliveryMode('outbox');
        $this->outboxOn(null);

        $this->gate()->enter();

        $this->addToAssertionCount(2);
    }

    /**
     * A transaction the store joins refuses a sync read, on entry and at write.
     *
     * @return void
     */
    public function testAnOpenTransactionTheStoreJoinsRefusesASyncRead(): void
    {
        $this->outboxOn(null);

        $this->app?->instance(AuditStore::class, self::storeOn(self::OTHER));

        DB::connection(self::OTHER)->beginTransaction();

        $refusal = AuditReadRefusedException::inTransaction(self::OTHER)->getMessage();

        $this->assertRefused($refusal, fn () => $this->gate()->enter());
        $this->assertRefused($refusal, fn () => $this->gate()->confirmDurable());

        $this->deliveryMode('outbox');

        $this->gate()->enter();
        $this->gate()->confirmDurable();

        $this->addToAssertionCount(2);
    }

    /**
     * The testing base transaction counts as committed, as Laravel counts it.
     *
     * @return void
     */
    public function testTheTestingManagersBaseTransactionCountsAsCommitted(): void
    {
        $this->testingManager();
        $this->deliveryMode('outbox');

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->gate()->enter();
        $this->gate()->confirmDurable();

        $this->addToAssertionCount(2);
    }

    /**
     * A transaction nested in the testing base transaction refuses the read.
     *
     * @return void
     */
    public function testANestedTransactionUnderTheTestingManagerRefuses(): void
    {
        $connection = DB::connection(self::CONNECTION);

        $this->testingManager();

        $connection->beginTransaction();
        $connection->beginTransaction();

        $this->assertRefused(AuditReadRefusedException::inTransaction(self::CONNECTION)->getMessage(), fn () => $this->gate()->enter());
    }

    /**
     * Rows of `[delivery mode]`: both.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideModes(): iterable
    {
        yield from [
            'sync'   => ['sync'],
            'outbox' => ['outbox'],
        ];
    }

    /**
     * A storage transaction refuses the read, whatever the store or mode.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testAnOpenTransactionOnTheReadConnectionRefusesWhateverTheStore(string $mode): void
    {
        $this->deliveryMode($mode);
        $this->outboxOn(self::OTHER);

        $this->app?->instance(AuditStore::class, self::storeOn(self::OTHER));

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->assertRefused(AuditReadRefusedException::inTransaction(self::CONNECTION)->getMessage(), fn () => $this->gate()->enter());
    }

    /**
     * In sync mode a non-durable store refuses the read, naming its class.
     *
     * @return void
     */
    public function testANonDurableStoreRefuses(): void
    {
        $this->app?->instance(AuditStore::class, new NullAuditStore);

        $this->assertRefused(AuditReadRefusedException::notDurable(NullAuditStore::class)->getMessage(), fn () => $this->gate()->enter());

        $this->deliveryMode('outbox');

        $this->gate()->enter();
    }

    /**
     * In sync mode a store keeping no attachment refuses the read up front.
     *
     * @return void
     */
    public function testAStoreThatKeepsNoArtifactsRefuses(): void
    {
        $this->app?->instance(AuditStore::class, CallbackStore::saying(true, [self::CONNECTION]));

        $this->assertRefused(AuditReadRefusedException::keepsNoArtifacts(CallbackStore::class)->getMessage(), fn () => $this->gate()->enter());

        $this->deliveryMode('outbox');

        $this->gate()->enter();
    }

    /**
     * Inside a read window entry is refused, reported once per window.
     *
     * @return void
     */
    public function testInsideAReadWindowEntryIsRefusedAndReportedOnce(): void
    {
        $reporter = $this->reporter();
        $guard    = app(ReadGuard::class);

        $guard->during(function (): void {
            $this->assertReentrant();
            $this->assertReentrant();
        });

        $afterOne = count($reporter->reports());

        $guard->during(function (): void {
            $this->assertReentrant();
        });

        $this->gate()->enter();

        $reports = $reporter->reports();

        self::assertSame([1, 2], [$afterOne, count($reports)]);
        self::assertInstanceOf(AuditReadRefusedException::class, $reports[0]);
        self::assertSame(self::REENTRANT, $reports[1]->getMessage());
    }

    /**
     * Inside a write window entry is refused, and only the first is reported.
     *
     * @return void
     */
    public function testInsideAWriteWindowEntryIsRefusedAndReportedOnce(): void
    {
        $reporter = $this->reporter();

        app(WriteGuard::class)->during(function (): void {
            $this->assertReentrant();
            $this->assertReentrant();
        });

        $this->gate()->enter();

        self::assertCount(1, $reporter->reports());
        self::assertSame(self::REENTRANT, $reporter->reports()[0]->getMessage());
    }

    /**
     * Inside both windows, the read window's first refusal is the one said.
     *
     * @return void
     */
    public function testInsideBothWindowsTheReadWindowsRefusalIsSaid(): void
    {
        $reporter = $this->reporter();
        $writes   = app(WriteGuard::class);

        $first = app(ReadGuard::class)->during(fn (): bool => $writes->during(function () use ($writes): bool {
            $this->assertReentrant();
            $this->assertReentrant();

            return $writes->isFirstRefusal();
        }));

        self::assertTrue($first);
        self::assertCount(1, $reporter->reports());
    }

    /**
     * While an event mapper runs every entry is refused and reported.
     *
     * @return void
     */
    public function testInsideAnEventMapperEntryIsRefused(): void
    {
        $reporter = $this->reporter();

        app(CapturedEvents::class)->whileMapping(function (): void {
            $this->assertReentrant();
            $this->assertReentrant();
        });

        $this->gate()->enter();

        self::assertCount(2, $reporter->reports());
        self::assertSame(self::REENTRANT, $reporter->reports()[0]->getMessage());
    }

    /**
     * A reporter that reads during a mapper's refusal is latched, not looped.
     *
     * @return void
     */
    public function testAMappersRefusalIsReportedThroughTheLatch(): void
    {
        $reports = 0;
        $handler = \Mockery::mock(ExceptionHandler::class);

        $handler->shouldReceive('report')->andReturnUsing(function () use (&$reports): void {
            $reports++;

            if ($reports > 5) {
                self::fail('The reporter was called in a loop.');
            }

            $this->assertReentrant();
        });

        $this->app?->instance(ExceptionHandler::class, $handler);

        app(CapturedEvents::class)->whileMapping(function (): void {
            $this->assertReentrant();
        });

        self::assertSame(1, $reports);
    }

    /**
     * A failing reporter is ignored and the refusal is still thrown.
     *
     * @return void
     */
    public function testAFailingReporterStillRefuses(): void
    {
        $this->app?->instance(ExceptionHandler::class, new RecordingExceptionHandler(throwsOnReport: true));

        app(ReadGuard::class)->during(function (): void {
            $this->assertReentrant();
        });

        app(WriteGuard::class)->during(function (): void {
            $this->assertReentrant();
        });

        app(CapturedEvents::class)->whileMapping(function (): void {
            $this->assertReentrant();
        });
    }

    /**
     * A re-entered read is refused before the mode or the store is read.
     *
     * @return void
     */
    public function testReentryIsRefusedFirst(): void
    {
        $this->reporter();

        $this->deliveryMode('carrier-pigeon');
        $this->app?->instance(AuditStore::class, new NullAuditStore);

        app(ReadGuard::class)->during(function (): void {
            $this->assertReentrant();
        });
    }

    /**
     * `confirmDurable()` applies the transaction rule alone.
     *
     * @return void
     */
    public function testConfirmDurableAppliesTheTransactionRuleAlone(): void
    {
        $gate = $this->gate();

        $this->app?->instance(AuditStore::class, new NullAuditStore);

        app(ReadGuard::class)->during(static function () use ($gate): void {
            $gate->confirmDurable();
        });

        DB::connection(self::CONNECTION)->beginTransaction();

        $this->assertRefused(AuditReadRefusedException::inTransaction(self::CONNECTION)->getMessage(), static fn () => $gate->confirmDurable());
    }

    /**
     * `confirmDurable()` judges the outbox connection in outbox mode only.
     *
     * @return void
     */
    public function testConfirmDurableJudgesTheOutboxConnectionInOutboxMode(): void
    {
        $this->outboxOn(self::OTHER);

        DB::connection(self::OTHER)->beginTransaction();

        $this->gate()->confirmDurable();

        $this->deliveryMode('outbox');

        $this->assertRefused(AuditReadRefusedException::inTransaction(self::OTHER)->getMessage(), fn () => $this->gate()->confirmDurable());
    }

    /**
     * The failure mode is never read: a read's record is always fail-closed.
     *
     * @return void
     */
    public function testTheFailureModeIsNeverRead(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', 'carrier-pigeon');

        $this->gate()->enter();
        $this->gate()->confirmDurable();

        $this->addToAssertionCount(2);
    }

    /**
     * A malformed delivery mode is refused as it is read, with its own message.
     *
     * @return void
     */
    public function testAMalformedDeliveryModePropagates(): void
    {
        $this->deliveryMode('carrier-pigeon');

        $this->assertThrows(fn () => $this->gate()->enter(), \InvalidArgumentException::class, '`audit-log.delivery.mode` must be `sync` or `outbox`.');
        $this->assertThrows(fn () => $this->gate()->confirmDurable(), \InvalidArgumentException::class, '`audit-log.delivery.mode` must be `sync` or `outbox`.');
    }

    /**
     * Without a transactions manager any open transaction refuses the read.
     *
     * @return void
     */
    public function testWithoutATransactionsManagerAnyOpenTransactionRefuses(): void
    {
        $connection = DB::connection(self::CONNECTION);

        $this->testingManager();

        $connection->beginTransaction();

        $this->gate()->enter();

        $this->app?->offsetUnset('db.transactions');

        $this->assertRefused(AuditReadRefusedException::inTransaction(self::CONNECTION)->getMessage(), fn () => $this->gate()->enter());
    }

    /**
     * A connection that is no database connection refuses nothing.
     *
     * @return void
     */
    public function testAConnectionThatIsNoDatabaseConnectionHoldsNothing(): void
    {
        $resolver = \Mockery::mock(ConnectionResolverInterface::class);

        $resolver->shouldReceive('connection')->andReturn(\Mockery::mock(ConnectionInterface::class));

        DB::connection(self::CONNECTION)->beginTransaction();

        (new ReadGate(app(), $resolver))->enter();

        $this->addToAssertionCount(1);
    }

    /**
     * The gate makes no query, letting in or refusing, in either mode.
     *
     * @return void
     */
    public function testTheGateMakesNoQuery(): void
    {
        $queries = [];

        $this->outboxOn(self::OTHER);

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $this->gate()->enter();
        $this->deliveryMode('outbox');
        $this->gate()->enter();

        DB::connection(self::OTHER)->beginTransaction();

        $this->assertRefused(AuditReadRefusedException::inTransaction(self::OTHER)->getMessage(), fn () => $this->gate()->enter());

        self::assertSame([], $queries);
    }

    /**
     * The window runs the work inside the read guard and always closes.
     *
     * @return void
     */
    public function testTheWindowIsTheReadGuards(): void
    {
        $guard = app(ReadGuard::class);

        self::assertTrue($this->gate()->window(static fn (): bool => $guard->isActive()));

        $this->assertThrows(
            fn () => $this->gate()->window(static function (): void {
                throw new \RuntimeException('The query failed.');
            }),
            \RuntimeException::class,
            'The query failed.',
        );

        self::assertFalse($guard->isActive());
    }

    /**
     * Add the second connection, on its own in-memory SQLite database.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        app(ConfigRepository::class)->set('database.connections.' . self::OTHER, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
    }

    /**
     * The gate, as the container builds it.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\ReadGate
     */
    private function gate(): ReadGate
    {
        return app(ReadGate::class);
    }

    /**
     * Set the delivery mode.
     *
     * @param  string  $mode
     * @return void
     */
    private function deliveryMode(string $mode): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', $mode);
    }

    /**
     * Put the outbox on the named connection, or on the storage connection.
     *
     * @param  ?string  $connection
     * @return void
     */
    private function outboxOn(?string $connection): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.outbox.connection', $connection);
    }

    /**
     * Bind the transactions manager Laravel's testing traits install.
     *
     * @return void
     */
    private function testingManager(): void
    {
        $manager = new DatabaseTransactionsManager([self::CONNECTION]);

        $this->app?->instance('db.transactions', $manager);

        DB::connection(self::CONNECTION)->setTransactionManager($manager);
    }

    /**
     * Bind a reporter that keeps what it is asked to report, and return it.
     *
     * @return \Tests\Fixtures\Privacy\RecordingExceptionHandler
     */
    private function reporter(): RecordingExceptionHandler
    {
        $reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $reporter);

        return $reporter;
    }

    /**
     * Assert that entering the gate now is refused as a re-entered read.
     *
     * @return void
     */
    private function assertReentrant(): void
    {
        $this->assertRefused(self::REENTRANT, fn () => $this->gate()->enter());
    }

    /**
     * Assert the work is refused with the message and no previous exception.
     *
     * @param  string  $message
     * @param  \Closure(): void  $work
     * @return void
     */
    private function assertRefused(string $message, \Closure $work): void
    {
        try {
            $work();

            self::fail('Expected the read to be refused.');
        } catch (AuditReadRefusedException $exception) {
            self::assertSame($message, $exception->getMessage());
            self::assertNull($exception->getPrevious());
        }
    }

    /**
     * A durable store that keeps attachments and joins the named connection.
     *
     * @param  string  $connection
     * @return \SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments&\SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore
     */
    private static function storeOn(string $connection): AcceptsAttachments&DurableAuditStore
    {
        return new readonly class ($connection) implements AcceptsAttachments, DurableAuditStore {
            /**
             * Constructor.
             *
             * @param  string  $connection
             */
            public function __construct(

                /** The connection whose transactions it joins. */
                private string $connection,
            ) {}

            /**
             * Keep nothing.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
             * @return void
             */
            #[\Override]
            public function store(#[\SensitiveParameter] FinalisedRecord $record): void {}

            /**
             * Say a return is durable.
             *
             * @return bool
             */
            #[\Override]
            public function isDurable(): bool
            {
                return true;
            }

            /**
             * Say it joins a transaction on its own connection alone.
             *
             * @param  string  $connection
             * @return bool
             */
            #[\Override]
            public function participatesIn(string $connection): bool
            {
                return $connection === $this->connection;
            }

            /**
             * Keep every attachment.
             *
             * @return bool
             */
            #[\Override]
            public function acceptsAttachments(): bool
            {
                return true;
            }
        };
    }
}
