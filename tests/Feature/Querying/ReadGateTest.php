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
 * Feature tests for the gate every read of the trail passes before anything is
 * queried: re-entry inside a read or a write window or an event mapper,
 * refused and reported once; a store that cannot keep the read's record in
 * sync mode; an open transaction on the storage connection or, in outbox mode,
 * the outbox connection, judged by the framework's own rule; the failure mode
 * never read; and no query made.
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
     * With nothing open, the bound store durable and keeping attachments, the
     * gate lets a read in, in either delivery mode.
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
     * A transaction open on the storage connection refuses the read, naming the
     * connection, since a row it would show, and the read's own record, could
     * still be rolled back.
     *
     * @return void
     */
    public function testAnOpenTransactionOnTheStorageConnectionRefusesTheRead(): void
    {
        DB::connection(self::CONNECTION)->beginTransaction();

        $this->assertRefused(AuditReadRefusedException::inTransaction(self::CONNECTION)->getMessage(), fn () => $this->gate()->enter());
    }

    /**
     * In outbox mode a transaction open on the outbox connection, one of its
     * own, refuses the read, naming that connection, since the committed row is
     * the read's acknowledgement.
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
     * A transaction open on a connection that neither reads the trail nor
     * acknowledges its record refuses nothing: in sync mode the outbox's own
     * connection is such a one, and in outbox mode on the storage connection,
     * any other.
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
     * In sync mode a transaction open on a connection the bound store says it
     * joins refuses the read, naming that connection, both on entry and just
     * before the record is written or acknowledged, since the store's write is
     * durable only once that transaction commits; in outbox mode, where the
     * outbox acknowledges the record, it does not.
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
     * Under the manager Laravel's testing traits install, the test's base
     * transaction, at level 1, counts as committed, as the framework counts it,
     * so a test that wraps itself in a transaction can read the trail; the
     * outbox connection is judged the same way.
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
     * Under that manager a transaction the test opens inside its base one, at
     * level 2, is one the framework would not yet call committed, so the read
     * is refused.
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
     * A transaction open on the storage connection refuses the read whatever
     * the store, one durable on another connection that keeps attachments
     * included, and in either mode, since the read itself is made there.
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
     * In sync mode a store that does not say a return is durable refuses the
     * read, naming its class; in outbox mode, where the outbox acknowledges the
     * record, it does not.
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
     * In sync mode a durable store that keeps no attachment refuses the read,
     * naming its class, since every read's record carries one and would
     * otherwise fail only after the query; in outbox mode it does not.
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
     * Inside a read window every entry is refused, and only the first is
     * reported; the next window's first refusal is reported again, and once the
     * window has ended a read enters.
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
     * Inside a write window, which also covers a failed write being handled,
     * every entry is refused, and only the first is reported.
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
     * Inside both a read and a write window the read window's first refusal is
     * the one said, and the write window's is left for its own refusals.
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
     * While an event mapper runs every entry is refused, before anything is
     * read, and each refusal is reported.
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
     * A reporter that reads the trail while it reports a mapper's refusal is
     * refused too, and that refusal is not reported again, through the report
     * latch, rather than reporting in a loop.
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
     * A reporter that fails is ignored: the refusal is what is thrown, inside a
     * read window, a write window or an event mapper alike.
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
     * A re-entered read is refused as such before the delivery mode or the
     * store is read, so neither a malformed mode nor a store that could not
     * keep the record is what refuses it.
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
     * `confirmDurable()` applies the transaction rule and nothing else: inside
     * a read window, with a store that is not durable, it lets the read on, and
     * a transaction open on the storage connection refuses it.
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
     * `confirmDurable()` judges the outbox connection in outbox mode, and only
     * then.
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
     * The failure mode is never read, since a read's record is fail-closed
     * whatever it says, so a malformed one does not refuse the read.
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
     * A malformed delivery mode is refused as it is read, with its own message,
     * by entering and by `confirmDurable()` alike.
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
     * Without a transactions manager the framework has no rule that would call
     * an open transaction committed, so any open transaction refuses the read.
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
     * A connection that is not a database connection holds no transaction the
     * gate could judge, so it refuses nothing.
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
     * The gate makes no query, whether it lets the read in or refuses it, in
     * either mode.
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
     * The window runs the work inside the read guard and returns what it
     * returns, and closes however the work ends.
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
     * Bind the manager Laravel's testing traits install, over the storage
     * connection.
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
     * Assert that the work is refused with the message, and carries no previous
     * exception.
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
     * A durable store that keeps attachments and joins transactions only on the
     * named connection.
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
