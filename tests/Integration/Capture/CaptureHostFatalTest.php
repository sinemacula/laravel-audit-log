<?php

declare(strict_types = 1);

namespace Tests\Integration\Capture;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Capture\CaptureFailedException;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Capture\Events\PortalEvent;
use Tests\Fixtures\Capture\Events\SignedInToPortal;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Integration tests for the one failure a capture lets out: a concurrency error
 * or lost connection that ended an open host transaction propagates sanitised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CaptureCoordinator::class)]
final class CaptureHostFatalTest extends TestCase
{
    use CapturesLogLines, SearchesForSecrets;

    /** @var string The message of the sanitised deadlock. */
    private const string SANITISED = 'Deadlock found when trying to get lock; an audit write was abandoned inside the host transaction.';

    /** @var int The code of the sanitised deadlock. */
    private const int SANITISED_CODE = 40001;

    /** @var \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore The store records reach unless a test binds another. */
    private FakeAuditStore $fake;

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> Every `AuditCaptureFailed` heard. */
    private array $failures = [];

    /**
     * Fake the store, bind the reporter and a registry mapping the portal
     * events, capture the log lines and hear each capture failure.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fake     = AuditLog::fake();
        $this->reporter = new RecordingExceptionHandler;
        $registry       = new MapperRegistry;

        $registry->map(PortalEvent::class, PortalMapper::class);

        $this->app?->instance(ExceptionHandler::class, $this->reporter);
        $this->app?->instance(MapperRegistry::class, $registry);
        $this->app?->scopedIf(CapturedEvents::class);

        $this->captureLogLines();

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $failure): void {
            $this->failures[] = $failure;
        });
    }

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
     * A store's deadlock in a host transaction reaches the host as the
     * sanitised, retryable deadlock, with nothing spilled or reported.
     *
     * @return void
     */
    public function testADeadlockInsideAHostTransactionPropagatesSanitised(): void
    {
        $host = $this->host();

        $this->bindStoreRaising(self::deadlock());

        $host->beginTransaction();

        self::assertSanitisedDeadlock($this->thrownBy(static fn () => self::capture()));
        self::assertSame(1, $host->transactionLevel());
        $this->assertNothingSpilledOrReported();
        $this->assertSaidOnce(DeadlockException::class);
    }

    /**
     * A store's lost connection in a host transaction reaches the host as the
     * sanitised failed write, holding nothing of the failure.
     *
     * @return void
     */
    public function testALostConnectionInsideAHostTransactionPropagatesSanitised(): void
    {
        $this->bindStoreRaising(self::lostConnection());

        $this->host()->beginTransaction();

        $thrown = $this->thrownBy(static fn () => self::capture());

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame(QueryException::class, $thrown->exceptionClass);
        self::assertNull($thrown->getPrevious());
        self::assertHoldsNoSecret($thrown->getMessage(), 'the thrown message');
        $this->assertNothingSpilledOrReported();
        $this->assertSaidOnce(QueryException::class);
    }

    /**
     * A contributor's deadlock before the write in a host transaction
     * propagates sanitised, with nothing written, spilled or reported.
     *
     * @return void
     */
    public function testADeadlockBeforeTheWriteInsideAHostTransactionPropagatesSanitised(): void
    {
        $host = $this->host();

        $this->contributeRaising(static function (): never {
            throw self::deadlock();
        });

        $host->beginTransaction();

        self::assertSanitisedDeadlock($this->thrownBy(static fn () => self::capture()));
        self::assertSame(1, $host->transactionLevel());
        self::assertSame(0, $this->fake->count());
        $this->assertNothingSpilledOrReported();
        $this->assertSaidOnce(QueryException::class);
    }

    /**
     * A contributor's lost connection ends the host transaction, which Laravel
     * then forgets, and still propagates as a capture failure of class names
     * alone.
     *
     * @return void
     */
    public function testALostConnectionBeforeTheWriteInsideAHostTransactionPropagatesSanitised(): void
    {
        $host = $this->host();

        $this->contributeRaising(static function () use ($host): never {
            $host->rollBack(0);

            throw self::lostConnection();
        });

        $host->beginTransaction();

        $thrown = $this->thrownBy(static fn () => self::capture());

        self::assertInstanceOf(CaptureFailedException::class, $thrown);
        self::assertSame([SignedInToPortal::class, PortalMapper::class, QueryException::class], [$thrown->eventClass, $thrown->mapperClass, $thrown->exceptionClass]);
        self::assertNull($thrown->getPrevious());
        self::assertHoldsNoSecret($thrown->getMessage(), 'the thrown message');
        self::assertSame(0, $host->transactionLevel());
        self::assertSame(0, $this->fake->count());
        $this->assertNothingSpilledOrReported();
        $this->assertSaidOnce(QueryException::class);
    }

    /**
     * Rows of `[failure, before the write]`: a deadlock and a lost connection,
     * raised by the store or by a contributor.
     *
     * @return iterable<string, array{0: \Closure(): \Illuminate\Database\QueryException, 1: bool}>
     */
    public static function provideFailures(): iterable
    {
        yield from [
            'a store\'s deadlock'              => [self::deadlock(...), false],
            'a store\'s lost connection'       => [self::lostConnection(...), false],
            'a contributor\'s deadlock'        => [self::deadlock(...), true],
            'a contributor\'s lost connection' => [self::lostConnection(...), true],
        ];
    }

    /**
     * With no transaction open the failure ends nothing, so the capture
     * contains it, returns `null` and reports it once.
     *
     * @param  \Closure(): \Illuminate\Database\QueryException  $failure
     * @param  bool  $beforeTheWrite
     * @return void
     */
    #[DataProvider('provideFailures')]
    public function testOutsideATransactionTheSameFailureIsContained(\Closure $failure, bool $beforeTheWrite): void
    {
        if ($beforeTheWrite) {
            $this->contributeRaising(static function () use ($failure): never {
                throw $failure();
            });
        } else {
            $this->bindStoreRaising($failure());
        }

        self::assertNull(self::capture());
        self::assertCount($beforeTheWrite ? 0 : 1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
        self::assertInstanceOf($beforeTheWrite ? CaptureFailedException::class : AuditWriteFailedException::class, $this->reporter->reports()[0]);
        self::assertHoldsNoSecret($this->reporter->reports(), 'the reports');
        self::assertCount(1, $this->failures);
    }

    /**
     * Capture a portal sign-in through its mapping.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function capture(): ?AuditRecord
    {
        return app(CaptureCoordinator::class)->mapped(new SignedInToPortal(secret: self::SECRET));
    }

    /**
     * Bind a store whose write raises the failure inside its own transaction on
     * the worker's connection, as a real insert would.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    private function bindStoreRaising(#[\SensitiveParameter] \Throwable $failure): void
    {
        $connection = $this->host();

        $this->app?->instance(AuditStore::class, new CallbackStore(static function () use ($connection, $failure): void {
            $connection->transaction(static function () use ($failure): never {
                throw $failure;
            });
        }));
    }

    /**
     * Register, for every capture, a contributor that runs the work, which
     * raises before the record is written.
     *
     * @param  \Closure(): never  $work
     * @return void
     */
    private function contributeRaising(#[\SensitiveParameter] \Closure $work): void
    {
        $contributor = new readonly class ($work) implements ContextContributor {
            /**
             * Constructor.
             *
             * @param  \Closure(): never  $work
             */
            public function __construct(

                /** What it runs instead of contributing. */
                #[\SensitiveParameter]
                private \Closure $work,
            ) {}

            /**
             * Run the work, which raises.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\Contribution  $contribution
             * @return void
             */
            #[\Override]
            public function contribute(Contribution $contribution): void
            {
                ($this->work)();
            }
        };

        $registry = new ContributorRegistry;

        $registry->add($contributor::class);

        $this->app?->instance($contributor::class, $contributor);
        $this->app?->instance(ContributorRegistry::class, $registry);
    }

    /**
     * Assert the throwable is the sanitised deadlock, with nothing of the
     * original.
     *
     * @param  \Throwable  $thrown
     * @return void
     */
    private static function assertSanitisedDeadlock(\Throwable $thrown): void
    {
        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertSame(self::SANITISED, $thrown->getMessage());
        self::assertSame(self::SANITISED_CODE, $thrown->getCode());
        self::assertNull($thrown->getPrevious());
    }

    /**
     * Assert nothing was spilled or reported.
     *
     * @return void
     */
    private function assertNothingSpilledOrReported(): void
    {
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * Assert the capture's failure was said once, naming the event, the mapper
     * and the failure's class.
     *
     * @param  string  $exceptionClass
     * @return void
     */
    private function assertSaidOnce(string $exceptionClass): void
    {
        self::assertCount(1, $this->failures);

        $failure = $this->failures[0];

        self::assertSame([SignedInToPortal::class, PortalMapper::class, $exceptionClass], [$failure->eventClass, $failure->mapperClass, $failure->exceptionClass]);
    }

    /**
     * What the work throws.
     *
     * @param  \Closure(): ?\SineMacula\Laravel\AuditLog\Records\AuditRecord  $work
     * @return \Throwable
     */
    private function thrownBy(\Closure $work): \Throwable
    {
        try {
            $work();
        } catch (\Throwable $thrown) {
            return $thrown;
        }

        self::fail('Expected the capture to throw.');
    }

    /**
     * The worker's connection, which the host's transaction and the store
     * share.
     *
     * @return \Illuminate\Database\Connection
     */
    private function host(): Connection
    {
        return DB::connection(self::CONNECTION);
    }

    /**
     * A failure Laravel recognises as a deadlock, whose message and bindings
     * hold the secret as a real one holds the row.
     *
     * @return \Illuminate\Database\QueryException
     */
    private static function deadlock(): QueryException
    {
        return self::queryFailure('SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction');
    }

    /**
     * A failure Laravel recognises as a lost connection, whose message and
     * bindings hold the secret as a real one holds the row.
     *
     * @return \Illuminate\Database\QueryException
     */
    private static function lostConnection(): QueryException
    {
        return self::queryFailure('SQLSTATE[HY000]: General error: 2006 MySQL server has gone away');
    }

    /**
     * A query failure on the worker's connection with the driver's message,
     * holding the secret in its bindings and its message.
     *
     * @param  string  $message
     * @return \Illuminate\Database\QueryException
     */
    private static function queryFailure(string $message): QueryException
    {
        return new QueryException(self::CONNECTION, 'insert into "audit_log_entries" ("note") values (?)', [self::SECRET], new \PDOException($message . ' ' . self::SECRET));
    }
}
