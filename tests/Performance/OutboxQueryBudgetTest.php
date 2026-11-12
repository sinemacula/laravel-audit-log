<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\DB;
use Monolog\Handler\NullHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Delivery\FailureHandler;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxWriter;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;

/**
 * Statement budget for the outbox write path, and for what a failed write adds
 * in either mode. Counts are of the default connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OutboxWriter::class)]
#[CoversClass(Outbox::class)]
#[CoversClass(RecordDelivery::class)]
#[CoversClass(FailureHandler::class)]
final class OutboxQueryBudgetTest extends PerformanceContractTestCase
{
    use CapturesLogLines, InteractsWithAuditStore, InteractsWithOutbox, SeedsTheOutbox;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string A second connection a host transacts on. */
    private const string OTHER = 'audit_other';

    /** @var string The spill channel, which writes nowhere; its lines are captured as logged. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<string> The statements run on the connection the outbox was moved to. */
    private array $movedStatements = [];

    /**
     * Bind the reporter, capture the spill lines, and put the application in
     * outbox mode.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        $this->captureLogLines();
        $this->outboxModeOn();
    }

    /**
     * Roll back any transaction a test left open, then remove what it moved.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ([DB::connection(), DB::connection(self::OTHER)] as $connection) {
            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }

        $this->removeOutboxProbeTable();
        $this->removeProbeTable();
        $this->removeMovedOutbox();

        parent::tearDown();
    }

    /**
     * Outside a transaction a record is its one insert, and no savepoint.
     *
     * @return void
     */
    public function testAnOutboxRecordOutsideATransactionIsOneInsert(): void
    {
        $this->assertStatementBudget(0, 1, 0, 0, fn (): AuditRecord => self::pending()->record());

        self::assertSame(1, $this->outboxCount());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * An outbox write outside a transaction opens none.
     *
     * @return void
     */
    public function testAnOutboxRecordOutsideATransactionOpensNone(): void
    {
        $this->assertTransactionBudget(0, 0, fn (): AuditRecord => self::pending()->record());
    }

    /**
     * Inside a transaction on the outbox connection an after-commit record is
     * one insert now, in a savepoint.
     *
     * @return void
     */
    public function testAnOutboxRecordInsideItsTransactionIsOneInsertAndASavepoint(): void
    {
        DB::beginTransaction();

        $this->assertStatementBudget(0, 1, 1, 0, fn (): AuditRecord => self::pending()->record());

        self::assertSame(1, $this->outboxCount());

        DB::commit();

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * Inside another connection's transaction an after-commit record costs
     * nothing until that commit, then one insert.
     *
     * @return void
     */
    public function testAnOutboxRecordInsideAnotherConnectionsTransactionCostsNothingUntilCommit(): void
    {
        DB::connection(self::OTHER)->beginTransaction();

        $this->assertStatementBudget(0, 0, 0, 0, fn (): AuditRecord => self::pending()->record());

        self::assertSame(0, $this->outboxCount());

        // The other connection is the one asked, so nothing shows on this one
        $this->assertStatementBudget(0, 1, 0, 0, static fn () => DB::connection(self::OTHER)->commit());

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * Another connection's rollback costs only itself: the dropped record was
     * never inserted.
     *
     * @return void
     */
    public function testAnOutboxRecordDroppedByAnotherConnectionsRollbackCostsNothing(): void
    {
        DB::connection(self::OTHER)->beginTransaction();

        $this->assertStatementBudget(0, 0, 0, 0, fn (): AuditRecord => self::pending()->record());
        $this->assertStatementBudget(0, 0, 0, 1, static fn () => DB::connection(self::OTHER)->rollBack());

        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A failed insert inside a transaction adds only its savepoint's rollback;
     * the report, event and spill run no statement.
     *
     * @return void
     */
    public function testAFailedOutboxInsertAddsItsRollback(): void
    {
        $this->pointOutboxAtProbeTable();

        DB::beginTransaction();

        $this->assertStatementBudget(0, 1, 1, 1, fn (): AuditRecord => self::pending()->record());

        self::assertCount(1, $this->reporter->reports());
        self::assertSame(1, DB::transactionLevel());

        $spilledBeforeTheCommit = $this->spillLines();

        self::assertSame([], $spilledBeforeTheCommit);

        $this->assertStatementBudget($this->commitQuestionReads(), 0, 0, 0, static fn () => DB::commit());

        self::assertCount(1, $this->spillLines());
    }

    /**
     * A failed insert outside a transaction is the one insert it tried, with no
     * savepoint.
     *
     * @return void
     */
    public function testAFailedOutboxInsertOutsideATransactionAddsNothing(): void
    {
        $this->pointOutboxAtProbeTable();

        $this->assertStatementBudget(0, 1, 0, 0, fn (): AuditRecord => self::pending()->record());

        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->spillLines());
    }

    /**
     * A failed insert that throws costs what one that reports costs, rolling
     * back only its savepoint.
     *
     * @return void
     */
    public function testAFailedOutboxInsertThatThrowsAddsOnlyItsRollback(): void
    {
        $this->pointOutboxAtProbeTable();

        DB::beginTransaction();

        $thrown = $this->assertStatementBudget(0, 1, 1, 1, static function (): ?\Throwable {
            try {
                self::pending()->transactional()->record();
            } catch (\Throwable $thrown) {
                return $thrown;
            }

            return null;
        });

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame(1, DB::transactionLevel());
        self::assertSame([], $this->spillLines());
    }

    /**
     * An immediate record outside a transaction is one insert, with no
     * savepoint.
     *
     * @return void
     */
    public function testAnImmediateOutboxRecordIsOneInsert(): void
    {
        $this->assertStatementBudget(0, 1, 0, 0, fn (): AuditRecord => self::pending()->immediately()->record());

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * An immediate record inside a transaction is one insert and a savepoint.
     *
     * @return void
     */
    public function testAnImmediateOutboxRecordInsideATransactionIsOneInsertAndASavepoint(): void
    {
        DB::beginTransaction();

        $this->assertStatementBudget(0, 1, 1, 0, fn (): AuditRecord => self::pending()->immediately()->record());

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * A fail-closed record is one insert too, since the outbox acknowledges for
     * it.
     *
     * @return void
     */
    public function testAFailClosedOutboxRecordIsOneInsert(): void
    {
        $this->assertStatementBudget(0, 1, 0, 0, fn (): AuditRecord => self::pending()->failClosed()->record());

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * A transactional record is one insert and a savepoint, inside the
     * transaction it needs.
     *
     * @return void
     */
    public function testATransactionalOutboxRecordIsOneInsertAndASavepoint(): void
    {
        DB::beginTransaction();

        $this->assertStatementBudget(0, 1, 1, 0, fn (): AuditRecord => self::pending()->transactional()->record());

        self::assertSame(1, $this->outboxCount());

        DB::commit();

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * With the outbox on its own connection a record runs nothing on the
     * storage connection, whatever is open there.
     *
     * @return void
     */
    public function testTheOutboxRunsNoStatementOnTheStorageConnection(): void
    {
        $this->moveOutboxToItsOwnConnection();

        DB::connection(self::MOVED_OUTBOX_CONNECTION)->beforeExecuting(function (string $query): void {
            $this->movedStatements[] = $query;
        });

        $this->assertStatementBudget(0, 0, 0, 0, fn (): AuditRecord => self::pending()->immediately()->record());

        self::assertCount(1, $this->movedStatements);
        self::assertStringStartsWith('insert', $this->movedStatements[0]);
        self::assertSame(1, $this->outboxCount());
    }

    /**
     * With the outbox elsewhere a record inside a storage transaction writes
     * nothing on the storage connection; the commit's question is all it adds.
     *
     * @return void
     */
    public function testAStorageTransactionAddsNothingToAnOutboxElsewhere(): void
    {
        $this->moveOutboxToItsOwnConnection();

        DB::beginTransaction();

        $this->assertStatementBudget(0, 0, 0, 0, fn (): AuditRecord => self::pending()->record());
        $this->assertStatementBudget($this->commitQuestionReads(), 0, 0, 0, static fn () => DB::commit());

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * In sync mode a failed write is the insert it tried; the spill, report and
     * event add no statement.
     *
     * @return void
     */
    public function testASyncFailedWriteAddsNoStatement(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::SYNC->value);

        $this->pointAtProbeTable();

        $this->assertStatementBudget(0, 1, 0, 0, fn (): AuditRecord => self::pending()->record());

        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->spillLines());
        self::assertSame(0, $this->probeCount());
    }

    /**
     * Rows of `[delivery mode]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode}>
     */
    public static function provideModes(): iterable
    {
        yield from [
            'sync'   => [DeliveryMode::SYNC],
            'outbox' => [DeliveryMode::OUTBOX],
        ];
    }

    /**
     * A record made during another's write is refused without a statement, in
     * either mode.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testARefusedRecordInsideAWriteAddsNoStatement(DeliveryMode $mode): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', $mode->value);

        $guard = app(WriteGuard::class);

        $this->assertStatementBudget(0, 0, 0, 0, static fn (): AuditRecord => $guard->during(static fn (): AuditRecord => self::pending()->record()));

        self::assertCount(1, $this->reporter->reports());
        self::assertSame(0, $this->outboxCount());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * Spill to a channel that writes nowhere, and configure the second
     * connection a host transacts on.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('logging.channels.' . self::SPILL_CHANNEL, ['driver' => 'monolog', 'handler' => NullHandler::class]);
        $config->set('audit-log.failure.log_channel', self::SPILL_CHANNEL);
        $config->set('database.connections.' . self::OTHER, [...$config->array('database.connections.' . self::CONNECTION), 'prefix' => 'other_']);
    }

    /**
     * A builder of the code.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function pending(): PendingRecord
    {
        return AuditLog::event(self::CODE);
    }
}
