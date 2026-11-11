<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Delivery\CaptureSignal;
use SineMacula\Laravel\AuditLog\Delivery\OutboxWriter;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Feature tests for a record written after the transaction: held until the
 * outermost transaction on its connection ends, written whether it commits or
 * rolls back, once, and never letting a failure out of the host's rollback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordDelivery::class)]
#[CoversClass(OutboxWriter::class)]
final class AfterTransactionDeliveryTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore, InteractsWithOutbox;

    /** @var string A second connection, on an in-memory SQLite database. */
    private const string OTHER = 'other';

    /** @var list<string> The class each capture's signal passed on, in order. */
    private array $signalled = [];

    /**
     * Capture every line logged.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->captureLogLines();

        app(ConfigRepository::class)->set('database.connections.' . self::OTHER, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
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
     * With no transaction open, the record is written at once.
     *
     * @return void
     */
    public function testItIsWrittenNowWithNoTransaction(): void
    {
        $this->deliver();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * The record waits for the commit.
     *
     * @return void
     */
    public function testItWaitsForTheCommit(): void
    {
        $connection = DB::connection(self::CONNECTION);

        $connection->beginTransaction();

        $this->deliver();

        self::assertSame(0, $this->entryCount());

        $connection->commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A rollback keeps the record, written once the rollback has finished.
     *
     * @return void
     */
    public function testItSurvivesARollback(): void
    {
        $connection = DB::connection(self::CONNECTION);

        $connection->beginTransaction();

        $this->deliver();
        $connection->rollBack();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A transaction that throws keeps the record, and its exception reaches the
     * caller unchanged.
     *
     * @return void
     */
    public function testItSurvivesATransactionThatThrows(): void
    {
        $this->assertThrows(function (): void {
            DB::connection(self::CONNECTION)->transaction(function (): never {
                $this->deliver();

                throw new \DomainException('Refused.');
            });
        }, \DomainException::class, 'Refused.');

        self::assertSame(1, $this->entryCount());
    }

    /**
     * A rollback inside the outermost transaction leaves the record waiting for
     * the outermost to end.
     *
     * @return void
     */
    public function testANestedRollbackLeavesItWaiting(): void
    {
        $connection = DB::connection(self::CONNECTION);

        $connection->beginTransaction();
        $connection->beginTransaction();

        $this->deliver();
        $connection->rollBack();

        self::assertSame(0, $this->entryCount());

        $connection->commit();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * Writing after a rollback never runs a commit callback of the work that
     * rolled back.
     *
     * @return void
     */
    public function testWritingAfterARollbackRunsNoCallbackOfTheUndoneWork(): void
    {
        $connection = DB::connection(self::CONNECTION);
        $ran        = false;
        $stored     = 0;

        app()->instance(AuditStore::class, new CallbackStore(static function () use ($connection, &$stored): void {
            $connection->transaction(static function () use (&$stored): void {
                $stored++;
            });
        }));

        $connection->beginTransaction();
        $connection->beginTransaction();

        DB::afterCommit(static function () use (&$ran): void {
            $ran = true;
        });

        $connection->commit();

        $this->deliver();
        $connection->rollBack();

        self::assertSame(1, $stored);
        self::assertFalse($ran);
    }

    /**
     * A transaction on another connection does not hold the record.
     *
     * @return void
     */
    public function testATransactionOnAnotherConnectionDoesNotHoldIt(): void
    {
        $other = DB::connection(self::OTHER);

        $other->beginTransaction();

        $this->deliver();

        self::assertSame(1, $this->entryCount());

        $other->rollBack();

        self::assertSame(1, $this->entryCount());
    }

    /**
     * The record is written once, however many transactions end after it.
     *
     * @return void
     */
    public function testItIsWrittenOnce(): void
    {
        $fake       = FakeAuditStore::fake();
        $connection = DB::connection(self::CONNECTION);

        $connection->beginTransaction();

        $this->deliver();
        $connection->commit();

        $connection->beginTransaction();
        $connection->rollBack();

        self::assertSame(1, $fake->count());
    }

    /**
     * Under the `throw` mode a failure after a rollback is spilled and
     * reported, and nothing leaves the rollback.
     *
     * @return void
     */
    public function testAFailureAfterARollbackIsContainedWhateverTheMode(): void
    {
        $reporter   = $this->reporter();
        $connection = DB::connection(self::CONNECTION);

        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $connection->beginTransaction();

        $this->deliver();
        $connection->rollBack();

        self::assertSame(0, $connection->transactionLevel());
        self::assertNotSame([], $reporter->reports());
        self::assertCount(1, $this->spillLines());
    }

    /**
     * Under the `throw` mode a failure at the commit reaches the code that
     * commits, as an after-commit record's does.
     *
     * @return void
     */
    public function testAFailureAtTheCommitFollowsTheRule(): void
    {
        $connection = DB::connection(self::CONNECTION);

        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $connection->beginTransaction();

        $this->deliver();

        $this->assertThrows(static fn () => $connection->commit(), AuditWriteFailedException::class);
    }

    /**
     * A capture's failure after a rollback is signalled, and nothing leaves the
     * rollback.
     *
     * @return void
     */
    public function testACapturesFailureAfterARollbackIsSignalled(): void
    {
        $this->reporter();

        $connection = DB::connection(self::CONNECTION);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        $connection->beginTransaction();

        $this->deliver($this->signal());
        $connection->rollBack();

        self::assertSame([\RuntimeException::class], $this->signalled);
    }

    /**
     * In outbox mode the row is inserted once the transaction on the outbox
     * connection has rolled back.
     *
     * @return void
     */
    public function testTheOutboxRowSurvivesARollback(): void
    {
        $connection = DB::connection(self::CONNECTION);

        app(ConfigRepository::class)->set('audit-log.delivery.mode', 'outbox');

        $connection->beginTransaction();

        $this->deliver();

        self::assertSame(0, $this->outboxCount());

        $connection->rollBack();

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * Deliver a captured record after the transaction.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $signal
     * @return void
     */
    private function deliver(?CaptureSignal $signal = null): void
    {
        app(RecordDelivery::class)->deliver(RecordFactory::captured(), Timing::AFTER_TRANSACTION, null, false, $signal);
    }

    /**
     * A signal that keeps the class of each failure it is told of.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\CaptureSignal
     */
    private function signal(): CaptureSignal
    {
        return new CaptureSignal(function (string $exceptionClass): void {
            $this->signalled[] = $exceptionClass;
        });
    }

    /**
     * Bind a reporter that keeps what it is asked to report, and return it.
     *
     * @return \Tests\Fixtures\Privacy\RecordingExceptionHandler
     */
    private function reporter(): RecordingExceptionHandler
    {
        $reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $reporter);

        return $reporter;
    }
}
