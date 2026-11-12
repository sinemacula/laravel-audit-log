<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Monolog\Handler\NullHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Delivery\CommitFlush;
use SineMacula\Laravel\AuditLog\Delivery\CommitQueue;
use SineMacula\Laravel\AuditLog\Delivery\FailureHandler;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Integration tests for a PostgreSQL transaction aborted by a swallowed
 * failure, whose commit PostgreSQL reports a success: no deferred write and no
 * replayable spill may follow.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CommitQueue::class)]
#[CoversClass(CommitFlush::class)]
#[CoversClass(FailureHandler::class)]
final class AbortedCommitTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore, InteractsWithOutbox, SeedsTheOutbox;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string A table the host transaction writes to. */
    private const string HOST_TABLE = 'audit_aborted_host_writes';

    /** @var string A second connection, whose commit a pinned record waits for. */
    private const string SECOND = 'audit_second';

    /** @var string The spill channel, which writes nowhere; lines are captured as logged. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler The application's reporter. */
    private RecordingExceptionHandler $reporter;

    /** @var list<object> Every `AuditRecorded` and `AuditWriteFailed` heard. */
    private array $events = [];

    /**
     * Create the host's table, bind the reporter, capture spill lines and hear
     * the package's events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::dropIfExists(self::HOST_TABLE);

        Schema::create(self::HOST_TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('name', 32);
        });

        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        $this->captureLogLines();

        Event::listen([AuditRecorded::class, AuditWriteFailed::class], function (object $event): void {
            $this->events[] = $event;
        });
    }

    /**
     * Roll back any transaction a test left open, and drop the host's table.
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

        $this->removeMovedOutbox();

        Schema::dropIfExists(self::HOST_TABLE);

        parent::tearDown();
    }

    /**
     * A healthy commit writes the record on every engine.
     *
     * @return void
     */
    public function testAHealthyCommitWritesTheRecord(): void
    {
        $statements = [];

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query) use (&$statements): void {
            $statements[] = $query;
        });

        DB::transaction(function (): void {
            $this->writeTheBusinessChange();

            AuditLog::event(self::CODE)->record();
        });

        self::assertSame(1, $this->hostRows());
        self::assertSame(1, $this->entryCount());
        self::assertCount($this->host()->getDriverName() === 'pgsql' ? 1 : 0, array_keys($statements, 'select 1', true));
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * A sync after-commit record of a transaction whose failure was swallowed
     * is not written, spilled or dispatched, and is reported.
     *
     * @return void
     */
    public function testASyncRecordOfAnAbortedTransactionIsNotWritten(): void
    {
        $this->skipUnlessPostgres();

        $record = null;

        DB::transaction(function () use (&$record): void {
            $this->writeTheBusinessChange();

            $record = AuditLog::event(self::CODE)->record();

            $this->failAStatementAndSwallowIt();
        });

        self::assertSame(0, $this->hostRows());
        self::assertSame(0, $this->entryCount());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->events);
        self::assertCount(1, $this->reporter->reports());

        $reported = $this->reporter->reports()[0];

        self::assertInstanceOf(AuditWriteFailedException::class, $reported);
        self::assertSame($record?->id, $reported->recordId);
        self::assertSame('25P02', $reported->sqlState);
        self::assertNull($reported->getPrevious());
    }

    /**
     * Every record waiting on an aborted commit is dropped and reported, a
     * nested transaction's included.
     *
     * @return void
     */
    public function testEveryRecordOfAnAbortedTransactionIsDropped(): void
    {
        $this->skipUnlessPostgres();

        DB::transaction(function (): void {
            AuditLog::event(self::CODE)->record();

            DB::transaction(static function (): void {
                AuditLog::event(self::CODE)->record();
            });

            $this->failAStatementAndSwallowIt();
        });

        self::assertSame(0, $this->entryCount());
        self::assertCount(2, $this->reporter->reports());
    }

    /**
     * An outbox on another connection inserts no row for an aborted commit.
     *
     * @return void
     */
    public function testAnOutboxRowOfAnAbortedTransactionIsNotInserted(): void
    {
        $this->skipUnlessPostgres();

        $this->outboxModeOn();
        $this->moveOutboxToItsOwnConnection();

        DB::transaction(function (): void {
            $this->writeTheBusinessChange();

            AuditLog::event(self::CODE)->record();

            $this->failAStatementAndSwallowIt();
        });

        self::assertSame(0, $this->hostRows());
        self::assertSame(0, $this->outboxCount());
        self::assertSame([], $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
    }

    /**
     * A spill bound to a commit that is later aborted leaves no replayable
     * line.
     *
     * @return void
     */
    public function testASpillBoundBeforeTheHostAbortedIsNotWritten(): void
    {
        $this->skipUnlessPostgres();

        $this->outboxModeOn();

        config()->set('audit-log.delivery.outbox.table', 'audit_no_such_outbox');

        DB::transaction(function (): void {
            $this->writeTheBusinessChange();

            AuditLog::event(self::CODE)->record();

            self::assertCount(1, $this->reporter->reports());

            $this->failAStatementAndSwallowIt();
        });

        self::assertSame(0, $this->hostRows());
        self::assertSame([], $this->spillLines());
    }

    /**
     * A stack over an aborted host discards the spill of its refused database
     * destination.
     *
     * @return void
     */
    public function testAStackOverAnAbortedHostLeavesNoSpill(): void
    {
        $this->skipUnlessPostgres();

        app()->instance(AuditStore::class, new StackAuditStore(['database' => app(DatabaseAuditStore::class)]));

        $host   = $this->host();
        $second = DB::connection(self::SECOND);

        $host->beginTransaction();
        $this->writeTheBusinessChange();
        $this->failAStatementAndSwallowIt();

        $second->beginTransaction();

        AuditLog::event(self::CODE)->afterCommit(self::SECOND)->record();

        $second->commit();

        self::assertCount(1, $this->reporter->reports());
        self::assertInstanceOf(AuditWriteFailedException::class, $this->reporter->reports()[0]);
        self::assertSame('database', $this->reporter->reports()[0]->destination);

        $host->commit();

        self::assertSame(0, $this->hostRows());
        self::assertSame(0, $this->entryCount());
        self::assertSame([], $this->spillLines());
    }

    /**
     * Spill to a channel that writes nowhere, and register a second connection.
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

        $config->set('logging.channels.' . self::SPILL_CHANNEL, ['driver' => 'monolog', 'handler' => NullHandler::class]);
        $config->set('audit-log.failure.log_channel', self::SPILL_CHANNEL);
        $config->set('database.connections.' . self::SECOND, $config->array('database.connections.' . self::CONNECTION));
    }

    /**
     * Run a failing statement and swallow it, as an application might.
     *
     * @return void
     */
    private function failAStatementAndSwallowIt(): void
    {
        try {
            $this->host()->select('select 1/0');
        } catch (QueryException) { // @phpstan-ignore catch.neverThrown
            // Swallowed, leaving the transaction aborted with a commit to come
        }
    }

    /**
     * Write the host's business change.
     *
     * @return void
     */
    private function writeTheBusinessChange(): void
    {
        $this->host()->table(self::HOST_TABLE)->insert(['name' => 'work']);
    }

    /**
     * How many business rows the host's table holds.
     *
     * @return int
     */
    private function hostRows(): int
    {
        return $this->host()->table(self::HOST_TABLE)->count();
    }

    /**
     * The host's connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function host(): Connection
    {
        return DB::connection(self::CONNECTION);
    }

    /**
     * Skip a test of a state only PostgreSQL has.
     *
     * @return void
     */
    private function skipUnlessPostgres(): void
    {
        if ($this->host()->getDriverName() === 'pgsql') {
            return;
        }

        self::markTestSkipped('Only PostgreSQL leaves a transaction aborted by a failed statement.');
    }
}
