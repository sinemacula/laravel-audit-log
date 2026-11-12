<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseTransactionsManager as LaravelManager;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Monolog\Handler\NullHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\AfterCommit;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxWriter;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\RunsInsideTheTestingWrapper;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Integration tests for the outbox write path inside real transactions, under
 * Laravel's own transaction manager and the one `DatabaseTransactions`
 * installs. In-memory SQLite has no second session, so there the tests rely on
 * what the rollback leaves.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AfterCommit::class)]
#[CoversClass(Outbox::class)]
#[CoversClass(OutboxWriter::class)]
final class OutboxTransactionsTest extends TestCase
{
    use CapturesLogLines, InteractsWithOutbox, RunsInsideTheTestingWrapper;

    /** @var string A table the host transaction writes to. */
    private const string HOST_TABLE = 'audit_host_writes';

    /** @var string A second session on the worker's database. */
    private const string READER = 'audit_reader';

    /** @var string The spill channel, which writes nowhere; lines are captured as logged. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler The application's reporter. */
    private RecordingExceptionHandler $reporter;

    /**
     * Create the host's table, bind the reporter and capture spill lines.
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
    }

    /**
     * Roll back any open transaction, then drop what the test added.
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

        $this->removeOutboxProbeTable();
        $this->removeMovedOutbox();

        Schema::dropIfExists(self::HOST_TABLE);

        parent::tearDown();
    }

    /**
     * The row exists for other sessions exactly when the host's work does.
     *
     * @return void
     */
    public function testAnOutboxRowCommitsWithTheHost(): void
    {
        $host = $this->outboxConnection();

        $host->beginTransaction();
        $host->table(self::HOST_TABLE)->insert(['name' => 'work']);

        $this->write();

        $this->assertAnotherSessionSees(0);

        $host->commit();

        $this->assertAnotherSessionSees(1);

        self::assertSame(1, $this->outboxCount());
        self::assertSame(1, $host->table(self::HOST_TABLE)->count());
    }

    /**
     * An outer rollback takes the row with the host's work.
     *
     * @return void
     */
    public function testAnOuterRollbackRemovesTheRow(): void
    {
        $host = $this->outboxConnection();

        $host->beginTransaction();
        $host->table(self::HOST_TABLE)->insert(['name' => 'work']);

        $this->write();

        self::assertSame(1, $this->outboxCount());

        $host->rollBack();

        self::assertSame(0, $this->outboxCount());
        self::assertSame(0, $host->table(self::HOST_TABLE)->count());
    }

    /**
     * Rolling back the transaction holding the row takes it, and the outer
     * transaction commits without it.
     *
     * @return void
     */
    public function testAnInnerRollbackRemovesTheRow(): void
    {
        $host = $this->outboxConnection();

        $host->beginTransaction();
        $host->beginTransaction();

        $this->write();

        $host->rollBack();

        self::assertSame(0, $this->outboxCount());

        $host->commit();

        self::assertSame(0, $this->outboxCount());
    }

    /**
     * An inner rollback keeps a row the outer transaction already holds.
     *
     * @return void
     */
    public function testAnInnerRollbackKeepsARowOfTheOuterTransaction(): void
    {
        $host = $this->outboxConnection();

        $host->beginTransaction();

        $kept = $this->write();

        $host->beginTransaction();

        $dropped = $this->write();

        $host->rollBack();
        $host->commit();

        self::assertNotNull($this->outboxRow($kept));
        self::assertNull($this->outboxRow($dropped));
    }

    /**
     * A row from a committed inner transaction waits for the outer: unseen by
     * other sessions and taken by its rollback.
     *
     * @return void
     */
    public function testAnInnerCommitWaitsForTheOuter(): void
    {
        $host = $this->outboxConnection();

        $host->beginTransaction();
        $host->beginTransaction();

        $this->write();

        $host->commit();

        $this->assertAnotherSessionSees(0);

        $host->rollBack();

        self::assertSame(0, $this->outboxCount());

        $host->beginTransaction();
        $host->beginTransaction();

        $this->write();

        $host->commit();
        $host->commit();

        $this->assertAnotherSessionSees(1);

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * A failed insert runs in a savepoint, so the host commits and its spill
     * waits for that commit.
     *
     * @return void
     */
    public function testAFailedInsertLeavesAHealthyHostCommitting(): void
    {
        $host = $this->outboxConnection();

        // Created first: MySQL commits an open transaction on any DDL
        $this->pointOutboxAtProbeTable();

        $host->beginTransaction();
        $host->table(self::HOST_TABLE)->insert(['name' => 'before']);

        $this->write();

        self::assertSame(1, $host->transactionLevel());
        self::assertSame([], $this->spillLines());

        $host->table(self::HOST_TABLE)->insert(['name' => 'after']);
        $host->commit();

        self::assertSame(['before', 'after'], $host->table(self::HOST_TABLE)->orderBy('id')->pluck('name')->all());
        self::assertSame(0, $host->table(self::OUTBOX_PROBE_TABLE)->count());
        self::assertCount(1, $this->spillLines());
    }

    /**
     * A failed insert drops none of the host's callbacks, and a throwing rule
     * leaves the host able to commit.
     *
     * @return void
     */
    public function testAFailedInsertKeepsTheHostsCallbacks(): void
    {
        $host = $this->outboxConnection();
        $ran  = [];

        $this->pointOutboxAtProbeTable();

        $host->beginTransaction();

        $host->afterCommit(static function () use (&$ran): void {
            $ran[] = 'before';
        });

        try {
            $this->write(rule: FailureRule::SPILL_AND_THROW);

            self::fail('Expected the insert to be thrown.');
        } catch (AuditWriteFailedException $thrown) {
            self::assertSame(QueryException::class, $thrown->exceptionClass);
            self::assertSame('outbox', $thrown->operation);
        }

        $host->afterCommit(static function () use (&$ran): void {
            $ran[] = 'after';
        });

        $host->commit();

        self::assertSame(['before', 'after'], $ran);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * An immediate row rolls back with an enclosing transaction on the outbox
     * connection.
     *
     * @return void
     */
    public function testAnImmediateRowRollsBackWithAnEnclosingTransaction(): void
    {
        $host = $this->outboxConnection();

        $host->beginTransaction();

        $this->write(Timing::IMMEDIATE);

        self::assertSame(1, $this->outboxCount());

        $host->rollBack();

        self::assertSame(0, $this->outboxCount());
    }

    /**
     * On a dedicated outbox connection an immediate row survives a host
     * rollback on another connection.
     *
     * @return void
     */
    public function testADedicatedOutboxConnectionIgnoresTheHostsRollback(): void
    {
        $this->moveOutboxToItsOwnConnection();

        $host = DB::connection(self::CONNECTION);

        $host->beginTransaction();

        $this->write(Timing::IMMEDIATE);

        $host->rollBack();

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * On a dedicated outbox connection an after-commit record is dropped by the
     * host's rollback and inserted on its commit.
     *
     * @return void
     */
    public function testADedicatedOutboxConnectionWaitsForTheHostsCommit(): void
    {
        $this->moveOutboxToItsOwnConnection();

        $host = DB::connection(self::CONNECTION);

        $host->beginTransaction();

        $this->write();

        $host->rollBack();

        self::assertSame(0, $this->outboxCount());

        $host->beginTransaction();

        $this->write();

        self::assertSame(0, $this->outboxCount());

        $host->commit();

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * With two connections transacting at once, each row follows the innermost
     * transaction that decided it.
     *
     * @return void
     */
    public function testInterleavedTransactionsOnTwoConnections(): void
    {
        $this->moveOutboxToItsOwnConnection();

        $host   = DB::connection(self::CONNECTION);
        $outbox = $this->outboxConnection();

        // The outbox's transaction is the innermost, so it holds the row and
        // the host's commit does not save it
        $host->beginTransaction();
        $outbox->beginTransaction();

        $this->write();

        $host->commit();

        self::assertSame(1, $this->outboxCount());

        $outbox->rollBack();

        self::assertSame(0, $this->outboxCount());

        // The host's transaction is the innermost, so the row waits for it and
        // the outbox's rollback does not touch it
        $outbox->beginTransaction();
        $host->beginTransaction();

        $this->write();

        $outbox->rollBack();

        self::assertSame(0, $this->outboxCount());

        $host->commit();

        self::assertSame(1, $this->outboxCount());
    }

    /**
     * A host PostgreSQL has aborted refuses the savepoint, and the spill is
     * discarded because its commit is really a rollback.
     *
     * @return void
     */
    public function testAnAbortedPostgresHostDiscardsTheBoundSpill(): void
    {
        $host = $this->outboxConnection();

        if ($host->getDriverName() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL leaves a transaction aborted by a failed statement.');
        }

        $host->beginTransaction();

        $this->assertThrows(static fn (): bool => $host->statement('select * from audit_no_such_table'), QueryException::class);

        $this->write();

        self::assertCount(1, $this->reporter->reports());

        $host->commit();

        self::assertSame([], $this->spillLines());
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * Inside only the testing wrapper no transaction is selected, so the row is
     * inserted now and the wrapper's rollback takes it.
     *
     * @return void
     */
    public function testInsideOnlyTheWrapperIsInsertedNow(): void
    {
        $this->insideTheTestingWrapper($this->outboxConnection(), function (Connection $connection, DatabaseTransactionsManager $manager): void {
            self::assertCount(0, $manager->callbackApplicableTransactions());

            $this->write();
            $this->write(transaction: self::CONNECTION);

            self::assertSame(1, $connection->transactionLevel());
            self::assertSame(2, $this->outboxCount());
        });

        self::assertSame(0, $this->outboxCount());
    }

    /**
     * A failed insert inside only the wrapper binds nothing, so the spill is
     * written at once.
     *
     * @return void
     */
    public function testInsideOnlyTheWrapperASpillIsWrittenAtOnce(): void
    {
        $this->pointOutboxAtProbeTable();

        $this->insideTheTestingWrapper($this->outboxConnection(), function (): void {
            $this->write();

            self::assertCount(1, $this->spillLines());
        });
    }

    /**
     * A transaction inside the wrapper holds the row: its commit leaves it in
     * the wrapper, whose rollback takes it.
     *
     * @return void
     */
    public function testANestedTransactionInsideTheWrapperHoldsTheRow(): void
    {
        $this->insideTheTestingWrapper($this->outboxConnection(), function (Connection $connection): void {
            $connection->beginTransaction();

            $this->write();

            self::assertSame(1, $this->outboxCount());

            $connection->commit();

            self::assertSame(1, $connection->transactionLevel());
            self::assertSame(1, $this->outboxCount());
        });

        self::assertSame(0, $this->outboxCount());
    }

    /**
     * Rolling back a transaction inside the wrapper takes the row, and the
     * wrapper stays open.
     *
     * @return void
     */
    public function testANestedRollbackInsideTheWrapperRemovesTheRow(): void
    {
        $this->insideTheTestingWrapper($this->outboxConnection(), function (Connection $connection): void {
            $connection->beginTransaction();

            $this->write();

            $connection->rollBack();

            self::assertSame(1, $connection->transactionLevel());
            self::assertSame(0, $this->outboxCount());
        });
    }

    /**
     * A spill bound inside the wrapper is written at the nested commit, since
     * that manager runs callbacks at level 1.
     *
     * @return void
     */
    public function testABoundSpillRunsAtTheNestedCommit(): void
    {
        $this->pointOutboxAtProbeTable();

        $this->insideTheTestingWrapper($this->outboxConnection(), function (Connection $connection): void {
            $connection->beginTransaction();

            $this->write();

            self::assertSame([], $this->spillLines());

            $connection->commit();

            self::assertSame(1, $connection->transactionLevel());
            self::assertCount(1, $this->spillLines());
        });
    }

    /**
     * A spill bound inside the wrapper goes with the nested rollback.
     *
     * @return void
     */
    public function testABoundSpillGoesWithTheNestedRollback(): void
    {
        $this->pointOutboxAtProbeTable();

        $this->insideTheTestingWrapper($this->outboxConnection(), function (Connection $connection): void {
            $connection->beginTransaction();

            $this->write();

            $connection->rollBack();

            self::assertSame([], $this->spillLines());
        });
    }

    /**
     * Under Laravel's own manager the row and the spill follow a single
     * transaction's commit and rollback.
     *
     * @return void
     */
    public function testTheSameBehaviourUnderLaravelsOwnManager(): void
    {
        $connection = $this->outboxConnection();

        self::assertSame(LaravelManager::class, get_debug_type($this->app?->make('db.transactions')));

        $connection->beginTransaction();

        $this->write();

        self::assertSame(1, $this->outboxCount());

        $connection->rollBack();

        self::assertSame(0, $this->outboxCount());

        $connection->beginTransaction();

        $this->write();

        $connection->commit();

        self::assertSame(1, $this->outboxCount());

        $this->pointOutboxAtProbeTable();

        $connection->beginTransaction();

        $this->write();

        $beforeTheCommit = $this->spillLines();

        $connection->commit();

        self::assertSame([], $beforeTheCommit);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * Spill to a channel that writes nowhere, and register a second session.
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
        $config->set('database.connections.' . self::READER, $config->array('database.connections.' . self::CONNECTION));
    }

    /**
     * Write a new record through a new writer, and return its id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $transaction
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function write(Timing $timing = Timing::AFTER_COMMIT, ?string $transaction = null, FailureRule $rule = FailureRule::REPORT): string
    {
        $record = RecordFactory::captured();

        (new OutboxWriter(app(), app(Outbox::class)))->write($record, $timing, $transaction, $rule);

        return $record->id;
    }

    /**
     * Assert another session reads that many outbox rows; no other session can
     * see in-memory SQLite.
     *
     * @param  int  $rows
     * @return void
     */
    private function assertAnotherSessionSees(int $rows): void
    {
        if ($this->outboxConnection()->getDriverName() === 'sqlite') {
            return;
        }

        self::assertSame($rows, DB::connection(self::READER)->table(DeliveryTables::outboxTable())->count());
    }
}
