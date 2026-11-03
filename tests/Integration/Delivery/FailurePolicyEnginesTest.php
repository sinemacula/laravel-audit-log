<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Log\LogManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Logger;
use Monolog\LogRecord;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Delivery\CaptureSignal;
use SineMacula\Laravel\AuditLog\Delivery\FailureHandler;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\OutboxWriter;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Delivery\ReplayResult;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\InteractsWithReadWriteSplit;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\DocumentedSpillChannel;
use Tests\TestCase;

/**
 * Integration tests for the failure policy inside real transactions, on the
 * engine the suite runs against, with the writes really refused by the engine
 * and the spill written to the documented channel's real file.
 *
 * A transactional failure rolls the business change back and leaves no spill,
 * only its safe diagnostics. A failed insert in report mode leaves a healthy
 * host committing, because it ran in a savepoint. An after-commit record's
 * spill waits for the commit its row would have joined, so a rollback leaves
 * nothing a replay could bring back. A fail-closed row commits and rolls back
 * with the connection it was written on. On PostgreSQL a host that has already
 * failed refuses even the savepoint: the record is reported and spilled,
 * without a fatal error, unless the spill would wait for a commit that is
 * really a rollback, or the channel is on the aborted database itself, which is
 * what `audit-log:check` flags. Every insert reaches the writer of a read/write
 * split. A captured record follows the `REPORT` rule under either mode, and a
 * refusal of it is reported and signalled, never thrown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailureHandler::class)]
#[CoversClass(OutboxWriter::class)]
#[CoversClass(RecordDelivery::class)]
final class FailurePolicyEnginesTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, InteractsWithReadWriteSplit, SeedsTheOutbox;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string A table the host transaction writes to. */
    private const string HOST_TABLE = 'audit_policy_host_writes';

    /** @var string A table a `database` spill channel writes to. */
    private const string SPILL_TABLE = 'audit_policy_spill_lines';

    /** @var string A second session on the worker's database. */
    private const string READER = 'audit_reader';

    /** @var string A storage connection of the application's own. */
    private const string STORAGE = 'audit_store';

    /** @var string The documented spill channel's name. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var string A spill channel on the storage connection's database. */
    private const string DATABASE_CHANNEL = 'audit-database-spill';

    /** @var string A mode in which a record is written to the store. */
    private const string SYNC = 'sync';

    /** @var string A mode in which a record is written to the outbox. */
    private const string OUTBOX = 'outbox';

    /** @var string The SQLSTATE of a statement run in a transaction PostgreSQL has already aborted. */
    private const string ABORTED = '25P02';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditWriteFailed> Every `AuditWriteFailed` heard. */
    private array $failures = [];

    /** @var list<string> The class each capture's signal was told, in order. */
    private array $signalled = [];

    /** @var string The documented channel's file. */
    private string $file = '';

    /**
     * Create the table the host writes to, bind the reporter, spill to the
     * documented channel in a file of the test's own and hear each
     * `AuditWriteFailed`.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::connection(self::CONNECTION)->dropIfExists(self::HOST_TABLE);

        Schema::connection(self::CONNECTION)->create(self::HOST_TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('name', 32);
        });

        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        $file = tempnam(sys_get_temp_dir(), 'audit-log-spill');

        self::assertIsString($file);

        $this->file = $file;

        app(ConfigRepository::class)->set([
            'logging.channels.' . self::SPILL_CHANNEL => DocumentedSpillChannel::config($this->file),
            'audit-log.failure.log_channel'           => self::SPILL_CHANNEL,
        ]);

        Event::listen(AuditWriteFailed::class, function (AuditWriteFailed $failure): void {
            $this->failures[] = $failure;
        });
    }

    /**
     * Roll back any transaction a failed test left open, then undo what the
     * test added, and remove the files.
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
        $this->removeOutboxProbeTable();
        $this->removeMovedOutbox();
        $this->removeReadWriteSplit();

        Schema::connection(self::CONNECTION)->dropIfExists(self::HOST_TABLE);
        Schema::connection(self::CONNECTION)->dropIfExists(self::SPILL_TABLE);

        if (is_file($this->file)) {
            unlink($this->file);
        }

        parent::tearDown();
    }

    /**
     * A transactional record the engine refuses, left uncaught, rolls the host
     * back, so neither the business change nor the record is kept.
     *
     * @return void
     */
    public function testATransactionalFailureRollsBackTheBusinessChange(): void
    {
        $this->failNextWrite(self::SYNC);

        $thrown = $this->failedWriteFrom(function (): void {
            $this->host()->transaction(function (): void {
                $this->writeTheBusinessChange();

                AuditLog::event(self::CODE)->transactional()->record();
            });
        });

        self::assertSame(QueryException::class, $thrown->exceptionClass);
        self::assertSame(0, $this->host()->transactionLevel());
        self::assertSame(0, $this->hostRows());
        self::assertSame(0, $this->probeCount());
    }

    /**
     * In outbox mode a transactional record's refused insert rolls the host
     * back in the same way.
     *
     * @return void
     */
    public function testATransactionalFailureInOutboxModeRollsBackTheBusinessChange(): void
    {
        $this->failNextWrite(self::OUTBOX);

        $thrown = $this->failedWriteFrom(function (): void {
            $this->host()->transaction(function (): void {
                $this->writeTheBusinessChange();

                AuditLog::event(self::CODE)->transactional()->record();
            });
        });

        self::assertSame(QueryException::class, $thrown->exceptionClass);
        self::assertSame(FailedOperation::OUTBOX->value, $thrown->operation);
        self::assertSame(0, $this->host()->transactionLevel());
        self::assertSame(0, $this->hostRows());
        self::assertSame(0, $this->outboxConnection()->table(self::OUTBOX_PROBE_TABLE)->count());
    }

    /**
     * Rows of `[write mode]`: the two places a record can be written.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideWriteModes(): iterable
    {
        yield from [
            'to the store'  => [self::SYNC],
            'to the outbox' => [self::OUTBOX],
        ];
    }

    /**
     * A transactional failure leaves nothing a replay could turn into evidence,
     * whether the host rolls back or catches the failure and commits.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideWriteModes')]
    public function testATransactionalFailureSpillsNothing(string $mode): void
    {
        $this->failNextWrite($mode);

        $host = $this->host();

        $host->beginTransaction();

        $this->failedWriteFrom(static fn (): AuditRecord => AuditLog::event(self::CODE)->transactional()->record());

        self::assertSame('', $this->spilled());

        $host->rollBack();

        self::assertSame('', $this->spilled());

        $host->beginTransaction();

        $this->failedWriteFrom(static fn (): AuditRecord => AuditLog::event(self::CODE)->transactional()->record());

        $host->commit();

        self::assertSame('', $this->spilled());
        self::assertSame(0, $this->replay()->replayed());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A transactional failure still says what failed, in the event and the
     * thrown exception, each holding only what is safe, and the package does
     * not also report what it throws.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideWriteModes')]
    public function testATransactionalFailureEmitsSafeDiagnostics(string $mode): void
    {
        $this->failNextWrite($mode);

        $this->host()->beginTransaction();

        $thrown = $this->failedWriteFrom(static fn (): AuditRecord => AuditLog::event(self::CODE)->transactional()->record());

        $store = $mode === self::SYNC ? DatabaseAuditStore::class : Outbox::class;

        self::assertSame(self::CODE, $thrown->eventCode);
        self::assertSame($store, $thrown->store);
        self::assertSame($mode === self::SYNC ? FailedOperation::STORE->value : FailedOperation::OUTBOX->value, $thrown->operation);
        self::assertSame(QueryException::class, $thrown->exceptionClass);
        self::assertSame(self::CONNECTION, $thrown->connection);
        self::assertNotNull($thrown->sqlState);
        self::assertNull($thrown->getPrevious());
        self::assertStringNotContainsString('insert into', $thrown->getMessage());

        self::assertCount(1, $this->failures);
        self::assertSame($thrown->recordId, $this->failures[0]->id);
        self::assertSame(self::CODE, $this->failures[0]->code);
        self::assertSame($store, $this->failures[0]->store);
        self::assertSame(QueryException::class, $this->failures[0]->exception);

        self::assertSame([], $this->reporter->reports());
    }

    /**
     * In report mode a refused insert costs only its savepoint: the record is
     * spilled, reported and said, the host writes again and commits, and on
     * PostgreSQL its transaction is not left aborted.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideWriteModes')]
    public function testAFailedSavepointInsertLeavesTheHostCommittingInReportMode(string $mode): void
    {
        $this->failNextWrite($mode);

        $this->host()->transaction(function (): void {
            $this->writeTheBusinessChange('before');

            AuditLog::event(self::CODE)->immediately()->record();

            self::assertSame(1, $this->host()->transactionLevel());

            $this->writeTheBusinessChange('after');
        });

        $this->assertAnotherSessionSeesTheBusinessChanges(2);

        self::assertSame(2, $this->hostRows());
        self::assertSame(1, self::lineCount($this->spilled()));
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->failures);
    }

    /**
     * Rows of `[failure mode, write mode]`: a captured record under each mode
     * it never reads, written to the store and to the outbox.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideCapturedModes(): iterable
    {
        yield from [
            'captured in report mode to the store'  => ['report', self::SYNC],
            'captured in throw mode to the store'   => ['throw', self::SYNC],
            'captured in report mode to the outbox' => ['report', self::OUTBOX],
            'captured in throw mode to the outbox'  => ['throw', self::OUTBOX],
        ];
    }

    /**
     * A captured record the engine refuses inside a host follows the `REPORT`
     * rule whatever the mode: never thrown, it costs only its savepoint, so the
     * host writes again and commits, and the record is spilled, reported, said
     * and signalled once each.
     *
     * @param  string  $failureMode
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideCapturedModes')]
    public function testACapturedFailureIsReportedAndNeverThrown(string $failureMode, string $mode): void
    {
        $signal = $this->signal();

        app(ConfigRepository::class)->set('audit-log.failure.mode', $failureMode);

        $this->failNextWrite($mode);

        $this->host()->transaction(function () use ($signal): void {
            $this->writeTheBusinessChange('before');

            app(RecordDelivery::class)->deliver(RecordFactory::captured(), Timing::IMMEDIATE, null, false, $signal);

            $this->writeTheBusinessChange('after');
        });

        $this->assertAnotherSessionSeesTheBusinessChanges(2);

        self::assertSame(2, $this->hostRows());
        self::assertSame(1, self::lineCount($this->spilled()));
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->failures);
        self::assertSame([QueryException::class], $this->signalled);
        self::assertFalse($signal->isFatal());
    }

    /**
     * A captured record written after the host commits, refused by the engine,
     * follows the `REPORT` rule whatever the mode: the commit stands, and the
     * record is spilled, reported and signalled once, with nothing thrown from
     * the commit.
     *
     * @param  string  $failureMode
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideCapturedModes')]
    public function testACapturedFailureAfterCommitIsReportedAndNeverThrown(string $failureMode, string $mode): void
    {
        $signal = $this->signal();

        app(ConfigRepository::class)->set('audit-log.failure.mode', $failureMode);

        $this->failNextWrite($mode);

        $this->host()->transaction(function () use ($signal): void {
            $this->writeTheBusinessChange();

            app(RecordDelivery::class)->deliver(RecordFactory::captured(), Timing::AFTER_COMMIT, null, false, $signal);
        });

        $this->assertAnotherSessionSeesTheBusinessChanges(1);

        self::assertSame(1, $this->hostRows());
        self::assertSame(1, self::lineCount($this->spilled()));
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->failures);
        self::assertSame([QueryException::class], $this->signalled);
        self::assertFalse($signal->isFatal());
    }

    /**
     * An after-commit record whose outbox insert fails says so at once, the
     * host rolls back, and the file holds no line, so a replay of it adds
     * nothing. A record of work that was undone never comes back as evidence
     * that it was done.
     *
     * @return void
     */
    public function testRollbackAfterAFailedInsertLeavesNoReplayableSpill(): void
    {
        $this->failNextWrite(self::OUTBOX);

        $host = $this->host();

        $host->beginTransaction();

        $this->writeTheBusinessChange();

        AuditLog::event(self::CODE)->record();

        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->failures);
        self::assertSame('', $this->spilled());

        $host->rollBack();

        self::assertSame(0, $this->hostRows());
        self::assertSame('', $this->spilled());

        $result = $this->replay();

        self::assertSame(0, $result->replayed());
        self::assertSame([], $result->events());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * The rollback of the transaction that selected the record takes its spill,
     * and the outer transaction commits without it; an inner commit does not
     * release the spill, whose fate waits for the outer.
     *
     * @return void
     */
    public function testANestedRollbackAfterAFailedInsertLeavesNoReplayableSpill(): void
    {
        $this->failNextWrite(self::OUTBOX);

        $host = $this->host();

        $host->beginTransaction();
        $host->beginTransaction();

        AuditLog::event(self::CODE)->record();

        $host->rollBack();
        $host->commit();

        self::assertSame('', $this->spilled());

        $host->beginTransaction();
        $host->beginTransaction();

        AuditLog::event(self::CODE)->record();

        $host->commit();

        self::assertSame('', $this->spilled());

        $host->rollBack();

        self::assertSame('', $this->spilled());
    }

    /**
     * When the host commits, the same failure's spill is written as one line,
     * at the commit, and a replay gives one row that verifies; a second replay
     * adds nothing.
     *
     * @return void
     */
    public function testCommitAfterAFailedInsertLeavesOneReplayableSpill(): void
    {
        $this->failNextWrite(self::OUTBOX);

        $host = $this->host();

        $host->beginTransaction();

        $this->writeTheBusinessChange();

        $record = AuditLog::event(self::CODE)->record();

        self::assertSame('', $this->spilled());

        $host->commit();

        self::assertSame(1, $this->hostRows());
        self::assertSame(1, self::lineCount($this->spilled()));

        self::assertSame(1, $this->replay()->replayed());
        self::assertSame(1, $this->entryCount());
        self::assertTrue(app(RecordSigner::class)->verifies($this->storedRow($record->id)));

        self::assertSame(1, $this->replay()->replayed());
        self::assertSame(1, $this->entryCount());
    }

    /**
     * A failed-closed write in either mode is refused to the caller and spilled
     * at once, and a host that catches it stays healthy enough to commit.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideWriteModes')]
    public function testAFailClosedFailureSpillsAndLeavesACatchingHostCommitting(string $mode): void
    {
        $this->failNextWrite($mode);

        $host = $this->host();

        $host->beginTransaction();

        $this->writeTheBusinessChange();

        $this->failedWriteFrom(static fn (): AuditRecord => AuditLog::event(self::CODE)->failClosed()->record());

        self::assertSame(1, self::lineCount($this->spilled()));
        self::assertSame([], $this->reporter->reports());
        self::assertCount(1, $this->failures);

        $host->commit();

        self::assertSame(1, $this->hostRows());
    }

    /**
     * On a storage connection of its own a fail-closed entry has committed by
     * the time the call returns, so the rollback of a host elsewhere leaves it.
     *
     * @return void
     */
    #[DefineEnvironment('useDedicatedStorage')]
    public function testFailClosedSurvivesItsDedicatedConnection(): void
    {
        $host = $this->host();

        $host->beginTransaction();

        $this->writeTheBusinessChange();

        $record = AuditLog::event(self::CODE)->failClosed()->record();

        $host->rollBack();

        self::assertSame(0, $this->hostRows());
        self::assertSame(1, $this->entryCount());
        self::assertSame($record->id, $this->storedRow($record->id)['id']);
    }

    /**
     * On an outbox connection of its own a fail-closed row has committed by the
     * time the call returns, so the rollback of a host elsewhere leaves it.
     *
     * @return void
     */
    public function testFailClosedSurvivesADedicatedOutboxConnection(): void
    {
        $this->outboxModeOn();
        $this->moveOutboxToItsOwnConnection();

        $host = $this->host();

        $host->beginTransaction();

        $this->writeTheBusinessChange();

        $record = AuditLog::event(self::CODE)->failClosed()->record();

        $host->rollBack();

        self::assertSame(0, $this->hostRows());
        self::assertNotNull($this->outboxRow($record->id));
    }

    /**
     * On a shared connection a fail-closed write has joined the enclosing
     * transaction, so its rollback removes the row with the business change.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideWriteModes')]
    public function testRollingBackAnEnclosingTransactionRemovesAFailClosedRow(string $mode): void
    {
        if ($mode === self::OUTBOX) {
            $this->outboxModeOn();
        }

        $host = $this->host();

        $host->beginTransaction();

        $this->writeTheBusinessChange();

        AuditLog::event(self::CODE)->failClosed()->record();

        self::assertSame(1, $mode === self::SYNC ? $this->entryCount() : $this->outboxCount());

        $host->rollBack();

        self::assertSame(0, $this->hostRows());
        self::assertSame(0, $this->entryCount());
        self::assertSame(0, $this->outboxCount());
        self::assertSame('', $this->spilled());
    }

    /**
     * A host PostgreSQL has already aborted refuses the savepoint itself. The
     * record is reported with the state that says so, said and spilled at once,
     * and the line is the evidence of an attempt a replay can keep.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideWriteModes')]
    public function testAnAbortedPostgresHostIsReportedAndSpilled(string $mode): void
    {
        $this->skipUnlessPostgres();

        if ($mode === self::OUTBOX) {
            $this->outboxModeOn();
        }

        $this->abortTheHost();

        $record = AuditLog::event(self::CODE)->immediately()->record();

        $reports = $this->reporter->reports();

        self::assertCount(1, $reports);
        self::assertInstanceOf(AuditWriteFailedException::class, $reports[0]);
        self::assertSame(self::ABORTED, $reports[0]->sqlState);
        self::assertSame($record->id, $reports[0]->recordId);
        self::assertCount(1, $this->failures);
        self::assertSame(1, self::lineCount($this->spilled()));

        $this->host()->rollBack();

        self::assertSame(1, $this->replay()->replayed());
        self::assertSame($record->id, $this->storedRow($record->id)['id']);
    }

    /**
     * In report mode an aborted host is not made worse: the call returns, the
     * transaction is left as the host left it, still aborted and still open,
     * and the host's rollback leaves the connection working.
     *
     * @param  string  $mode
     * @return void
     */
    #[DataProvider('provideWriteModes')]
    public function testAnAbortedPostgresHostDoesNotThrowInReportMode(string $mode): void
    {
        $this->skipUnlessPostgres();

        if ($mode === self::OUTBOX) {
            $this->outboxModeOn();
        }

        $host = $this->host();

        $this->abortTheHost();

        $record = AuditLog::event(self::CODE)->immediately()->record();

        self::assertNotSame('', $record->id);
        self::assertSame(1, $host->transactionLevel());

        $this->assertThrows(fn () => $this->writeTheBusinessChange(), QueryException::class);

        $host->rollBack();

        $this->writeTheBusinessChange();

        self::assertSame(1, $this->hostRows());
    }

    /**
     * Rows of `[failure mode, whether the record is fail-closed]`: a record
     * whose rule throws and spills.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideThrowingRules(): iterable
    {
        yield from [
            'throw mode'  => ['throw', false],
            'fail closed' => ['report', true],
        ];
    }

    /**
     * Under a rule that throws, an aborted host gets the sanitised exception:
     * no previous exception, no statement, and the state that says what
     * happened. The record is spilled, said, and not also reported.
     *
     * @param  string  $mode
     * @param  bool  $failClosed
     * @return void
     */
    #[DataProvider('provideThrowingRules')]
    public function testAnAbortedPostgresHostThrowsSanitisedInThrowMode(string $mode, bool $failClosed): void
    {
        $this->skipUnlessPostgres();

        app(ConfigRepository::class)->set('audit-log.failure.mode', $mode);

        $this->abortTheHost();

        $thrown = $this->failedWriteFrom(static function () use ($failClosed): void {
            $record = AuditLog::event(self::CODE)->immediately();

            ($failClosed ? $record->failClosed() : $record)->record();
        });

        self::assertSame(self::ABORTED, $thrown->sqlState);
        self::assertNull($thrown->getPrevious());
        self::assertStringNotContainsString('SAVEPOINT', strtoupper($thrown->getMessage()));
        self::assertSame(1, self::lineCount($this->spilled()));
        self::assertSame([], $this->reporter->reports());
        self::assertCount(1, $this->failures);
    }

    /**
     * A transactional record in an aborted host throws too and is never
     * spilled, like any other transactional failure.
     *
     * @return void
     */
    public function testAnAbortedPostgresHostSpillsNoTransactionalRecord(): void
    {
        $this->skipUnlessPostgres();

        $this->abortTheHost();

        $thrown = $this->failedWriteFrom(static fn (): AuditRecord => AuditLog::event(self::CODE)->transactional()->record());

        self::assertSame(self::ABORTED, $thrown->sqlState);
        self::assertSame('', $this->spilled());
        self::assertCount(1, $this->failures);
    }

    /**
     * An after-commit record in outbox mode would bind its spill to the
     * selected transaction, but an aborted one never commits, whatever
     * PostgreSQL then says. The spill is discarded, and the record is reported
     * and said.
     *
     * @return void
     */
    public function testAnAbortedHostDiscardsTheOutboxSpill(): void
    {
        $this->skipUnlessPostgres();

        $this->outboxModeOn();
        $this->abortTheHost();

        AuditLog::event(self::CODE)->record();

        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->failures);
        self::assertSame('', $this->spilled());

        $this->host()->rollBack();

        self::assertSame('', $this->spilled());
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * PostgreSQL ends the `COMMIT` of an aborted transaction with a rollback
     * and reports a success, so Laravel runs its commit callbacks, as the
     * host's own shows. The work before the failure is gone, and a spill bound
     * to that commit would have been a record of it, so none was bound.
     *
     * @return void
     */
    public function testACommitOfAnAbortedHostSpillsNothing(): void
    {
        $this->skipUnlessPostgres();

        $this->outboxModeOn();

        $host = $this->host();
        $ran  = false;

        $host->beginTransaction();

        $this->writeTheBusinessChange();

        $this->abortTheOpenHost();

        AuditLog::event(self::CODE)->record();

        $host->afterCommit(static function () use (&$ran): void {
            $ran = true;
        });

        $host->commit();

        self::assertTrue($ran);
        self::assertSame(0, $host->transactionLevel());
        self::assertSame(0, $this->hostRows());
        self::assertSame(0, $this->outboxCount());
        self::assertSame('', $this->spilled());
    }

    /**
     * A spill channel on the database of an aborted host fails with the store,
     * so nothing durable is left: the failed spill is reported apart, and a
     * line written once the host has gone shows the channel itself works. That
     * is the condition `audit-log:check` flags, by name, with a failing exit
     * code.
     *
     * @return void
     */
    public function testASpillOnTheAbortedDatabaseIsWhatCheckFlags(): void
    {
        $this->skipUnlessPostgres();

        $this->spillToTheHostsDatabase();

        $this->abortTheHost();

        AuditLog::event(self::CODE)->immediately()->record();

        $reports = $this->reporter->reports();

        self::assertCount(2, $reports);
        self::assertInstanceOf(AuditWriteFailedException::class, $reports[0]);
        self::assertInstanceOf(AuditWriteFailedException::class, $reports[1]);
        self::assertSame(FailedOperation::SPILL->value, $reports[0]->operation);
        self::assertSame(FailedOperation::STORE->value, $reports[1]->operation);
        self::assertCount(1, $this->failures);

        $this->host()->rollBack();

        self::assertSame(0, DB::table(self::SPILL_TABLE)->count());

        app(LogManager::class)->channel(self::DATABASE_CHANNEL)->critical('the channel works');

        self::assertSame(1, DB::table(self::SPILL_TABLE)->count());

        $kernel = $this->app?->make(Kernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);
        self::assertNotSame(0, $kernel->call('audit-log:check'));

        $message = '[delivery] The spill channel [%s] writes to the storage connection [%s], so it would fail together with the store.';

        self::assertStringContainsString(sprintf($message, self::DATABASE_CHANNEL, self::CONNECTION), $kernel->output());
    }

    /**
     * On a read/write split whose replica lags, each write of the path lands on
     * the primary and none on the replica: the entry of a sync write, the
     * outbox row of an outbox write, and the entry and the receipt of its
     * drain, which also reads the row it finds there.
     *
     * @return void
     */
    public function testTheInsertReachesTheWriter(): void
    {
        $this->useReadWriteSplit();
        $this->migrateDeliveryTablesOn([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION]);

        $primary = DB::connection(self::PRIMARY_CONNECTION);
        $replica = DB::connection(self::REPLICA_CONNECTION);
        $entries = EntrySettings::table();
        $outbox  = DeliveryTables::outboxTable();

        AuditLog::event(self::CODE)->immediately()->record();

        self::assertSame(1, $primary->table($entries)->count());
        self::assertSame(0, $replica->table($entries)->count());

        $this->outboxModeOn();

        AuditLog::event(self::CODE)->immediately()->record();

        self::assertSame(1, $primary->table($outbox)->count());
        self::assertSame(0, $replica->table($outbox)->count());

        self::assertSame(1, app(OutboxDrainer::class)->drain(100, false)->delivered());

        self::assertSame(0, $primary->table($outbox)->count());
        self::assertSame(2, $primary->table($entries)->count());
        self::assertSame(0, $replica->table($entries)->count());
        self::assertSame(1, $primary->table(DeliveryTables::deliveriesTable())->count());
        self::assertSame(0, $replica->table(DeliveryTables::deliveriesTable())->count());
    }

    /**
     * Register a second session and a storage connection of the application's
     * own, on the same database under a table prefix of its own.
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

        $config  = $app->make(ConfigRepository::class);
        $testing = $config->array('database.connections.' . self::CONNECTION);

        $config->set('database.connections.' . self::READER, $testing);
        $config->set('database.connections.' . self::STORAGE, [...$testing, 'prefix' => 'store_']);
    }

    /**
     * Make the storage connection the application's own.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function useDedicatedStorage(Application $app): void
    {
        $app->make(ConfigRepository::class)->set('audit-log.storage.connection', self::STORAGE);
    }

    /**
     * Make the next write in the mode a real refusal by the engine. Done before
     * any transaction: MySQL commits an open one on any DDL.
     *
     * @param  string  $mode
     * @return void
     */
    private function failNextWrite(string $mode): void
    {
        if ($mode === self::SYNC) {
            $this->pointAtProbeTable();

            return;
        }

        $this->outboxModeOn();
        $this->pointOutboxAtProbeTable();
    }

    /**
     * Open a host transaction and abort it with a failed statement.
     *
     * @return void
     */
    private function abortTheHost(): void
    {
        $this->host()->beginTransaction();

        $this->abortTheOpenHost();
    }

    /**
     * Abort the open host transaction with a failed statement.
     *
     * @return void
     */
    private function abortTheOpenHost(): void
    {
        $this->assertThrows(fn () => $this->host()->statement('select * from audit_no_such_table'), QueryException::class);
    }

    /**
     * Make the spill channel one with the `database` driver, writing to a table
     * on the host's connection, which is the storage connection, as a custom
     * log driver would.
     *
     * @return void
     */
    private function spillToTheHostsDatabase(): void
    {
        Schema::connection(self::CONNECTION)->create(self::SPILL_TABLE, static function (Blueprint $table): void {
            $table->longText('line');
        });

        $logger = self::loggerOn($this->host());

        // The log manager binds the creator to itself, so it cannot be static
        app(LogManager::class)->extend('database', fn (): Logger => $logger);

        app(ConfigRepository::class)->set([
            'logging.channels.' . self::DATABASE_CHANNEL => ['driver' => 'database', 'connection' => self::CONNECTION],
            'audit-log.failure.log_channel'              => self::DATABASE_CHANNEL,
        ]);
    }

    /**
     * A logger whose one handler inserts each message in the spill table on the
     * connection.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return \Monolog\Logger
     */
    private static function loggerOn(Connection $connection): Logger
    {
        return new Logger('database', [new class ($connection, self::SPILL_TABLE) extends AbstractProcessingHandler {
            /**
             * Constructor.
             *
             * @param  \Illuminate\Database\Connection  $connection
             * @param  string  $table
             */
            public function __construct(

                /** The connection the table is on. */
                private readonly Connection $connection,

                /** The table each message is inserted in. */
                private readonly string $table,
            ) {
                parent::__construct();
            }

            /**
             * Insert the message.
             *
             * @param  \Monolog\LogRecord  $record
             * @return void
             */
            #[\Override]
            protected function write(LogRecord $record): void
            {
                $this->connection->table($this->table)->insert(['line' => $record->message]);
            }
        }]);
    }

    /**
     * Skip unless the suite runs on PostgreSQL, the only engine that leaves a
     * transaction aborted by a failed statement.
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

    /**
     * Assert another session reads that many committed business changes, which
     * on an in-memory SQLite database no other session can.
     *
     * @param  int  $rows
     * @return void
     */
    private function assertAnotherSessionSeesTheBusinessChanges(int $rows): void
    {
        if ($this->host()->getDriverName() === 'sqlite') {
            return;
        }

        self::assertSame($rows, DB::connection(self::READER)->table(self::HOST_TABLE)->count());
    }

    /**
     * Write a business change.
     *
     * @param  string  $name
     * @return void
     */
    private function writeTheBusinessChange(string $name = 'work'): void
    {
        $this->host()->table(self::HOST_TABLE)->insert(['name' => $name]);
    }

    /**
     * The number of business changes the host's connection reads.
     *
     * @return int
     */
    private function hostRows(): int
    {
        return $this->host()->table(self::HOST_TABLE)->count();
    }

    /**
     * The connection the host transacts on, which is the storage connection and
     * the outbox connection unless a test moved them.
     *
     * @return \Illuminate\Database\Connection
     */
    private function host(): Connection
    {
        return DB::connection(self::CONNECTION);
    }

    /**
     * The sanitised exception the work throws.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(): mixed  $work
     * @return \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function failedWriteFrom(\Closure $work): AuditWriteFailedException
    {
        try {
            $work();
        } catch (AuditWriteFailedException $thrown) {
            return $thrown;
        }

        self::fail('Expected the failed write to be thrown.');
    }

    /**
     * A capture's signal that keeps the class it is told.
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
     * Replay the documented channel's file.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\ReplayResult
     */
    private function replay(): ReplayResult
    {
        return app(Replayer::class)->spill($this->file, false);
    }

    /**
     * What the documented channel's file holds.
     *
     * @return string
     */
    private function spilled(): string
    {
        $contents = file_get_contents($this->file);

        self::assertIsString($contents);

        return $contents;
    }

    /**
     * The number of lines the contents hold.
     *
     * @param  string  $contents
     * @return int
     */
    private static function lineCount(string $contents): int
    {
        return substr_count($contents, "\n");
    }
}
