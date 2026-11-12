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
 * Integration tests for the failure policy inside real transactions, with
 * writes refused by the engine and spills written to the documented channel's
 * real file.
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

    /** @var string The SQLSTATE of a statement in a transaction PostgreSQL has aborted. */
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
     * Create the host's table, bind the reporter, spill to the documented
     * channel in the test's own file, and hear each `AuditWriteFailed`.
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
     * Roll back any open transaction, undo the test's additions, and remove the
     * files.
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
     * A refused transactional record rolls the host back, keeping neither the
     * business change nor the record.
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
     * In outbox mode a refused transactional insert rolls the host back too.
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
     * A transactional failure spills nothing, whether the host rolls back or
     * commits.
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
     * A transactional failure emits only safe diagnostics and is not also
     * reported.
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
     * In report mode a refused insert costs only its savepoint, and the host
     * commits.
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
     * Rows of `[failure mode, write mode]` for a captured record.
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
     * A refused captured record inside a host is reported and never thrown,
     * whatever the mode.
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
     * A captured record refused after the host commits is reported and never
     * thrown, whatever the mode.
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
     * A host rollback after a failed after-commit outbox insert leaves no
     * replayable spill.
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
     * Rolling back the transaction that selected the record takes its spill,
     * though the outer one commits.
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
     * A host commit after a failed insert writes one spill line, which replays
     * once.
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
     * A fail-closed failure is thrown and spilled at once, and a catching host
     * can still commit.
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
     * A fail-closed entry on a dedicated storage connection survives a host
     * rollback elsewhere.
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
     * A fail-closed row on a dedicated outbox connection survives a host
     * rollback elsewhere.
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
     * On a shared connection a fail-closed row rolls back with the enclosing
     * transaction.
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
     * A host PostgreSQL has already aborted refuses the savepoint, and the
     * record is reported and spilled.
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
     * In report mode an aborted host is left aborted and open, and its rollback
     * leaves the connection working.
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
     * Rows of `[failure mode, fail closed]` for rules that throw and spill.
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
     * Under a throwing rule an aborted host gets the sanitised exception, and
     * the record is spilled but not reported.
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
     * A transactional record in an aborted host throws and is never spilled.
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
     * An aborted host discards an after-commit outbox spill, since its commit
     * is really a rollback.
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
     * PostgreSQL reports a successful `COMMIT` of an aborted transaction, so a
     * spill bound to it would record undone work; none is bound.
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
     * A spill channel on an aborted host's database fails with it, which
     * `audit-log:check` flags.
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
     * With a lagging replica, every write of the path lands on the primary.
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
     * own, on the same database with its own table prefix.
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
     * Make the next write in the mode a real refusal; done before any
     * transaction because MySQL commits an open one on DDL.
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
     * Spill through a `database` channel writing to a table on the host's
     * connection, as a custom log driver would.
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
     * A logger whose one handler inserts each message into the spill table.
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
     * Skip unless on PostgreSQL, the only engine that leaves a transaction
     * aborted.
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
     * Assert another session reads that many committed business changes; no
     * other session can see in-memory SQLite.
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
     * The host's connection, which is also the storage and outbox connection
     * unless a test moved them.
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
