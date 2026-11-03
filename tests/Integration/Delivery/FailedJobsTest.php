<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Queue\Events\JobQueued;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Schema;
use Monolog\Handler\NullHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\DrainCommand;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Delivery\DeliveryCoordinator;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Delivery\FailureHandler;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\Receipts;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SearchesForSecrets;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Jobs\RecordingJob;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * What a failed delivery leaves in the queue's tables, through a database queue
 * and the real `queue:work` command, which is what writes `failed_jobs`, on the
 * engine the suite runs against: a drain dispatches no job, so a destination
 * that keeps failing leaves a receipt and a failed row, and nothing a job could
 * fail with; run from a job, it completes the job. A record that throws inside
 * a job does fail it, and Laravel stores that exception's text and trace, which
 * hold only the sanitised exception's fixed text, however the store failed.
 *
 * The whole class turns `zend.exception_ignore_args` off, so a stored trace
 * writes every frame's arguments.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OutboxDrainer::class)]
#[CoversClass(DeliveryCoordinator::class)]
#[CoversClass(Receipts::class)]
#[CoversClass(DrainCommand::class)]
#[CoversClass(FailureHandler::class)]
final class FailedJobsTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, SearchesForSecrets, SeedsTheOutbox;

    /** @var string The code every test records, unless a job records its own. */
    private const string CODE = 'invoice.approved';

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var string Later than any wait before a retry. */
    private const string LATER = '2026-11-01T14:00:00.000000Z';

    /** @var string The queue's own table. */
    private const string JOBS = 'jobs';

    /** @var string The table Laravel keeps a failed job in. */
    private const string FAILED_JOBS = 'failed_jobs';

    /** @var string The spill channel, which writes nowhere. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var string The setting that turns a frame's arguments off. */
    private const string IGNORE_ARGS = 'zend.exception_ignore_args';

    /** @var string What the store's failure says, besides the secret. */
    private const string FAILURE = 'SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter, the worker's among them, is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditWriteFailed> The failed writes said, in order. */
    private array $events = [];

    /** @var string The setting as it was before the test. */
    private string $ignoreArgs = '';

    /**
     * Create the queue's tables, keep every frame's arguments, stop the clock,
     * and keep what is reported and said.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->ignoreArgs = (string) ini_get(self::IGNORE_ARGS);

        ini_set(self::IGNORE_ARGS, '0');

        $this->moveClockTo(self::NOW);
        $this->createTheQueuesTables();

        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        Event::listen(AuditWriteFailed::class, function (AuditWriteFailed $event): void {
            $this->events[] = $event;
        });
    }

    /**
     * Drop the queue's tables, and put the setting and the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(self::JOBS);
        Schema::dropIfExists(self::FAILED_JOBS);

        CarbonImmutable::setTestNow();

        ini_set(self::IGNORE_ARGS, $this->ignoreArgs);

        parent::tearDown();
    }

    /**
     * Rows of `[connections the destination joins]`: one called on its own, and
     * one that shares a transaction with its receipt, which that failure rolls
     * back, so the receipt must be written after it.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideDestinations(): iterable
    {
        yield from [
            'called on its own'       => [[]],
            'sharing its transaction' => [[self::CONNECTION]],
        ];
    }

    /**
     * A destination that fails every attempt leaves a receipt that counts them
     * and names the failure's class, is never marked delivered, and has its row
     * failed and kept, its payload whole, for a replay; only the last attempt
     * is reported and said.
     *
     * @param  list<string>  $joins
     * @return void
     */
    #[DataProvider('provideDestinations')]
    public function testAPermanentlyFailingDestinationLeavesAReceipt(array $joins): void
    {
        $this->outboxModeOn();

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 2);

        $id      = AuditLog::event(self::CODE)->record()->id;
        $payload = $this->existingRow($id)['payload'];

        app()->instance(AuditStore::class, self::failingStore($joins));

        Artisan::call('audit-log:drain');

        $receipt = $this->existingReceipt($id, DeliveryCoordinator::STORE_DESTINATION);

        self::assertSame(1, $receipt['attempts']);
        self::assertSame(QueryException::class, $receipt['last_error_class']);
        self::assertNull($this->existingRow($id)['failed_at']);
        self::assertSame([], $this->reporter->reports());
        self::assertSame([], $this->events);

        $this->moveClockTo(self::LATER);

        Artisan::call('audit-log:drain');

        $receipt = $this->existingReceipt($id, DeliveryCoordinator::STORE_DESTINATION);
        $row     = $this->existingRow($id);

        self::assertSame(2, $receipt['attempts']);
        self::assertSame(QueryException::class, $receipt['last_error_class']);
        self::assertNull($receipt['delivered_at']);
        self::assertSame(self::LATER, $row['failed_at']);
        self::assertSame(QueryException::class, $row['last_error_class']);
        self::assertSame($payload, $row['payload']);
        self::assertCount(1, $this->reporter->reports());
        self::assertCount(1, $this->events);
    }

    /**
     * A destination that keeps failing leaves the receipt of one that succeeded
     * as it was, and a further drain calls only the one that failed.
     *
     * @return void
     */
    public function testAPermanentlyFailingDestinationLeavesTheOthersReceipt(): void
    {
        $this->outboxModeOn();

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 2);

        $id    = AuditLog::event(self::CODE)->record()->id;
        $calls = 0;

        $working = new CallbackStore(static function () use (&$calls): void {
            $calls++;
        });

        app()->instance(AuditStore::class, new StackAuditStore(['working' => $working, 'failing' => self::failingStore()]));

        Artisan::call('audit-log:drain');

        $this->moveClockTo(self::LATER);

        Artisan::call('audit-log:drain');

        self::assertSame(1, $calls);
        self::assertSame(self::NOW, $this->existingReceipt($id, 'working')['delivered_at']);
        self::assertNull($this->existingReceipt($id, 'failing')['delivered_at']);
        self::assertSame(2, $this->existingReceipt($id, 'failing')['attempts']);
        self::assertSame(self::LATER, $this->existingRow($id)['failed_at']);
    }

    /**
     * With a secret in the record's context and in what the destination fails
     * with, a drain leaves `failed_jobs` empty, whether a job or the scheduler
     * ran it, because it is no job's to fail: run from a job, the job
     * completes, though the row is failed and reported.
     *
     * @return void
     */
    public function testNoPayloadIsInFailedJobs(): void
    {
        $this->outboxModeOn();

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 1);

        $pending = AuditLog::event(self::CODE);

        $pending->fillContext(['detail' => self::SECRET]);

        $id = $pending->record()->id;

        app()->instance(AuditStore::class, self::failingStore());

        Artisan::queue('audit-log:drain');

        self::assertSame(1, DB::table(self::JOBS)->count());

        $this->runTheWorker();

        self::assertSame(0, DB::table(self::JOBS)->count());
        self::assertSame(0, DB::table(self::FAILED_JOBS)->count());
        self::assertNotNull($this->existingRow($id)['failed_at']);
        self::assertCount(1, $this->reporter->reports());
        self::assertHoldsNoSecret($this->reporter->reports(), 'a report');
        self::assertHoldsNoSecret($this->events, 'an event');
    }

    /**
     * Rows of `[command, options]`: each command that delivers.
     *
     * @return iterable<string, array{0: string, 1: array<string, bool>}>
     */
    public static function provideDeliveries(): iterable
    {
        yield from [
            'a drain'                => ['audit-log:drain', []],
            'a drain until empty'    => ['audit-log:drain', ['--until-empty' => true]],
            'a replay of the outbox' => ['audit-log:replay', ['--outbox' => true]],
        ];
    }

    /**
     * Delivering pushes nothing onto a queue, whether the row delivers or
     * fails: the real queue's table stays empty, and no job is said to be
     * queued.
     *
     * @param  string  $command
     * @param  array<string, bool>  $options
     * @return void
     */
    #[DataProvider('provideDeliveries')]
    public function testADrainDispatchesNoJob(string $command, array $options): void
    {
        $this->outboxModeOn();

        $queued = 0;

        Event::listen(JobQueued::class, static function () use (&$queued): void {
            $queued++;
        });

        AuditLog::event(self::CODE)->record();

        app()->instance(AuditStore::class, self::failingStore());

        Artisan::call($command, $options);

        app()->instance(AuditStore::class, CallbackStore::saying(true));

        $this->moveClockTo(self::LATER);

        Artisan::call($command, $options);

        self::assertSame(0, $this->outboxCount());
        self::assertSame(0, $queued);
        self::assertSame(0, DB::table(self::JOBS)->count());
        self::assertSame(0, DB::table(self::FAILED_JOBS)->count());
    }

    /**
     * Neither the queue's nor the bus's fake sees a drain push anything.
     *
     * @return void
     */
    public function testADrainPushesNothingAFakeCanSee(): void
    {
        $this->outboxModeOn();

        AuditLog::event(self::CODE)->record();

        app()->instance(AuditStore::class, self::failingStore());

        Queue::fake();
        Bus::fake();

        self::assertSame(0, Artisan::call('audit-log:drain'));

        $row = DB::table(DeliveryTables::outboxTable())->sole();

        self::assertSame(1, (int) $row->attempts);
        self::assertSame(QueryException::class, $row->last_error_class);

        Queue::assertNothingPushed();
        Bus::assertNothingDispatched();
    }

    /**
     * Rows of `[delivery mode]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode}>
     */
    public static function provideModes(): iterable
    {
        foreach (DeliveryMode::cases() as $mode) {
            yield $mode->value => [$mode];
        }
    }

    /**
     * A queued job whose record throws, under the `throw` mode, is failed by
     * the worker, and `failed_jobs` then holds what Laravel stores of an
     * exception: only the sanitised exception's fixed text, one exception with
     * no `Next`, and a trace whose frames that took the record show the
     * stand-in.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testAThrownFailureInsideAJobLeavesNoSecretInFailedJobs(DeliveryMode $mode): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.delivery.mode', $mode->value);
        $config->set('audit-log.failure.mode', 'throw');

        $this->breakTheWrite($mode);

        Bus::dispatch(new RecordingJob);

        $this->runTheWorker();

        self::assertSame(0, DB::table(self::JOBS)->count());

        $row = DB::table(self::FAILED_JOBS)->first();

        self::assertNotNull($row, 'The job must have failed.');

        $exception = $row->exception;

        self::assertIsString($exception);

        $this->assertHoldsOnlyTheFixedText($exception, $mode);

        self::assertHoldsNoSecret((array) $row, 'the failed job');
        self::assertHoldsNoSecret($this->reporter->reports(), 'what the worker reported');
    }

    /**
     * A job whose record only reports its failed write completes: nothing is
     * failed, and nothing of the record is on the queue.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testAReportedFailureInsideAJobLeavesNothingInFailedJobs(DeliveryMode $mode): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', $mode->value);

        $this->breakTheWrite($mode);

        Bus::dispatch(new RecordingJob);

        $this->runTheWorker();

        self::assertSame(0, DB::table(self::JOBS)->count());
        self::assertSame(0, DB::table(self::FAILED_JOBS)->count());
        self::assertCount(1, $this->reporter->reports());
        self::assertInstanceOf(AuditWriteFailedException::class, $this->reporter->reports()[0]);
        self::assertHoldsNoSecret($this->reporter->reports(), 'a report');
    }

    /**
     * Configure a database queue with a table of failed jobs, and spill to a
     * channel that writes nowhere.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('queue.default', 'database');
        $config->set('queue.connections.database', ['driver' => 'database', 'connection' => self::CONNECTION, 'table' => self::JOBS, 'queue' => 'default', 'retry_after' => 90]);
        $config->set('queue.failed', ['driver' => 'database-uuids', 'database' => self::CONNECTION, 'table' => self::FAILED_JOBS]);
        $config->set('logging.channels.' . self::SPILL_CHANNEL, ['driver' => 'monolog', 'handler' => NullHandler::class]);
        $config->set('audit-log.failure.log_channel', self::SPILL_CHANNEL);
    }

    /**
     * Create the queue's table and the failed jobs' table, as Laravel's own
     * migrations shape them.
     *
     * @return void
     */
    private function createTheQueuesTables(): void
    {
        Schema::dropIfExists(self::JOBS);
        Schema::dropIfExists(self::FAILED_JOBS);

        Schema::create(self::JOBS, static function (Blueprint $table): void {
            $table->id();
            $table->string('queue')->index();
            $table->longText('payload');
            $table->unsignedTinyInteger('attempts');
            $table->unsignedInteger('reserved_at')->nullable();
            $table->unsignedInteger('available_at');
            $table->unsignedInteger('created_at');
        });

        Schema::create(self::FAILED_JOBS, static function (Blueprint $table): void {
            $table->id();
            $table->string('uuid')->unique();
            $table->text('connection');
            $table->text('queue');
            $table->longText('payload');
            $table->longText('exception');
            $table->timestamp('failed_at')->useCurrent();
        });
    }

    /**
     * Fail unless the text Laravel stored of an exception is the one the worker
     * reported, whose message is built from the diagnostics alone, followed by
     * its trace, with no exception chained after it and the stand-in in the
     * frames that took the record.
     *
     * @param  string  $stored
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    private function assertHoldsOnlyTheFixedText(string $stored, DeliveryMode $mode): void
    {
        $report = $this->reporter->reports()[0] ?? null;

        self::assertInstanceOf(AuditWriteFailedException::class, $report);

        $message = sprintf(
            'Audit record %s (%s) was not written: %s failed on %s with %s, SQLSTATE 23000, driver code 1062, connection %s.',
            $report->recordId,
            RecordingJob::CODE,
            $mode === DeliveryMode::SYNC ? 'store' : 'outbox',
            $mode === DeliveryMode::SYNC ? CallbackStore::class : Outbox::class,
            QueryException::class,
            self::CONNECTION,
        );

        self::assertStringStartsWith(AuditWriteFailedException::class . ': ' . $message . ' in ', $stored);
        self::assertStringContainsString('Stack trace:', $stored);
        self::assertStringContainsString('Object(SensitiveParameterValue)', $stored);
        self::assertStringNotContainsString('Next ', $stored);
        self::assertStringNotContainsString(self::FAILURE, $stored);
    }

    /**
     * The outbox row under the id, which must exist.
     *
     * @param  string  $id
     * @return array<string, int|string|null>
     */
    private function existingRow(string $id): array
    {
        $row = $this->outboxRow($id);

        self::assertNotNull($row);

        return $row;
    }

    /**
     * The receipt of the destination for the entry, which must exist.
     *
     * @param  string  $id
     * @param  string  $destination
     * @return array<string, int|string|null>
     */
    private function existingReceipt(string $id, string $destination): array
    {
        $receipt = $this->receipt($id, $destination);

        self::assertNotNull($receipt);

        return $receipt;
    }

    /**
     * Run the next job through the real `queue:work` command, which alone
     * writes a job that fails to `failed_jobs`, trying it once.
     *
     * @return void
     */
    private function runTheWorker(): void
    {
        Artisan::call('queue:work', ['connection' => 'database', '--once' => true, '--tries' => 1, '--sleep' => 0]);
    }

    /**
     * Make the write fail, quoting the secret: the store, or the outbox's
     * insert.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    private function breakTheWrite(DeliveryMode $mode): void
    {
        if ($mode === DeliveryMode::SYNC) {
            app()->instance(AuditStore::class, self::failingStore());

            return;
        }

        $this->outboxConnection()->beforeExecuting(static function (string $query): void {
            if (!str_starts_with($query, 'insert into') || !str_contains($query, DeliveryTables::outboxTable())) {
                return;
            }

            throw self::quoting('the row');
        });
    }

    /**
     * A store whose every call fails quoting the row it was given and the
     * secret, joining the connections given.
     *
     * @param  list<string>  $joins
     * @return \Tests\Fixtures\Stores\CallbackStore
     */
    private static function failingStore(array $joins = []): CallbackStore
    {
        return new CallbackStore(static function (FinalisedRecord $record): never {
            throw self::quoting(json_encode($record->toArray(), JSON_THROW_ON_ERROR));
        }, true, $joins);
    }

    /**
     * A real query failure, as Laravel throws one, quoting the row and the
     * secret in its message and its bindings.
     *
     * @param  string  $row
     * @return \Illuminate\Database\QueryException
     */
    private static function quoting(string $row): QueryException
    {
        $driver = self::FAILURE . ' ' . self::SECRET . ' ' . $row;

        $previous = new \PDOException($driver);

        $previous->errorInfo = ['23000', 1062, $driver];

        return new QueryException(self::CONNECTION, 'insert into "audit_quoted_rows" ("row") values (?)', [self::SECRET, $row], $previous);
    }
}
