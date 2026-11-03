<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Scheduling\Event as ScheduledEvent;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\DrainCommand;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SearchesForSecrets;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Feature tests for `audit-log:drain`: it passes its limit and `--until-empty`
 * on, refuses a limit outside 1 to 10000 as invalid, prints the drain's tally
 * and exits non-zero only when a row failed, names whatever stops the run by
 * its class alone, prints no payload or message, and is neither scheduled nor
 * run through a job by the package.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DrainCommand::class)]
final class DrainCommandTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, SearchesForSecrets, SeedsTheOutbox;

    /**
     * Stop the clock and register the command with the console kernel, which
     * keeps the test independent of the provider.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClockTo('2026-11-01T12:00:00.000000Z');

        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new DrainCommand);

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);
    }

    /**
     * Roll back any transaction a test left open and put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(self::CONNECTION);

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A run prints the tally on one line and exits zero.
     *
     * @return void
     */
    public function testPrintsTheCounts(): void
    {
        $this->enqueue($this->finalisedRecord());
        $this->enqueue($this->finalisedRecord());

        self::assertSame(0, $this->drain());
        self::assertSame("Delivered 2, retried 0, failed 0, stale 0, missed 0.\n", $this->printed());
    }

    /**
     * A run in which a row failed prints the tally and exits non-zero.
     *
     * @return void
     */
    public function testAFailedRowExitsNonZero(): void
    {
        $this->seedOutboxRow(RecordFactory::captured()->id, 'not-an-encrypted-payload');

        self::assertSame(1, $this->drain());
        self::assertSame("Delivered 0, retried 0, failed 1, stale 0, missed 0.\n", $this->printed());
    }

    /**
     * A run in which a row is only retried exits zero: the retry is still to
     * come.
     *
     * @return void
     */
    public function testARetryExitsZero(): void
    {
        $this->failingStore(new \DomainException('Down.'));
        $this->enqueue($this->finalisedRecord());

        self::assertSame(0, $this->drain());
        self::assertSame("Delivered 0, retried 1, failed 0, stale 0, missed 0.\n", $this->printed());
    }

    /**
     * Rows of `[limit given]`: below one, above 10000, not a number, and not an
     * integer.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedLimits(): iterable
    {
        yield from [
            'zero'         => ['0'],
            'one too many' => ['10001'],
            'not a number' => ['abc'],
            'a fraction'   => ['1.5'],
            'padded'       => ['01'],
            'negative'     => ['-1'],
            'empty'        => [''],
        ];
    }

    /**
     * A limit outside 1 to 10000 is refused as invalid before anything is
     * drained, naming the range and not the value.
     *
     * @param  string  $limit
     * @return void
     */
    #[DataProvider('provideRefusedLimits')]
    public function testARefusedLimitIsInvalid(string $limit): void
    {
        $id = $this->enqueue($this->finalisedRecord());

        self::assertSame(2, $this->drain(['--limit' => $limit]));
        self::assertSame("The --limit option must be an integer from 1 to 10000.\n", $this->printed());
        self::assertSame(0, $this->outboxRow($id)['attempts'] ?? null);
    }

    /**
     * Rows of `[limit given]`: the least and the greatest limit accepted.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideAcceptedLimits(): iterable
    {
        yield from [
            'one'          => ['1'],
            'ten thousand' => ['10000'],
        ];
    }

    /**
     * Each end of the range is accepted.
     *
     * @param  string  $limit
     * @return void
     */
    #[DataProvider('provideAcceptedLimits')]
    public function testEachEndOfTheRangeIsAccepted(string $limit): void
    {
        $this->enqueue($this->finalisedRecord());

        self::assertSame(0, $this->drain(['--limit' => $limit]));
        self::assertSame("Delivered 1, retried 0, failed 0, stale 0, missed 0.\n", $this->printed());
    }

    /**
     * The limit given is the most rows the run drains.
     *
     * @return void
     */
    public function testTheLimitIsPassedOn(): void
    {
        foreach (range(1, 3) as $ignored) {
            $this->enqueue($this->finalisedRecord());
        }

        $this->drain(['--limit' => '2']);

        self::assertSame("Delivered 2, retried 0, failed 0, stale 0, missed 0.\n", $this->printed());
        self::assertSame(1, $this->outboxCount());
    }

    /**
     * Without a limit a run drains at most 100 rows.
     *
     * @return void
     */
    public function testTheDefaultLimitIsOneHundred(): void
    {
        $this->bindStore(CallbackStore::saying(false));

        foreach (range(1, DrainCommand::DEFAULT_LIMIT + 1) as $ignored) {
            $this->enqueue($this->finalisedRecord());
        }

        $this->drain();

        self::assertSame("Delivered 100, retried 0, failed 0, stale 0, missed 0.\n", $this->printed());
        self::assertSame(1, $this->outboxCount());
    }

    /**
     * With `--until-empty` a run drains batch after batch until no due row is
     * left.
     *
     * @return void
     */
    public function testUntilEmptyIsPassedOn(): void
    {
        foreach (range(1, 3) as $ignored) {
            $this->enqueue($this->finalisedRecord());
        }

        $this->drain(['--limit' => '1', '--until-empty' => true]);

        self::assertSame("Delivered 3, retried 0, failed 0, stale 0, missed 0.\n", $this->printed());
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * Nothing of a record or of a failure's message reaches the console, the
     * secret planted in both.
     *
     * @return void
     */
    public function testPrintsNoPayload(): void
    {
        $this->failingStore(new \DomainException('Down: ' . self::SECRET));
        $this->enqueue($this->finalisedRecord(RecordFactory::captured(['note' => self::SECRET])));

        $this->drain();

        self::assertFalse(self::holdsText($this->printed(), self::SECRET), 'The planted secret was printed.');
    }

    /**
     * Whatever stops the run is named by its class alone, never its message.
     *
     * @return void
     */
    public function testPrintsNoExceptionMessage(): void
    {
        $this->enqueue($this->finalisedRecord());

        DB::connection(self::CONNECTION)->beginTransaction();

        self::assertSame(1, $this->drain());
        self::assertSame("The drain stopped with LogicException.\nDelivered 0, retried 0, failed 0, stale 0, missed 0.\n", $this->printed());
    }

    /**
     * A missing outbox table stops the run, printing only the class of what was
     * thrown and never its statement.
     *
     * @return void
     */
    public function testAMissingTablePrintsOnlyItsClass(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.outbox.table', 'audit_missing_outbox');

        self::assertSame(1, $this->drain());
        self::assertSame("The drain stopped with Illuminate\\Database\\QueryException.\nDelivered 0, retried 0, failed 0, stale 0, missed 0.\n", $this->printed());
    }

    /**
     * Whatever stops the run is reported as well as printed, payload-free and
     * naming no record, because a scheduled run's output is discarded by
     * default.
     *
     * @return void
     */
    public function testWhatStopsTheRunIsReported(): void
    {
        $handler = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $handler);
        app(ConfigRepository::class)->set('audit-log.delivery.outbox.table', 'audit_missing_outbox');

        self::assertSame(1, $this->drain());

        $reported = $handler->reports()[0] ?? null;

        self::assertCount(1, $handler->reports());
        self::assertInstanceOf(AuditWriteFailedException::class, $reported);
        self::assertNull($reported->recordId);
        self::assertSame('drain', $reported->operation);
        self::assertSame(OutboxDrainer::class, $reported->store);
        self::assertSame(QueryException::class, $reported->exceptionClass);
        self::assertStringStartsWith('No audit record was read: drain failed on ', $reported->getMessage());
        self::assertNull($reported->getPrevious());
    }

    /**
     * A reporter that fails too stops nothing: the class and the tally are
     * still printed, and the run still exits non-zero.
     *
     * @return void
     */
    public function testABrokenReporterStillPrintsAndExitsNonZero(): void
    {
        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler(throwsOnReport: true));
        app(ConfigRepository::class)->set('audit-log.delivery.outbox.table', 'audit_missing_outbox');

        self::assertSame(1, $this->drain());
        self::assertStringContainsString('The drain stopped with', $this->printed());
    }

    /**
     * Rows already worked are still tallied when the run stops at a later read.
     *
     * @return void
     */
    public function testTheTallyOfRowsAlreadyWorkedIsPrintedWhenTheRunStops(): void
    {
        $this->enqueue($this->finalisedRecord());

        $reads = 0;

        DB::connection(self::CONNECTION)->beforeExecuting(static function (string $query) use (&$reads): void {
            if (str_starts_with($query, 'select ') && str_contains($query, DeliveryTables::outboxTable()) && str_contains($query, 'available_at') && ++$reads === 2) {
                throw new \DomainException('The outbox cannot be read.');
            }
        });

        self::assertSame(1, $this->drain(['--limit' => '1', '--until-empty' => true]));
        self::assertSame("The drain stopped with DomainException.\nDelivered 1, retried 0, failed 0, stale 0, missed 0.\n", $this->printed());
    }

    /**
     * The package schedules no drain: the application runs the command.
     *
     * @return void
     */
    public function testNothingIsScheduled(): void
    {
        $events = app(Schedule::class)->events();

        self::assertSame([], array_values(array_filter($events, static fn (ScheduledEvent $event): bool => str_contains((string) $event->command, 'audit-log:drain'))));
    }

    /**
     * A run pushes no job: the command is the drain's only trigger.
     *
     * @return void
     */
    public function testDispatchesNoJob(): void
    {
        Queue::fake();

        $this->failingStore(new \DomainException('Down.'));
        $this->enqueue($this->finalisedRecord(), ['attempts' => 9]);
        $this->enqueue($this->finalisedRecord());

        self::assertSame(1, $this->drain());
        self::assertSame("Delivered 0, retried 1, failed 1, stale 0, missed 0.\n", $this->printed());

        Queue::assertNothingPushed();
    }

    /**
     * An application writing records synchronously can still drain what its
     * outbox holds, from a time it used the outbox.
     *
     * @return void
     */
    public function testASyncModeApplicationCanStillDrain(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::SYNC->value);

        $this->enqueue($this->finalisedRecord());

        self::assertSame(0, $this->drain());
        self::assertSame(1, $this->entryCount());
    }

    /**
     * Run the command with the options given and return its exit code.
     *
     * @param  array<string, bool|string>  $options
     * @return int
     */
    private function drain(array $options = []): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        return $kernel->call('audit-log:drain', $options);
    }

    /**
     * What the last run printed.
     *
     * @return string
     */
    private function printed(): string
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof Kernel);

        return $kernel->output();
    }

    /**
     * Bind a store that is neither durable nor joins a transaction and throws
     * the failure from every call.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    private function failingStore(\Throwable $failure): void
    {
        $this->bindStore(CallbackStore::failingWith($failure, false));
    }

    /**
     * Bind the store.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditStore  $store
     * @return void
     */
    private function bindStore(AuditStore $store): void
    {
        app()->instance(AuditStore::class, $store);
    }
}
