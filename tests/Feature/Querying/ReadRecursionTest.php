<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Query\Builder;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\RecordedNotifier;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\ReadGate;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Capture\Events\PortalEvent;
use Tests\Fixtures\Capture\Events\SignedInToPortal;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Querying\ReadingListener;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Feature tests for reads of the trail that would recurse, through the read API
 * alone: a listener of a read record, synchronous, at a drain or at a replay,
 * refused and reported once; a terminal call inside a write, a failure handler
 * or an event mapper refused before anything is queried; a listener of an
 * application's record reading once, and its own read record's listener
 * refused; and the write guard refusing a record inside a store as it always
 * has, a read record's write included.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReadGate::class)]
#[CoversClass(RecordedNotifier::class)]
final class ReadRecursionTest extends TestCase
{
    use CapturesLogLines, InteractsWithOutbox, ReadsTheTrail;

    /** @var string The code of an application's own record. */
    private const string CODE = 'invoice.approved';

    /** @var string The code of a record made where none may be. */
    private const string INNER_CODE = 'invoice.voided';

    /** @var ?\Tests\Fixtures\Privacy\RecordingExceptionHandler What each failure is reported to. */
    private ?RecordingExceptionHandler $reporter = null;

    /** @var ?string The spill file a test wrote, removed when it ends. */
    private ?string $spillFile = null;

    /**
     * Bind the read path, report to a recording handler, and capture every line
     * logged.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
        $this->captureLogLines();

        $this->reporter = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $this->reporter);
    }

    /**
     * Remove the spill file a test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->spillFile !== null && is_file($this->spillFile)) {
            unlink($this->spillFile);
        }

        parent::tearDown();
    }

    /**
     * A synchronous listener of a read record that reads the trail is refused
     * before anything is queried, as every such listener is, and the recursion
     * is reported once; the read that was recorded returns all the same, and is
     * the only read recorded.
     *
     * @return void
     */
    public function testASynchronousListenerReadingTheTrailIsRefusedAndReportedOnce(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        $listeners = [new ReadingListener($this->viewer()), new ReadingListener($this->viewer())];

        foreach ($listeners as $listener) {
            Event::listen(AuditRecorded::class, $listener(...));
        }

        $this->captureQueries();

        $page = $this->trail()->cursorPaginate();

        self::assertCount(2, $page->entries);
        self::assertCount(1, $this->entryReads());
        self::assertCount(1, $this->readRecords());

        foreach ($listeners as $listener) {
            self::assertSame(['audit_log.trail_read'], $listener->heard());
            $this->assertRefusedAsReentrant($listener);
        }

        $this->assertReportedOnce();
    }

    /**
     * A listener of a read record that a drain delivers is refused too: the
     * read record queued in the outbox is heard of only at the drain, inside
     * the read guard, and nothing more is recorded.
     *
     * @return void
     */
    public function testAnOutboxDrainListenerReadingTheTrailIsRefused(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', 'outbox');

        $this->allowEverything();
        $this->seedEntries(2);

        $listener = new ReadingListener($this->viewer());

        Event::listen(AuditRecorded::class, $listener(...));

        self::assertCount(2, $this->trail()->cursorPaginate()->entries);
        self::assertSame([], $listener->heard());
        self::assertSame(1, $this->outboxCount());

        app(OutboxDrainer::class)->drain(10, false);

        self::assertSame(['audit_log.trail_read'], $listener->heard());
        self::assertSame(0, $this->outboxCount());
        self::assertCount(1, $this->readRecords());

        $this->assertRefusedAsReentrant($listener);
        $this->assertReportedOnce();
    }

    /**
     * A listener of a read record that a replay of the spill restores is
     * refused too, and nothing more is recorded.
     *
     * @return void
     */
    public function testAReplayListenerReadingTheTrailIsRefused(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        try {
            $this->trail()->cursorPaginate();

            self::fail('Expected the unrecorded read to be refused.');
        } catch (AuditReadRefusedException $refusal) {
            self::assertSame(AuditReadRefusedException::unrecorded()->getMessage(), $refusal->getMessage());
        }

        app()->instance(AuditStore::class, app(DatabaseAuditStore::class));
        app()->instance(ExceptionHandler::class, $this->reporter = new RecordingExceptionHandler);

        $listener = new ReadingListener($this->viewer());

        Event::listen(AuditRecorded::class, $listener(...));

        $result = app(Replayer::class)->spill($this->spillFileOf($this->spillLines()), false);

        self::assertSame(1, $result->replayed());
        self::assertSame(['audit_log.trail_read'], $listener->heard());
        self::assertCount(1, $this->readRecords());

        $this->assertRefusedAsReentrant($listener);
        $this->assertReportedOnce();
    }

    /**
     * A terminal call made inside a store's write is refused before the policy
     * is asked or anything is read, and the record being written is stored.
     *
     * @return void
     */
    public function testATerminalInsideAWriteIsRefusedBeforeAnyQuery(): void
    {
        $policy  = $this->usePolicy(static fn (): AccessScope => AccessScope::all());
        $refusal = null;
        $reads   = [];

        app()->instance(AuditStore::class, new CallbackStore(function () use (&$refusal, &$reads): void {
            $this->captureQueries();

            $refusal = $this->refusalOf(fn () => $this->trail()->count());
            $reads   = $this->entryReads();
        }));

        self::assertInstanceOf(AuditRecord::class, AuditLog::record(self::CODE));
        self::assertSame(AuditReadRefusedException::reentrant()->getMessage(), $refusal?->getMessage());
        self::assertSame([], $reads);
        self::assertSame([], $policy->asked());

        $this->assertReportedOnce();
    }

    /**
     * A terminal call made by a listener of a failed write, while its failure
     * is handled, is refused before the policy is asked or anything is read.
     *
     * @return void
     */
    public function testATerminalInsideAFailureHandlerIsRefused(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', 'report');

        $policy  = $this->usePolicy(static fn (): AccessScope => AccessScope::all());
        $refusal = null;
        $reads   = [];

        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        Event::listen(AuditWriteFailed::class, function () use (&$refusal, &$reads): void {
            $this->captureQueries();

            $refusal = $this->refusalOf(fn () => $this->trail()->cursorPaginate());
            $reads   = $this->entryReads();
        });

        AuditLog::record(self::CODE);

        self::assertSame(AuditReadRefusedException::reentrant()->getMessage(), $refusal?->getMessage());
        self::assertSame([], $reads);
        self::assertSame([], $policy->asked());
        self::assertContains(AuditReadRefusedException::reentrant()->getMessage(), $this->reportedMessages());
    }

    /**
     * A terminal call made by an event mapper, while the event it maps is
     * captured, is refused before the policy is asked or anything is read,
     * reported once, and the mapped record is written all the same.
     *
     * @return void
     */
    #[DefineEnvironment('mapThePortalEvents')]
    public function testATerminalInsideAnEventMapperIsRefusedBeforeAnyQuery(): void
    {
        $policy  = $this->usePolicy(static fn (): AccessScope => AccessScope::all());
        $refusal = null;
        $reads   = ['not read'];

        app()->instance(PortalMapper::class, self::mapperRunning(function () use (&$refusal, &$reads): void {
            $this->captureQueries();

            $refusal = $this->refusalOf(fn () => $this->trail()->count());
            $reads   = $this->entryReads();
        }));

        Event::dispatch(new SignedInToPortal);

        self::assertSame(AuditReadRefusedException::reentrant()->getMessage(), $refusal?->getMessage());
        self::assertSame([], $reads);
        self::assertSame([], $policy->asked());
        self::assertSame(1, $this->entryCountOf(PortalMapper::CODE));

        $this->assertReportedOnce();
    }

    /**
     * A listener of an application's own record reads the trail, which is
     * recorded; the listener then hears of that read record inside the read
     * guard, and its read there is refused, before the first read returns, so a
     * listener that reads on every record reads once and records one read.
     *
     * @return void
     */
    public function testAListenerOfAnApplicationRecordMayReadOnce(): void
    {
        $this->allowEverything();

        $listener = new ReadingListener($this->viewer(), EventDefinition::DEFAULT_CATEGORY);

        Event::listen(AuditRecorded::class, $listener(...));

        AuditLog::record(self::CODE);

        $caught = $listener->caught();

        self::assertSame([self::CODE, 'audit_log.trail_read'], $listener->heard());
        self::assertCount(2, $caught);
        self::assertInstanceOf(AuditReadRefusedException::class, $caught[0]);
        self::assertInstanceOf(TrailPage::class, $caught[1]);
        self::assertSame([self::CODE], array_map(static fn (TrailEntry $entry): string => $entry->event, $caught[1]->entries));
        self::assertCount(1, $this->readRecords());

        $this->assertReportedOnce();
    }

    /**
     * The write guard is unchanged: a record made inside a store is refused,
     * reported naming its code and returned, as it always has been, and only
     * the outer record is stored.
     *
     * @return void
     */
    public function testTheWriteGuardIsUnchanged(): void
    {
        $inner = null;
        $calls = 0;
        $store = app(DatabaseAuditStore::class);

        app()->instance(AuditStore::class, new CallbackStore(static function (#[\SensitiveParameter] FinalisedRecord $record) use ($store, &$inner, &$calls): void {
            $calls++;
            $inner = AuditLog::record(self::INNER_CODE);

            $store->store($record);
        }));

        AuditLog::record(self::CODE);

        $reports = $this->reporter?->reports() ?? [];

        self::assertSame(1, $calls);
        self::assertSame(self::INNER_CODE, $inner?->event);
        self::assertSame([1, 0], [$this->entryCountOf(self::CODE), $this->entryCountOf(self::INNER_CODE)]);
        self::assertCount(1, $reports);
        self::assertInstanceOf(\LogicException::class, $reports[0]);
        self::assertStringContainsString(self::INNER_CODE, $reports[0]->getMessage());
    }

    /**
     * A record made inside the write of a read's own record is refused and
     * reported as one inside any other write is, and the read returns what it
     * found once its record is stored.
     *
     * @return void
     */
    public function testARecordInsideAReadRecordsWriteIsRefusedAsBefore(): void
    {
        $this->allowEverything();
        $this->seedEntries(2);

        $inner = null;

        app()->instance(AuditStore::class, self::storeRecordingInside(app(DatabaseAuditStore::class), static function () use (&$inner): void {
            $inner = AuditLog::record(self::INNER_CODE);
        }));

        self::assertCount(2, $this->trail()->cursorPaginate()->entries);
        self::assertSame(self::INNER_CODE, $inner?->event);
        self::assertCount(1, $this->readRecords('audit_log.trail_read'));
        self::assertSame(0, $this->entryCountOf(self::INNER_CODE));
        self::assertSame([\LogicException::class], array_map(get_debug_type(...), $this->reporter?->reports() ?? []));
    }

    /**
     * Map the portal interface to the portal mapper while the application
     * boots.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function mapThePortalEvents(Application $app): void
    {
        $app->booting(static function (): void {
            AuditLog::map(PortalEvent::class, PortalMapper::class);
        });
    }

    /**
     * The trail, in the `finance` category the seeded entries are in, read for
     * the viewer.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\AuditTrail
     */
    private function trail(): AuditTrail
    {
        return app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance');
    }

    /**
     * The refusal the read is refused with, or `null` when it is not.
     *
     * @param  \Closure(): (int|\SineMacula\Laravel\AuditLog\Querying\TrailPage)  $read
     * @return ?\SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function refusalOf(\Closure $read): ?AuditReadRefusedException
    {
        try {
            $read();
        } catch (AuditReadRefusedException $refusal) {
            return $refusal;
        }

        return null;
    }

    /**
     * Assert the listener read once and was refused as a re-entered read, with
     * nothing chained.
     *
     * @param  \Tests\Fixtures\Querying\ReadingListener  $listener
     * @return void
     */
    private function assertRefusedAsReentrant(ReadingListener $listener): void
    {
        $refusals = $listener->refusals();

        self::assertCount(1, $refusals);
        self::assertSame([], $listener->pages());
        self::assertSame(AuditReadRefusedException::reentrant()->getMessage(), $refusals[0]->getMessage());
        self::assertNull($refusals[0]->getPrevious());
    }

    /**
     * Assert the re-entered read was reported once, and nothing else was.
     *
     * @return void
     */
    private function assertReportedOnce(): void
    {
        self::assertSame([AuditReadRefusedException::reentrant()->getMessage()], $this->reportedMessages());
    }

    /**
     * The message of each report, in order.
     *
     * @return list<string>
     */
    private function reportedMessages(): array
    {
        return array_map(static fn (\Throwable $report): string => $report->getMessage(), $this->reporter?->reports() ?? []);
    }

    /**
     * How many rows of the code the entries table holds.
     *
     * @param  string  $code
     * @return int
     */
    private function entryCountOf(string $code): int
    {
        return $this->storage()->where('event', $code)->count();
    }

    /**
     * The entries table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function storage(): Builder
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table());
    }

    /**
     * Write the lines to a spill file of the test's own, and return its path.
     *
     * @param  list<string>  $lines
     * @return string
     */
    private function spillFileOf(array $lines): string
    {
        self::assertCount(1, $lines, 'Expected the read record to be spilled once.');

        $this->spillFile = (string) tempnam(sys_get_temp_dir(), 'audit-read-spill-');

        file_put_contents($this->spillFile, implode("\n", $lines) . "\n");

        return $this->spillFile;
    }

    /**
     * An event mapper that runs the work, then maps the event as the portal
     * mapper does.
     *
     * @param  \Closure(): void  $work
     * @return \SineMacula\Laravel\AuditLog\Contracts\EventMapper
     */
    private static function mapperRunning(\Closure $work): EventMapper
    {
        return new readonly class ($work) implements EventMapper {
            /**
             * Constructor.
             *
             * @param  \Closure(): void  $work
             */
            public function __construct(

                /** What it runs before it maps the event. */
                private \Closure $work,
            ) {}

            /**
             * Run the work, then name the sign-in.
             *
             * @param  object  $event
             * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
             * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
             *
             * @throws \InvalidArgumentException
             * @throws \LogicException
             */
            #[\Override]
            public function map(#[\SensitiveParameter] object $event, #[\SensitiveParameter] PendingRecord $record): PendingRecord
            {
                ($this->work)();

                return $record->event(PortalMapper::CODE);
            }
        };
    }

    /**
     * A store that keeps attachments and says a return is durable, running the
     * work inside each write before the store given writes the record.
     *
     * @param  \SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore  $store
     * @param  \Closure(): void  $work
     * @return \SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments&\SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore
     */
    private static function storeRecordingInside(DatabaseAuditStore $store, \Closure $work): AcceptsAttachments&DurableAuditStore
    {
        return new readonly class ($store, $work) implements AcceptsAttachments, DurableAuditStore {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore  $store
             * @param  \Closure(): void  $work
             */
            public function __construct(

                /** The store that writes each record. */
                private DatabaseAuditStore $store,

                /** What runs inside each write. */
                private \Closure $work,
            ) {}

            /**
             * Run the work, then write the record.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
             * @return void
             *
             * @throws \Throwable
             */
            #[\Override]
            public function store(#[\SensitiveParameter] FinalisedRecord $record): void
            {
                ($this->work)();

                $this->store->store($record);
            }

            /**
             * Say a return is durable, as the database store does.
             *
             * @return bool
             */
            #[\Override]
            public function isDurable(): bool
            {
                return $this->store->isDurable();
            }

            /**
             * Join a transaction as the database store does.
             *
             * @param  string  $connection
             * @return bool
             */
            #[\Override]
            public function participatesIn(string $connection): bool
            {
                return $this->store->participatesIn($connection);
            }

            /**
             * Keep every attachment, as the database store does.
             *
             * @return bool
             */
            #[\Override]
            public function acceptsAttachments(): bool
            {
                return $this->store->acceptsAttachments();
            }
        };
    }
}
