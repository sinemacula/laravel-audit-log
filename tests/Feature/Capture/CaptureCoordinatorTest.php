<?php

declare(strict_types = 1);

namespace Tests\Feature\Capture;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Capture\CaptureFailedException;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Delivery\CommitQueue;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\CaptureMappedEvent;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Capture\Events\AccountEvent;
use Tests\Fixtures\Capture\Events\PackageShapedEvent;
use Tests\Fixtures\Capture\Events\PortalEvent;
use Tests\Fixtures\Capture\Events\PortalSignedIn;
use Tests\Fixtures\Capture\Events\SignedInToPortal;
use Tests\Fixtures\Capture\Mappers\AfterTransactionMapper;
use Tests\Fixtures\Capture\Mappers\CodelessMapper;
use Tests\Fixtures\Capture\Mappers\ConsumingMapper;
use Tests\Fixtures\Capture\Mappers\FailClosedMapper;
use Tests\Fixtures\Capture\Mappers\InvalidCodeMapper;
use Tests\Fixtures\Capture\Mappers\NotAMapper;
use Tests\Fixtures\Capture\Mappers\NullMapper;
use Tests\Fixtures\Capture\Mappers\OtherInstanceMapper;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Capture\Mappers\RecordingMapper;
use Tests\Fixtures\Capture\Mappers\ThrowingMapper;
use Tests\Fixtures\Capture\Mappers\TimingMapper;
use Tests\Fixtures\Capture\Mappers\TransactionalMapper;
use Tests\Fixtures\Capture\Mappers\WritingMapper;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Feature tests for the capture coordinator, on a registry of the test's own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CaptureCoordinator::class)]
final class CaptureCoordinatorTest extends TestCase
{
    use CapturesLogLines, SearchesForSecrets;

    /** @var string The class a package source names itself by. */
    private const string SOURCE = 'Tests\Fixtures\Capture\PackageSource';

    /** @var string The code a package source records. */
    private const string SOURCE_CODE = 'portal.session_restored';

    /** @var \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore The store records reach. */
    private FakeAuditStore $fake;

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> Every `AuditCaptureFailed` heard. */
    private array $failures = [];

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditWriteFailed> Every `AuditWriteFailed` heard. */
    private array $writeFailures = [];

    /**
     * Fake the store, bind the reporter and a fresh registry, as the
     * application's freezes once booted.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fake     = AuditLog::fake();
        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);
        $this->app?->instance(MapperRegistry::class, new MapperRegistry);

        $this->captureLogLines();

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $failure): void {
            $this->failures[] = $failure;
        });

        Event::listen(AuditWriteFailed::class, function (AuditWriteFailed $failure): void {
            $this->writeFailures[] = $failure;
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
        $connection = DB::connection(self::CONNECTION);

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        parent::tearDown();
    }

    /**
     * An event no mapping applies to is not captured and says nothing.
     *
     * @return void
     */
    public function testAnUnmappedEventIsNull(): void
    {
        self::assertNull(self::coordinator()->mapped(new SignedInToPortal));

        self::registry()->map(PortalSignedIn::class, PortalMapper::class);

        self::assertNull(self::coordinator()->mapped(new SignedInToPortal));
        $this->assertNothingHappened();
    }

    /**
     * A package event is turned away before any mapping is resolved.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testAPackageEventIsNullBeforeAnyMappingIsResolved(): void
    {
        self::registry()->map(PortalEvent::class, PortalMapper::class);

        self::assertNull(self::coordinator()->mapped(new PackageShapedEvent));
        self::assertNull(self::coordinator()->mapped(new AuditCaptureFailed(SignedInToPortal::class, null, \RuntimeException::class)));
        self::assertSame([], (new \ReflectionProperty(MapperRegistry::class, 'resolved'))->getValue(self::registry()));
        $this->assertNothingHappened();
    }

    /**
     * A mapped event object is written once, through its mapper.
     *
     * @return void
     */
    public function testAnEventObjectIsRecordedOnce(): void
    {
        self::registry()->map(PortalEvent::class, PortalMapper::class);

        $event  = new SignedInToPortal('7');
        $record = self::coordinator()->mapped($event);

        self::assertSame(PortalMapper::CODE, $record?->event);
        self::assertSame(PortalMapper::SUBJECT_TYPE, $record->subjectType);
        self::assertSame('7', $record->subjectId);
        self::assertNull(self::coordinator()->mapped($event));
        self::assertSame([$record], $this->fake->recorded());
        self::assertNotNull(self::coordinator()->mapped(new SignedInToPortal('7')));
        self::assertSame(2, $this->fake->count());
    }

    /**
     * The mapper gets a builder with no recorder, so its `record()` is refused.
     *
     * @return void
     */
    public function testTheMapperGetsABuilderWithNoRecorder(): void
    {
        $spy = self::spyMapper();

        self::registry()->map(PortalEvent::class, PortalMapper::class);

        $this->app?->instance(PortalMapper::class, $spy);

        self::assertNotNull(self::coordinator()->mapped(new SignedInToPortal));
        self::assertSame(['This pending record has no recorder; make one with `AuditLog::event()`.', true, false], $spy->seen);
    }

    /**
     * A mapper that records the builder it was given is contained.
     *
     * @return void
     */
    public function testRecordInsideAMapperIsContained(): void
    {
        $this->assertContained(RecordingMapper::class, \LogicException::class);
    }

    /**
     * A mapper that writes a record of its own is contained.
     *
     * @return void
     */
    public function testAMapperThatWritesIsContained(): void
    {
        $this->assertContained(WritingMapper::class, \LogicException::class);
    }

    /**
     * A skipped event is left unclaimed for another source.
     *
     * @return void
     */
    public function testASkippedEventIsLeftForAnotherSource(): void
    {
        $event     = new SignedInToPortal;
        $described = 0;

        self::registry()->map(PortalEvent::class, NullMapper::class);

        self::assertNull(self::coordinator()->mapped($event));
        self::assertFalse(app(CapturedEvents::class)->isClaimed($event));
        self::assertNull(self::coordinator()->captured($event, self::SOURCE, static fn (): null => null));
        self::assertFalse(app(CapturedEvents::class)->isClaimed($event));

        $record = self::coordinator()->captured($event, self::SOURCE, self::describer());

        self::assertSame(self::SOURCE_CODE, $record?->event);
        self::assertTrue(app(CapturedEvents::class)->isClaimed($event));

        self::assertNull(self::coordinator()->captured($event, self::SOURCE, static function (PendingRecord $pending) use (&$described): PendingRecord {
            $described++;

            return $pending->event(self::SOURCE_CODE);
        }));
        self::assertSame(0, $described);
        self::assertSame(1, $this->fake->count());
    }

    /**
     * A deferred capture's failure callback holds class names and nothing of
     * the event.
     *
     * @return void
     */
    public function testTheFailureCallbackHoldsNoPayload(): void
    {
        $this->app?->instance(AuditStore::class, CallbackStore::failingWith(new \RuntimeException('The store is down.')));

        $connection = DB::connection(self::CONNECTION);

        $connection->beginTransaction();

        $deferred = static fn (PendingRecord $pending): PendingRecord => $pending->event(self::SOURCE_CODE)->afterCommit();
        $record   = self::coordinator()->captured(new SignedInToPortal(secret: self::SECRET), self::SOURCE, $deferred, mayDefer: true);
        $queue    = app(CommitQueue::class);

        self::assertNotNull($record);
        self::assertTrue(self::holdsText($queue, SignedInToPortal::class));
        self::assertHoldsNoSecret($queue, 'the commit queue');
        self::assertSame(0, $this->failureCount());

        $connection->commit();

        self::assertSame(1, $this->failureCount());
        self::assertSame([SignedInToPortal::class, self::SOURCE, \RuntimeException::class], self::classesOf($this->failures[0]));
    }

    /**
     * A mapper that returns `null` records nothing and says nothing.
     *
     * @return void
     */
    public function testANullReturnRecordsNothing(): void
    {
        self::registry()->map(PortalEvent::class, NullMapper::class);

        self::assertNull(self::coordinator()->mapped(new SignedInToPortal));
        $this->assertNothingHappened();
    }

    /**
     * A mapper that returns a builder other than its own is contained.
     *
     * @return void
     */
    public function testAnotherInstanceIsContained(): void
    {
        $this->assertContained(OtherInstanceMapper::class, \LogicException::class);
    }

    /**
     * A mapper that returns its builder used up is contained.
     *
     * @return void
     */
    public function testAConsumedBuilderIsContained(): void
    {
        $this->assertContained(ConsumingMapper::class, \LogicException::class);
    }

    /**
     * A mapper that makes its record fail-closed is contained.
     *
     * @return void
     */
    public function testFailClosedIsContained(): void
    {
        $this->assertContained(FailClosedMapper::class, \LogicException::class);
    }

    /**
     * A mapper that makes its record transactional is contained.
     *
     * @return void
     */
    public function testTransactionalIsContained(): void
    {
        $this->assertContained(TransactionalMapper::class, \LogicException::class);
    }

    /**
     * A mapper that chooses any timing is contained.
     *
     * @return void
     */
    public function testAMapperChoosingTheTimingIsContained(): void
    {
        $this->assertContained(TimingMapper::class, \LogicException::class);
    }

    /**
     * A mapper may write after the transaction, surviving its rollback.
     *
     * @return void
     */
    public function testAMapperMayWriteAfterTheTransaction(): void
    {
        $connection = DB::connection(self::CONNECTION);

        self::registry()->map(PortalEvent::class, AfterTransactionMapper::class);

        $connection->beginTransaction();

        self::assertNotNull(self::coordinator()->mapped(new SignedInToPortal));
        self::assertSame(0, $this->fake->count());

        $connection->rollBack();

        self::assertSame(1, $this->fake->count());
    }

    /**
     * A mapper that names no code is contained.
     *
     * @return void
     */
    public function testAMissingCodeIsContained(): void
    {
        $this->assertContained(CodelessMapper::class, \LogicException::class);
    }

    /**
     * A mapper that names an invalid code is contained.
     *
     * @return void
     */
    public function testAnInvalidCodeIsContained(): void
    {
        $this->assertContained(InvalidCodeMapper::class, \InvalidArgumentException::class);
    }

    /**
     * A throwing mapper is reported once with nothing of its message.
     *
     * @return void
     */
    public function testAThrowingMapperIsContained(): void
    {
        $this->assertContained(ThrowingMapper::class, \RuntimeException::class);

        $report = $this->reporter->reports()[0];

        self::assertInstanceOf(CaptureFailedException::class, $report);
        self::assertSame(sprintf('Capturing `%s` with `%s` failed with `RuntimeException`.', SignedInToPortal::class, ThrowingMapper::class), $report->getMessage());
        self::assertNull($report->getPrevious());
    }

    /**
     * A mapper the container makes as something else is contained.
     *
     * @return void
     */
    public function testAMapperTheContainerDoesNotMakeAsAMapperIsContained(): void
    {
        $this->app?->instance(PortalMapper::class, new NotAMapper);

        $this->assertContained(PortalMapper::class, \LogicException::class);
    }

    /**
     * An event matching two broad mappings is contained and neither mapper
     * runs.
     *
     * @return void
     */
    public function testAnAmbiguityIsContainedWithNoMapperClass(): void
    {
        self::registry()->map(PortalEvent::class, ThrowingMapper::class);
        self::registry()->map(AccountEvent::class, ThrowingMapper::class);

        self::assertNull(self::coordinator()->mapped(new SignedInToPortal));
        self::assertCount(1, $this->failures);
        self::assertSame([SignedInToPortal::class, null, \LogicException::class], self::classesOf($this->failures[0]));
        self::assertCount(1, $this->reporter->reports());
        self::assertSame(sprintf('Capturing `%s` with `no mapper` failed with `LogicException`.', SignedInToPortal::class), $this->reporter->reports()[0]->getMessage());
        self::assertSame(0, $this->fake->count());
    }

    /**
     * A failure before the capture runs is contained the same way.
     *
     * @return void
     */
    public function testAFailureBeforeTheCaptureRunsIsContained(): void
    {
        self::registry()->map(PortalEvent::class, PortalMapper::class);

        $this->app?->bind(CapturedEvents::class, static function (): never {
            throw new \UnexpectedValueException('The capture state is unavailable.');
        });

        self::assertNull(self::coordinator()->mapped(new SignedInToPortal));
        self::assertNull(self::coordinator()->captured(new SignedInToPortal, self::SOURCE, self::describer()));
        self::assertSame(
            [[SignedInToPortal::class, null, \UnexpectedValueException::class], [SignedInToPortal::class, self::SOURCE, \UnexpectedValueException::class]],
            array_map(self::classesOf(...), $this->failures),
        );
        self::assertCount(2, $this->reporter->reports());
        self::assertSame(0, $this->fake->count());
    }

    /**
     * A failed write is spilled, reported and dispatched once each.
     *
     * @return void
     */
    public function testAWriteFailureIsHandledOnce(): void
    {
        self::registry()->map(PortalEvent::class, PortalMapper::class);

        $this->app?->instance(AuditStore::class, CallbackStore::failingWith(new \RuntimeException('The store is down.')));

        self::assertNull(self::coordinator()->mapped(new SignedInToPortal));
        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->reporter->reports());
        self::assertInstanceOf(AuditWriteFailedException::class, $this->reporter->reports()[0]);
        self::assertCount(1, $this->writeFailures);
        self::assertCount(1, $this->failures);
        self::assertSame([SignedInToPortal::class, PortalMapper::class, \RuntimeException::class], self::classesOf($this->failures[0]));
    }

    /**
     * A capture never reads the failure mode.
     *
     * @return void
     */
    public function testTheThrowFailureModeIsIgnored(): void
    {
        self::registry()->map(PortalEvent::class, PortalMapper::class);

        app(ConfigRepository::class)->set('audit-log.failure.mode', 'nonsense');

        self::assertNotNull(self::coordinator()->mapped(new SignedInToPortal));

        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        $this->app?->instance(AuditStore::class, CallbackStore::failingWith(new \RuntimeException('The store is down.')));

        self::assertNull(self::coordinator()->mapped(new SignedInToPortal));
        self::assertCount(1, $this->failures);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * A throwing `AuditCaptureFailed` listener is contained.
     *
     * @return void
     */
    public function testAThrowingDiagnosticListenerIsContained(): void
    {
        Event::listen(AuditCaptureFailed::class, static function (): never {
            throw new \UnexpectedValueException('The alert failed.');
        });

        self::registry()->map(PortalEvent::class, ThrowingMapper::class);

        self::assertNull(self::coordinator()->mapped(new SignedInToPortal));
        self::assertCount(1, $this->failures);
        self::assertSame(
            [\RuntimeException::class, \UnexpectedValueException::class],
            array_map(static fn (\Throwable $report): string => $report instanceof CaptureFailedException ? $report->exceptionClass : $report::class, $this->reporter->reports()),
        );
    }

    /**
     * A throwing reporter is contained.
     *
     * @return void
     */
    public function testAThrowingReporterIsContained(): void
    {
        $reporter = new RecordingExceptionHandler(throwsOnReport: true);

        $this->app?->instance(ExceptionHandler::class, $reporter);

        self::registry()->map(PortalEvent::class, ThrowingMapper::class);

        self::assertNull(self::coordinator()->mapped(new SignedInToPortal));
        self::assertCount(1, $reporter->reports());
        self::assertCount(1, $this->failures);
    }

    /**
     * Nothing is captured or said inside the write guard.
     *
     * @return void
     */
    public function testNothingIsCapturedInsideTheWriteGuard(): void
    {
        $described = 0;
        $event     = new SignedInToPortal;

        self::registry()->map(PortalEvent::class, ThrowingMapper::class);

        $results = app(WriteGuard::class)->during(static fn (): array => [
            self::coordinator()->mapped($event),
            self::coordinator()->captured($event, self::SOURCE, static function () use (&$described): null {
                $described++;

                return null;
            }),
        ]);

        self::assertSame([null, null], $results);
        self::assertSame(0, $described);
        self::assertFalse(app(CapturedEvents::class)->isClaimed($event));
        $this->assertNothingHappened();
    }

    /**
     * A package source takes the same path as a mapper.
     *
     * @return void
     */
    public function testAPackageSourceUsesTheSamePath(): void
    {
        $record = self::coordinator()->captured(new SignedInToPortal, self::SOURCE, self::describer());

        self::assertSame(self::SOURCE_CODE, $record?->event);
        self::assertSame([$record], $this->fake->recorded());

        $this->app?->instance(AuditStore::class, CallbackStore::failingWith(new \RuntimeException('The store is down.')));

        self::assertNull(self::coordinator()->captured(new SignedInToPortal, self::SOURCE, self::describer()));
        self::assertCount(1, $this->spillLines());
        self::assertCount(1, $this->writeFailures);
        self::assertCount(1, $this->failures);
        self::assertSame([SignedInToPortal::class, self::SOURCE, \RuntimeException::class], self::classesOf($this->failures[0]));
    }

    /**
     * A strict choice is refused before the event object is claimed.
     *
     * @return void
     */
    public function testAStrictChoiceLeavesTheEventUnclaimed(): void
    {
        $event  = new SignedInToPortal;
        $strict = static fn (PendingRecord $pending): PendingRecord => $pending->event(self::SOURCE_CODE)->failClosed();

        self::assertNull(self::coordinator()->captured($event, self::SOURCE, $strict, mayDefer: true));
        self::assertNotNull(self::coordinator()->captured($event, self::SOURCE, self::describer()));
    }

    /**
     * Only a source allowed to defer may choose a timing.
     *
     * @return void
     */
    public function testAPackageSourceMayDeferOnlyWhenAllowed(): void
    {
        $deferred = static fn (PendingRecord $pending): PendingRecord => $pending->event(self::SOURCE_CODE)->afterCommit();

        self::assertNull(self::coordinator()->captured(new SignedInToPortal, self::SOURCE, $deferred));
        self::assertSame(1, $this->failureCount());

        DB::connection(self::CONNECTION)->transaction(function () use ($deferred): void {
            self::assertNotNull(self::coordinator()->captured(new SignedInToPortal, self::SOURCE, $deferred, mayDefer: true));
            self::assertSame(0, $this->fake->count());
        });

        self::assertSame(1, $this->fake->count());

        $strict = [
            static fn (PendingRecord $pending): PendingRecord => $pending->event(self::SOURCE_CODE)->failClosed(),
            static fn (PendingRecord $pending): PendingRecord => $pending->event(self::SOURCE_CODE)->transactional(),
        ];

        foreach ($strict as $describe) {
            self::assertNull(self::coordinator()->captured(new SignedInToPortal, self::SOURCE, $describe, mayDefer: true));
        }

        self::assertSame(3, $this->failureCount());
        self::assertSame(1, $this->fake->count());
    }

    /**
     * A non-claiming source writes the same object each time it sees it.
     *
     * @return void
     */
    public function testANonClaimingSourceRecordsTheSameObjectTwice(): void
    {
        $event = new SignedInToPortal;

        self::assertNotNull(self::coordinator()->captured($event, self::SOURCE, self::describer(), once: false));
        self::assertNotNull(self::coordinator()->captured($event, self::SOURCE, self::describer(), once: false));
        self::assertFalse(app(CapturedEvents::class)->isClaimed($event));
        self::assertSame(2, $this->fake->count());
    }

    /**
     * No capture failure carries a value of the event, record or exception.
     *
     * @return void
     */
    public function testNoFailureCarriesAPayload(): void
    {
        Event::listen(AuditCaptureFailed::class, static function (): never {
            throw new \UnexpectedValueException(sprintf('The alert for %s failed.', self::SECRET));
        });

        self::registry()->map(PortalEvent::class, ThrowingMapper::class);
        self::registry()->map(PortalSignedIn::class, PortalMapper::class);

        self::assertNull(self::coordinator()->mapped(new SignedInToPortal(secret: self::SECRET)));

        $this->app?->instance(AuditStore::class, CallbackStore::failingWith(new \RuntimeException(self::SECRET)));

        self::assertNull(self::coordinator()->mapped(new PortalSignedIn(secret: self::SECRET)));
        self::assertCount(2, $this->failures);
        self::assertCount(1, $this->spillLines());
        self::assertCount(4, $this->reporter->reports());
        self::assertHoldsNoSecret($this->reporter->reports(), 'the reports');
        self::assertHoldsNoSecret($this->failures, 'the capture failures');
        self::assertHoldsNoSecret($this->writeFailures, 'the write failures');
        self::assertHoldsNoSecret($this->spillLines(), 'the spill');
    }

    /**
     * A contained failure lets the listeners after the bridge run.
     *
     * @return void
     */
    public function testALaterListenerStillRuns(): void
    {
        $ran = 0;

        self::registry()->map(PortalEvent::class, ThrowingMapper::class);

        Event::listen('*', CaptureMappedEvent::class);
        Event::listen('*', static function (string $name) use (&$ran): void {
            $ran += $name === SignedInToPortal::class ? 1 : 0;
        });

        Event::dispatch(new SignedInToPortal);

        self::assertSame(1, $ran);
        self::assertCount(1, $this->failures);
    }

    /**
     * Bind the scoped capture state as the provider does.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        app()->scopedIf(CapturedEvents::class);
    }

    /**
     * Capture a portal event through the mapper and assert it was contained.
     *
     * @param  class-string<\SineMacula\Laravel\AuditLog\Contracts\EventMapper>  $mapper
     * @param  class-string<\Throwable>  $failure
     * @return void
     */
    private function assertContained(string $mapper, string $failure): void
    {
        self::registry()->map(PortalEvent::class, $mapper);

        self::assertNull(self::coordinator()->mapped(new SignedInToPortal));
        self::assertSame(0, $this->fake->count());
        self::assertSame([], $this->spillLines());
        self::assertCount(1, $this->reporter->reports());

        $report = $this->reporter->reports()[0];

        self::assertInstanceOf(CaptureFailedException::class, $report);
        self::assertSame([SignedInToPortal::class, $mapper, $failure], [$report->eventClass, $report->mapperClass, $report->exceptionClass]);
        self::assertCount(1, $this->failures);
        self::assertSame([SignedInToPortal::class, $mapper, $failure], self::classesOf($this->failures[0]));
    }

    /**
     * Assert nothing was written, reported, spilled or dispatched.
     *
     * @return void
     */
    private function assertNothingHappened(): void
    {
        self::assertSame(0, $this->fake->count());
        self::assertSame([], $this->reporter->reports());
        self::assertSame([], $this->spillLines());
        self::assertSame([], $this->failures);
        self::assertSame([], $this->writeFailures);
    }

    /**
     * How many `AuditCaptureFailed` events have been heard.
     *
     * @return int
     */
    private function failureCount(): int
    {
        return count($this->failures);
    }

    /**
     * The three class names a capture failure carries.
     *
     * @param  \SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed  $failure
     * @return array{0: string, 1: ?string, 2: string}
     */
    private static function classesOf(AuditCaptureFailed $failure): array
    {
        return [$failure->eventClass, $failure->mapperClass, $failure->exceptionClass];
    }

    /**
     * A package source's description of a portal event.
     *
     * @return \Closure(\SineMacula\Laravel\AuditLog\Records\PendingRecord): \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function describer(): \Closure
    {
        return static fn (PendingRecord $pending): PendingRecord => $pending->event(self::SOURCE_CODE)->on(Reference::of(PortalMapper::SUBJECT_TYPE, '42'));
    }

    /**
     * A mapper that notes what its builder is.
     *
     * @return object{seen: list<bool|string>}&\SineMacula\Laravel\AuditLog\Contracts\EventMapper
     */
    private static function spyMapper(): EventMapper
    {
        return new class implements EventMapper {
            /** @var list<bool|string> What it saw of the builder it was given. */
            public array $seen = [];

            /**
             * Note what the builder is, then return it with a code.
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
                try {
                    $record->record();
                } catch (\LogicException $exception) {
                    $this->seen[] = $exception->getMessage();
                }

                $this->seen[] = app(CapturedEvents::class)->isMapping();
                $this->seen[] = $record->isConsumed();

                return $record->event(PortalMapper::CODE);
            }
        };
    }

    /**
     * The coordinator of the current container.
     *
     * @return \SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator
     */
    private static function coordinator(): CaptureCoordinator
    {
        return app(CaptureCoordinator::class);
    }

    /**
     * The registry the test binds.
     *
     * @return \SineMacula\Laravel\AuditLog\Capture\MapperRegistry
     */
    private static function registry(): MapperRegistry
    {
        return app(MapperRegistry::class);
    }
}
