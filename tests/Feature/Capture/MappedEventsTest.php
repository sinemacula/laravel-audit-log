<?php

declare(strict_types = 1);

namespace Tests\Feature\Capture;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;
use SineMacula\Laravel\AuditLog\Capture\CaptureFailedException;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\CaptureMappedEvent;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Recorder;
use Tests\Concerns\CreatesWatchedModels;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Capture\Events\AccountEvent;
use Tests\Fixtures\Capture\Events\ExcludedPortalEvent;
use Tests\Fixtures\Capture\Events\PackageShapedEvent;
use Tests\Fixtures\Capture\Events\PortalEvent;
use Tests\Fixtures\Capture\Events\PortalSignedIn;
use Tests\Fixtures\Capture\Events\RenewedPortalSession;
use Tests\Fixtures\Capture\Events\SignedInToPortal;
use Tests\Fixtures\Capture\Mappers\CodelessMapper;
use Tests\Fixtures\Capture\Mappers\ConsumingMapper;
use Tests\Fixtures\Capture\Mappers\CoveringMapper;
use Tests\Fixtures\Capture\Mappers\FacadeRecordingMapper;
use Tests\Fixtures\Capture\Mappers\FailClosedMapper;
use Tests\Fixtures\Capture\Mappers\InvalidCodeMapper;
use Tests\Fixtures\Capture\Mappers\NullMapper;
use Tests\Fixtures\Capture\Mappers\OtherInstanceMapper;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Capture\Mappers\RecapturingMapper;
use Tests\Fixtures\Capture\Mappers\RecordingMapper;
use Tests\Fixtures\Capture\Mappers\RedispatchingMapper;
use Tests\Fixtures\Capture\Mappers\SideEffectMapper;
use Tests\Fixtures\Capture\Mappers\ThrowingMapper;
use Tests\Fixtures\Capture\Mappers\TimingMapper;
use Tests\Fixtures\Capture\Mappers\TransactionalMapper;
use Tests\Fixtures\Capture\Models\PlainLine;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for mapped events through the provider's wiring and the real
 * dispatcher.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CaptureMappedEvent::class)]
#[CoversClass(CaptureCoordinator::class)]
#[CoversClass(MapperRegistry::class)]
final class MappedEventsTest extends TestCase
{
    use CreatesWatchedModels, SearchesForSecrets;

    /** @var string What a mapping of the package's own events is refused with. */
    private const string PACKAGE_EVENTS_REFUSAL = 'The package\'s own events are never mapped.';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> Every `AuditCaptureFailed` heard. */
    private array $failures = [];

    /** @var list<string> The events a listener registered after the bridge heard, by name. */
    private array $heard = [];

    /** @var list<string> What each mapping refused while the application booted said. */
    private array $refusals = [];

    /**
     * Bind the reporter, hear capture failures and listen after the bridge.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $failure): void {
            $this->failures[] = $failure;
        });

        Event::listen('*', function (string $name): void {
            $this->heard[] = $name;
        });
    }

    /**
     * An exact class mapping wins over a broad one.
     *
     * @return void
     */
    #[DefineEnvironment('mapTheClassAndItsInterfaceApart')]
    public function testAnExactClassMappingWins(): void
    {
        Event::dispatch(new SignedInToPortal);

        self::assertSame([[PortalMapper::CODE, PortalMapper::SUBJECT_TYPE, '42']], $this->rows());
        self::assertSame([], $this->failures);
    }

    /**
     * The one interface mapping an event's class implements is used.
     *
     * @return void
     */
    #[DefineEnvironment('mapThePortalEvents')]
    public function testASingleInterfaceMappingIsUsed(): void
    {
        Event::dispatch(new ExcludedPortalEvent);

        self::assertSame([[PortalMapper::CODE, PortalMapper::SUBJECT_TYPE, '42']], $this->rows());
    }

    /**
     * A subclass reaches its parent's mapping when it has none of its own.
     *
     * @return void
     */
    #[DefineEnvironment('mapThePortalSignIns')]
    public function testASubclassReachesItsParentsMapping(): void
    {
        Event::dispatch(new RenewedPortalSession(user: '7'));

        self::assertSame([[PortalMapper::CODE, PortalMapper::SUBJECT_TYPE, '7']], $this->rows());
    }

    /**
     * An event two broad mappings match is a contained failure naming no
     * mapper.
     *
     * @return void
     */
    #[DefineEnvironment('mapTwoInterfaces')]
    public function testAnAmbiguityIsContainedAndDiagnosed(): void
    {
        Event::dispatch(new SignedInToPortal);

        self::assertSame([], $this->rows());
        self::assertSame([[SignedInToPortal::class, null, \LogicException::class]], array_map(self::classesOf(...), $this->failures));
        self::assertCount(1, $this->reporter->reports());
        self::assertSame(sprintf('Capturing `%s` with `no mapper` failed with `LogicException`.', SignedInToPortal::class), $this->reporter->reports()[0]->getMessage());
        self::assertContains(SignedInToPortal::class, $this->heard);
    }

    /**
     * A class the mapping excepts is left unmapped.
     *
     * @return void
     */
    #[DefineEnvironment('mapThePortalEventsExceptOne')]
    public function testAnExceptListLeavesAClassUnmapped(): void
    {
        Event::dispatch(new ExcludedPortalEvent);

        self::assertSame([], $this->rows());
        self::assertNull(AuditLog::capture(new ExcludedPortalEvent));

        Event::dispatch(new SignedInToPortal(user: '7'));

        self::assertSame([[PortalMapper::CODE, PortalMapper::SUBJECT_TYPE, '7']], $this->rows());
        self::assertSame([], $this->failures);
    }

    /**
     * A class and its interface mapped together write one row.
     *
     * @return void
     */
    #[DefineEnvironment('mapTheClassAndItsInterfaceTogether')]
    public function testAClassAndItsInterfaceMappedTogetherGiveOneRow(): void
    {
        Event::dispatch(new SignedInToPortal);

        self::assertSame([[PortalMapper::CODE, PortalMapper::SUBJECT_TYPE, '42']], $this->rows());
        self::assertSame([], $this->failures);
    }

    /**
     * One event object dispatched twice, then captured, writes one row.
     *
     * @return void
     */
    #[DefineEnvironment('mapThePortalEvents')]
    public function testOneEventObjectDispatchedTwiceGivesOneRow(): void
    {
        $event = new SignedInToPortal;

        Event::dispatch($event);
        Event::dispatch($event);

        self::assertNull(AuditLog::capture($event));
        self::assertCount(1, $this->rows());

        self::assertNotNull(AuditLog::capture(new SignedInToPortal));
        self::assertCount(2, $this->rows());
    }

    /**
     * Mapping the package's marker, or an event implementing it, is refused.
     *
     * @return void
     */
    #[DefineEnvironment('mapThePackageMarker')]
    public function testMappingThePackageMarkerIsRefused(): void
    {
        self::assertSame([self::PACKAGE_EVENTS_REFUSAL, self::PACKAGE_EVENTS_REFUSAL], $this->refusals);
        self::assertFalse(app(MapperRegistry::class)->hasMappings());
    }

    /**
     * A broad mapping never captures the package's own events.
     *
     * @return void
     */
    #[DefineEnvironment('mapThePortalEvents')]
    public function testABroadMappingNeverCapturesAPackageEvent(): void
    {
        Event::dispatch(new PackageShapedEvent);

        self::assertNull(AuditLog::capture(new PackageShapedEvent));
        self::assertSame([], $this->rows());
        self::assertSame([], $this->failures);
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * Rows of `[mapper, the class of the failure it is contained with]`.
     *
     * @return iterable<string, array{0: class-string<\SineMacula\Laravel\AuditLog\Contracts\EventMapper>, 1: ?class-string<\Throwable>}>
     */
    public static function provideMapperReturns(): iterable
    {
        yield from [
            'null'                        => [NullMapper::class, null],
            'another instance'            => [OtherInstanceMapper::class, \LogicException::class],
            'record() inside'             => [RecordingMapper::class, \LogicException::class],
            'a record through the facade' => [FacadeRecordingMapper::class, \LogicException::class],
            'a consumed builder'          => [ConsumingMapper::class, \LogicException::class],
            'failClosed()'                => [FailClosedMapper::class, \LogicException::class],
            'transactional()'             => [TransactionalMapper::class, \LogicException::class],
            'a timing'                    => [TimingMapper::class, \LogicException::class],
            'no code'                     => [CodelessMapper::class, \LogicException::class],
            'an invalid code'             => [InvalidCodeMapper::class, \InvalidArgumentException::class],
            'an exception'                => [ThrowingMapper::class, \RuntimeException::class],
        ];
    }

    /**
     * Every kind of mapper return is contained, `null` skipping the event.
     *
     * @param  class-string<\SineMacula\Laravel\AuditLog\Contracts\EventMapper>  $mapper
     * @param  ?class-string<\Throwable>  $failure
     * @return void
     */
    #[DataProvider('provideMapperReturns')]
    #[DefineEnvironment('mapThePortalEventsToTheProvidedMapper')]
    public function testEachKindOfReturnIsContained(string $mapper, ?string $failure): void
    {
        self::assertNull(AuditLog::capture(new SignedInToPortal(secret: self::SECRET)));

        Event::dispatch(new SignedInToPortal(secret: self::SECRET));

        self::assertSame([], $this->rows());
        self::assertContains(SignedInToPortal::class, $this->heard);

        $expected = $failure === null ? [] : [[SignedInToPortal::class, $mapper, $failure], [SignedInToPortal::class, $mapper, $failure]];

        self::assertSame($expected, array_map(self::classesOf(...), $this->failures));
        self::assertCount(count($expected), $this->reporter->reports());

        foreach ($this->reporter->reports() as $report) {
            self::assertInstanceOf(CaptureFailedException::class, $report);
            self::assertNull($report->getPrevious());
            self::assertHoldsNoSecret(self::whatThePackageHolds($report), 'a report');
        }

        self::assertHoldsNoSecret($this->failures, 'the capture failures');
    }

    /**
     * The package's own events are never recorded, even from the write path.
     *
     * @return void
     */
    #[DefineEnvironment('mapThePortalEvents')]
    public function testAPackageEventIsNeverRecorded(): void
    {
        $captured = [];

        Event::listen(AuditRecorded::class, static function () use (&$captured): void {
            Event::dispatch(new PackageShapedEvent);

            $captured[] = AuditLog::capture(new PackageShapedEvent);
        });

        Event::dispatch(new SignedInToPortal);

        self::assertContains(AuditRecorded::class, $this->heard);
        self::assertSame([null], $captured);
        self::assertCount(1, $this->rows());
        self::assertSame([], $this->failures);
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * Rows of `[mapper]`: one that captures its event again, one that
     * dispatches it.
     *
     * @return iterable<string, array{0: class-string<\Tests\Fixtures\Capture\Mappers\RecapturingMapper|\Tests\Fixtures\Capture\Mappers\RedispatchingMapper>}>
     */
    public static function provideReentrantMappers(): iterable
    {
        yield from [
            'captured again'   => [RecapturingMapper::class],
            'dispatched again' => [RedispatchingMapper::class],
        ];
    }

    /**
     * A mapper that captures or dispatches its event again never recurses.
     *
     * @param  class-string<\Tests\Fixtures\Capture\Mappers\RecapturingMapper|\Tests\Fixtures\Capture\Mappers\RedispatchingMapper>  $mapper
     * @return void
     */
    #[DataProvider('provideReentrantMappers')]
    #[DefineEnvironment('mapThePortalEventsToTheProvidedMapper')]
    public function testAMapperThatCapturesItsEventAgainNeverRecurses(string $mapper): void
    {
        $instance = $mapper === RecapturingMapper::class ? new RecapturingMapper : new RedispatchingMapper;

        $this->app?->instance($mapper, $instance);

        $event = new SignedInToPortal('7');

        Event::dispatch($event);

        self::assertSame(1, $instance->calls);
        self::assertSame([[PortalMapper::CODE, null, null]], $this->rows());
        self::assertSame([], $this->failures);
        self::assertSame([], $this->reporter->reports());
        self::assertNull(AuditLog::capture($event));
    }

    /**
     * What a mapper's own work sets off is captured on its own.
     *
     * @return void
     */
    #[DefineEnvironment('mapToAMapperWithSideEffects')]
    public function testWhatAMapperSetsOffIsCaptured(): void
    {
        Event::dispatch(new SignedInToPortal('7'));

        $codes = array_column($this->rows(), 0);

        sort($codes);

        self::assertSame([CapturedActivity::GATE_DENIED->value, 'line.created', PortalMapper::CODE], $codes);
        self::assertSame(1, PlainLine::query()->count());
        self::assertSame([], $this->failures);
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * A mapper covers the subjects of a bulk operation.
     *
     * @return void
     */
    #[DefineEnvironment('mapThePortalEventsToCovering')]
    public function testAMapperCoversTheSubjectsOfABulkOperation(): void
    {
        Event::dispatch(new SignedInToPortal);

        $entry    = AuditEntry::query()->sole();
        $artifact = (array) DB::connection(self::CONNECTION)->table(EntrySettings::artifactsTable())->sole();

        self::assertSame(CoveringMapper::CODE, $entry->event);
        self::assertSame([$entry->id, 'bulk', count(CoveringMapper::USERS)], [$artifact['entry_id'], $artifact['kind'], (int) $artifact['member_count']]);
        self::assertSame(count(CoveringMapper::USERS), $entry->properties['_audit']['manifest']['count'] ?? null);
        self::assertSame([], $this->failures);
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
        self::mapWhileBooting($app, static function (): void {
            AuditLog::map(PortalEvent::class, PortalMapper::class);
        });
    }

    /**
     * Map the portal interface to the portal mapper, excepting one class.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function mapThePortalEventsExceptOne(Application $app): void
    {
        self::mapWhileBooting($app, static function (): void {
            AuditLog::map(PortalEvent::class, PortalMapper::class, except: [ExcludedPortalEvent::class]);
        });
    }

    /**
     * Map the portal sign-in class, which a renewed session extends.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function mapThePortalSignIns(Application $app): void
    {
        self::mapWhileBooting($app, static function (): void {
            AuditLog::map(PortalSignedIn::class, PortalMapper::class);
        });
    }

    /**
     * Map both interfaces one class implements while the application boots.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function mapTwoInterfaces(Application $app): void
    {
        self::mapWhileBooting($app, static function (): void {
            AuditLog::map(PortalEvent::class, PortalMapper::class);
            AuditLog::map(AccountEvent::class, PortalMapper::class);
        });
    }

    /**
     * Map a class to the portal mapper and its interface to a mapper that
     * throws, while the application boots.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function mapTheClassAndItsInterfaceApart(Application $app): void
    {
        self::mapWhileBooting($app, static function (): void {
            AuditLog::map(PortalEvent::class, ThrowingMapper::class);
            AuditLog::map(AccountEvent::class, ThrowingMapper::class);
            AuditLog::map(SignedInToPortal::class, PortalMapper::class);
        });
    }

    /**
     * Map a class and its interface to the same mapper while the application
     * boots.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function mapTheClassAndItsInterfaceTogether(Application $app): void
    {
        self::mapWhileBooting($app, static function (): void {
            AuditLog::map(PortalEvent::class, PortalMapper::class);
            AuditLog::map(SignedInToPortal::class, PortalMapper::class);
        });
    }

    /**
     * Map the portal interface to the covering mapper while the application
     * boots.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function mapThePortalEventsToCovering(Application $app): void
    {
        self::mapWhileBooting($app, static function (): void {
            AuditLog::map(PortalEvent::class, CoveringMapper::class);
        });
    }

    /**
     * Map the portal interface to the data provider's mapper.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function mapThePortalEventsToTheProvidedMapper(Application $app): void
    {
        $mapper = $this->providedData()[0] ?? null;

        self::assertIsString($mapper);

        self::mapWhileBooting($app, static function () use ($mapper): void {
            AuditLog::map(PortalEvent::class, $mapper);
        });
    }

    /**
     * Map the portal interface to a mapper with side effects, with lines
     * watched and Gate capture on.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function mapToAMapperWithSideEffects(Application $app): void
    {
        $app->make(ConfigRepository::class)->set('audit-log.capture.gate.enabled', true);

        self::mapWhileBooting($app, static function (): void {
            AuditLog::map(PortalEvent::class, SideEffectMapper::class);
            AuditLog::watch(PlainLine::class, 'line', ['description', 'quantity']);
        });
    }

    /**
     * Try to map the package's marker and an implementing event, noting each
     * refusal.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function mapThePackageMarker(Application $app): void
    {
        $app->booting(function (Application $app): void {
            foreach ([AuditLogEvent::class, PackageShapedEvent::class] as $class) {
                try {
                    $app->make(Recorder::class)->map($class, PortalMapper::class);
                } catch (\LogicException $exception) {
                    $this->refusals[] = $exception->getMessage();
                }
            }
        });
    }

    /**
     * The rows written, oldest first, as their code and subject.
     *
     * @return list<array{0: string, 1: ?string, 2: ?string}>
     */
    private function rows(): array
    {
        return array_values(array_map(
            static fn (AuditEntry $entry): array => [$entry->event, $entry->subject_type, $entry->subject_id],
            AuditEntry::query()->orderBy('recorded_at')->orderBy('id')->get()->all(),
        ));
    }

    /**
     * Register the mappings while the application boots.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  \Closure(): void  $mappings
     * @return void
     */
    private static function mapWhileBooting(Application $app, \Closure $mappings): void
    {
        $app->booting($mappings);
    }

    /**
     * What the package puts in a report: its message, class names and own
     * frames' arguments; the caller's frames hold the event anyway.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\CaptureFailedException  $report
     * @return array{0: string, 1: list<?string>, 2: list<array<array-key, mixed>>}
     */
    private static function whatThePackageHolds(CaptureFailedException $report): array
    {
        $frames = array_filter($report->getTrace(), static fn (array $frame): bool => str_starts_with($frame['class'] ?? '', 'SineMacula\Laravel\AuditLog\\'));

        self::assertNotSame([], $frames);

        return [
            $report->getMessage(),
            [$report->eventClass, $report->mapperClass, $report->exceptionClass],
            array_values(array_map(static fn (array $frame): array => $frame['args'] ?? [], $frames)),
        ];
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
}
