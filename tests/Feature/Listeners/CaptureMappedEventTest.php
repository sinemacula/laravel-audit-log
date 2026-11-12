<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\CaptureMappedEvent;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Fixtures\Capture\Events\PortalEvent;
use Tests\Fixtures\Capture\Events\PortalSignedIn;
use Tests\Fixtures\Capture\Events\RenewedPortalSession;
use Tests\Fixtures\Capture\Events\SignedInToPortal;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Capture\Mappers\ThrowingMapper;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for the wildcard listener routing mapped events to the capture.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CaptureMappedEvent::class)]
final class CaptureMappedEventTest extends TestCase
{
    /** @var \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore The store records reach. */
    private FakeAuditStore $fake;

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /**
     * Fake the store and reporter, and replace the frozen booted registry.
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

        app(MapperRegistry::class)->map(PortalEvent::class, PortalMapper::class);
        app(MapperRegistry::class)->map(PortalSignedIn::class, PortalMapper::class);
    }

    /**
     * An object event is captured through an interface or parent mapping.
     *
     * @return void
     */
    public function testAnObjectEventIsCaptured(): void
    {
        Event::listen('*', CaptureMappedEvent::class);

        Event::dispatch(new SignedInToPortal('7'));
        Event::dispatch(new RenewedPortalSession('8'));

        self::assertSame(['7', '8'], array_map(static fn ($record): ?string => $record->subjectId, $this->fake->recorded()));
    }

    /**
     * An object event handed straight to the bridge is captured.
     *
     * @return void
     */
    public function testAnObjectEventHandedToTheBridgeIsCaptured(): void
    {
        $event = new SignedInToPortal;

        self::bridge()->handle(SignedInToPortal::class, [$event]);

        self::assertSame(1, $this->fake->count());
        self::assertTrue(app(CapturedEvents::class)->isClaimed($event));
    }

    /**
     * A string event is ignored, even with a mapped event in its payload.
     *
     * @return void
     */
    public function testAStringEventIsIgnored(): void
    {
        Event::listen('*', CaptureMappedEvent::class);

        Event::dispatch('portal.signed_in', [new SignedInToPortal]);

        self::bridge()->handle('portal.signed_in', [new SignedInToPortal]);

        self::assertSame(0, $this->fake->count());
    }

    /**
     * Rows of `[name, payload]` that are not one object of the named class.
     *
     * @return iterable<string, array{0: string, 1: list<object|string>}>
     */
    public static function provideOtherPayloads(): iterable
    {
        yield from [
            'no payload'                 => [SignedInToPortal::class, []],
            'two objects'                => [SignedInToPortal::class, [new SignedInToPortal, new SignedInToPortal]],
            'a string'                   => [SignedInToPortal::class, [SignedInToPortal::class]],
            'an object of another class' => [SignedInToPortal::class, [new RenewedPortalSession]],
            'a subclass named as parent' => [PortalSignedIn::class, [new RenewedPortalSession]],
        ];
    }

    /**
     * A payload of any other shape is ignored at once.
     *
     * @param  string  $name
     * @param  list<object|string>  $payload
     * @return void
     */
    #[DataProvider('provideOtherPayloads')]
    public function testAPayloadOfAnotherShapeIsIgnored(string $name, array $payload): void
    {
        self::bridge()->handle($name, $payload);

        self::assertSame(0, $this->fake->count());
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * A contained failure is reported and dispatched once, and writes nothing.
     *
     * @return void
     */
    public function testAContainedFailureNeverLeavesTheBridge(): void
    {
        $failures = [];

        Event::listen(AuditCaptureFailed::class, static function (AuditCaptureFailed $failure) use (&$failures): void {
            $failures[] = $failure->mapperClass;
        });

        $this->app?->instance(PortalMapper::class, new ThrowingMapper);

        self::bridge()->handle(SignedInToPortal::class, [new SignedInToPortal]);

        self::assertSame(0, $this->fake->count());
        self::assertCount(1, $this->reporter->reports());
        self::assertSame([PortalMapper::class], $failures);
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
     * The bridge, made from the container.
     *
     * @return \SineMacula\Laravel\AuditLog\Listeners\CaptureMappedEvent
     */
    private static function bridge(): CaptureMappedEvent
    {
        return app(CaptureMappedEvent::class);
    }
}
