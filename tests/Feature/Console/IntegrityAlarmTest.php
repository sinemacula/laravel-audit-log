<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Contracts\Events\Dispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Console\IntegrityAlarm;
use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityCheckFailedException;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for how the seal and verify commands raise an integrity alarm.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegrityAlarm::class)]
final class IntegrityAlarmTest extends TestCase
{
    /** @var string The id of the seal a test's finding was found at. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000001';

    /**
     * The event is dispatched, then its exception is reported.
     *
     * @return void
     */
    public function testDispatchesTheEventThenReportsIt(): void
    {
        $handler = new RecordingExceptionHandler;
        $seen    = $this->listen();
        $event   = self::event(self::SEAL_ID);

        (new IntegrityAlarm($handler, app(Dispatcher::class)))->raise($event);

        self::assertSame([$event], $seen->getArrayCopy());
        self::assertCount(1, $handler->reports());
        self::assertSame(IntegrityCheckFailedException::of($event)->getMessage(), $handler->reports()[0]->getMessage());
    }

    /**
     * A run that stopped reports the exception given, never the event's own.
     *
     * @return void
     */
    public function testAStoppedRunReportsTheExceptionGiven(): void
    {
        $handler = new RecordingExceptionHandler;
        $stopped = IntegrityCheckFailedException::stopped('verify', \DomainException::class);

        (new IntegrityAlarm($handler, app(Dispatcher::class)))->raise(self::event(null), $stopped);

        self::assertSame([$stopped], $handler->reports());
    }

    /**
     * A failing listener is reported and the alarm is still reported.
     *
     * @return void
     */
    public function testAListenerThatFailsIsReportedAndHidesNothing(): void
    {
        $handler = new RecordingExceptionHandler;
        $failure = new \RuntimeException('The alerting listener failed.');

        app(Dispatcher::class)->listen(IntegrityCheckFailed::class, static function () use ($failure): void {
            throw $failure;
        });

        (new IntegrityAlarm($handler, app(Dispatcher::class)))->raise(self::event(self::SEAL_ID));

        $reports = $handler->reports();

        self::assertCount(2, $reports);
        self::assertSame($failure, $reports[0]);
        self::assertInstanceOf(IntegrityCheckFailedException::class, $reports[1]);
    }

    /**
     * A failing reporter stops nothing and throws nothing.
     *
     * @return void
     */
    public function testAReporterThatFailsStopsNothing(): void
    {
        $seen = $this->listen();

        (new IntegrityAlarm(new RecordingExceptionHandler(throwsOnReport: true), app(Dispatcher::class)))->raise(self::event(self::SEAL_ID));

        self::assertCount(1, $seen);
    }

    /**
     * Reporting alone reports the exception and ignores a broken reporter.
     *
     * @return void
     */
    public function testReportsTheExceptionGivenAndIgnoresABrokenReporter(): void
    {
        $handler = new RecordingExceptionHandler;
        $failure = new \RuntimeException('Sealing stopped.');

        (new IntegrityAlarm($handler, app(Dispatcher::class)))->report($failure);
        (new IntegrityAlarm(new RecordingExceptionHandler(throwsOnReport: true), app(Dispatcher::class)))->report($failure);

        self::assertSame([$failure], $handler->reports());
    }

    /**
     * Rows of `[first bad id]`: ids that are no lower-case UUID.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnnameableIds(): iterable
    {
        yield from [
            'a line break'     => [self::SEAL_ID . "\nforged log line"],
            'a control byte'   => [self::SEAL_ID . "\x1b[31m"],
            'an upper-case id' => [strtoupper(self::SEAL_ID)],
            'empty'            => [''],
        ];
    }

    /**
     * A first bad id that is no lower-case UUID never reaches a listener.
     *
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideUnnameableIds')]
    public function testAnIdThatIsNoUuidNeverReachesAListener(string $id): void
    {
        $seen = $this->listen();

        (new IntegrityAlarm(new RecordingExceptionHandler, app(Dispatcher::class)))->raise(self::event($id));

        $event = $seen->getArrayCopy()[0] ?? null;

        self::assertNotNull($event);
        self::assertNull($event->firstBadId);
        self::assertSame(['verify', 'member_hmac', 2, 1, true], [$event->command, $event->finding, $event->head, $event->remoteHead, $event->complete]);
        self::assertSame(1, $event->integrity['tampered']);
        self::assertSame(1, $event->anchoring['unanchored']);
    }

    /**
     * Keep every integrity event dispatched.
     *
     * @return \ArrayObject<int, \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed>
     */
    private function listen(): \ArrayObject
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed> $seen */
        $seen = new \ArrayObject;

        app(Dispatcher::class)->listen(IntegrityCheckFailed::class, static function (IntegrityCheckFailed $event) use ($seen): void {
            $seen->append($event);
        });

        return $seen;
    }

    /**
     * A failed verification event whose first finding has the id given.
     *
     * @param  ?string  $firstBadId
     * @return \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed
     */
    private static function event(?string $firstBadId): IntegrityCheckFailed
    {
        return new IntegrityCheckFailed(
            'verify',
            ['valid' => 0, 'pruned' => 0, 'incomplete' => 0, 'unverifiable' => 0, 'tampered' => 1],
            ['anchored' => 0, 'unanchored' => 1, 'unavailable' => 0, 'contradicted' => 0],
            'member_hmac',
            $firstBadId,
            2,
            1,
            true,
        );
    }
}
