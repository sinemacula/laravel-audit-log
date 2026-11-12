<?php

declare(strict_types = 1);

namespace Tests\Unit\Capture;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use Tests\Fixtures\Capture\Events\PortalSignedIn;

/**
 * Unit tests for the claims a capture takes on event objects and the window a
 * mapper runs in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CapturedEvents::class)]
final class CapturedEventsTest extends TestCase
{
    /**
     * The first claim of an event object takes it, and every later one is
     * refused, so the object is written once.
     *
     * @return void
     */
    public function testAnEventIsClaimedOnce(): void
    {
        $events = new CapturedEvents;
        $event  = new PortalSignedIn;

        self::assertSame([true, false, false], [$events->claims($event), $events->claims($event), $events->claims($event)]);
        self::assertTrue($events->isClaimed($event));
    }

    /**
     * A claim is on the object, not its class or its values: two equal events
     * are each claimed.
     *
     * @return void
     */
    public function testDistinctEventsAreEachClaimed(): void
    {
        $events = new CapturedEvents;
        $first  = new PortalSignedIn;
        $second = new PortalSignedIn;

        self::assertTrue($events->claims($first));
        self::assertFalse($events->isClaimed($second));
        self::assertTrue($events->claims($second));
    }

    /**
     * A claim is held weakly, so it goes when its event does and keeps nothing
     * of it alive.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testAClaimGoesWithItsEvent(): void
    {
        $events = new CapturedEvents;
        $event  = new PortalSignedIn;
        $kept   = \WeakReference::create($event);

        $events->claims($event);

        unset($event);

        gc_collect_cycles();

        $claimed = (new \ReflectionProperty(CapturedEvents::class, 'claimed'))->getValue($events);

        self::assertNull($kept->get());
        self::assertInstanceOf(\WeakMap::class, $claimed);
        self::assertCount(0, $claimed);
    }

    /**
     * Asking whether an event is claimed claims nothing, so the next claim
     * still takes it.
     *
     * @return void
     */
    public function testIsClaimedClaimsNothing(): void
    {
        $events = new CapturedEvents;
        $event  = new PortalSignedIn;

        self::assertFalse($events->isClaimed($event));
        self::assertFalse($events->isClaimed($event));
        self::assertTrue($events->claims($event));
    }

    /**
     * The mapping window is open while its work runs and closed before and
     * after, and the work's result is returned as it is, `null` included.
     *
     * @return void
     */
    public function testTheMappingWindowIsOpenOnlyWhileItsWorkRuns(): void
    {
        $events = new CapturedEvents;
        $result = new \stdClass;

        $before = $events->isMapping();
        $during = $events->whileMapping(static fn (): bool => $events->isMapping());

        self::assertSame([false, true, false], [$before, $during, $events->isMapping()]);
        self::assertSame($result, $events->whileMapping(static fn (): \stdClass => $result));
        self::assertNull($events->whileMapping(static fn (): null => null));
    }

    /**
     * Work that throws closes the window, and its exception propagates as it
     * is.
     *
     * @return void
     */
    public function testTheMappingWindowClosesWhenItsWorkThrows(): void
    {
        $events = new CapturedEvents;

        try {
            $events->whileMapping(static function (): void {
                self::raise('The mapper failed.');
            });

            self::fail('Expected the work\'s exception to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The mapper failed.', $exception->getMessage());
        }

        self::assertFalse($events->isMapping());
    }

    /**
     * A nested window leaves the outer one open until the outermost ends, even
     * by throwing; catches a counter replaced by a flag.
     *
     * @return void
     */
    public function testMappingWindowsNest(): void
    {
        $events = new CapturedEvents;

        $states = $events->whileMapping(static function () use ($events): array {
            $inner = $events->whileMapping(static fn (): bool => $events->isMapping());

            try {
                $events->whileMapping(static function (): void {
                    self::raise('The nested mapper failed.');
                });
            } catch (\RuntimeException) {
                // The nested window's failure is what this test provokes
            }

            return [$inner, $events->isMapping()];
        });

        self::assertSame([true, true], $states);
        self::assertFalse($events->isMapping());
    }

    /**
     * Mapping and claiming are independent: an open window claims nothing, and
     * a claim opens no window.
     *
     * @return void
     */
    public function testMappingAndClaimingAreIndependent(): void
    {
        $events = new CapturedEvents;
        $event  = new PortalSignedIn;

        $events->whileMapping(static fn (): bool => $events->isClaimed($event));

        self::assertFalse($events->isClaimed($event));

        $events->claims($event);

        self::assertFalse($events->isMapping());
    }

    /**
     * An object is being described only while its description runs, inside a
     * mapping window, and nothing is claimed.
     *
     * @return void
     */
    public function testAnObjectIsDescribedOnlyWhileItsDescriptionRuns(): void
    {
        $events = new CapturedEvents;
        $event  = new PortalSignedIn;
        $other  = new PortalSignedIn;

        $during = $events->whileDescribing($event, static fn (): array => [$events->isDescribing($event), $events->isDescribing($other), $events->isMapping()]);

        self::assertSame([true, false, true], $during);
        self::assertSame([false, false, false], [$events->isDescribing($event), $events->isMapping(), $events->isClaimed($event)]);
        self::assertNull($events->whileDescribing($event, static fn (): null => null));
    }

    /**
     * A description that throws removes its mark and closes its window, and its
     * exception propagates as it is, so the object is free for another source.
     *
     * @return void
     */
    public function testADescriptionThatThrowsRemovesItsMark(): void
    {
        $events = new CapturedEvents;
        $event  = new PortalSignedIn;

        try {
            $events->whileDescribing($event, static function (): void {
                self::raise('The description failed.');
            });

            self::fail('Expected the description\'s exception to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The description failed.', $exception->getMessage());
        }

        self::assertFalse($events->isDescribing($event));
        self::assertFalse($events->isMapping());
    }

    /**
     * Throw a runtime exception with the message.
     *
     * @param  string  $message
     * @return void
     *
     * @throws \RuntimeException
     */
    private static function raise(string $message): void
    {
        throw new \RuntimeException($message);
    }
}
