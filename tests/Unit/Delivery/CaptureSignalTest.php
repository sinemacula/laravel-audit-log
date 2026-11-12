<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\CaptureSignal;

/**
 * Unit tests for one capture's failure channel.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CaptureSignal::class)]
final class CaptureSignalTest extends TestCase
{
    /** @var list<string> The class each call of the callback was given, in order. */
    private array $passedOn = [];

    /**
     * A new signal has no failure, is neither fatal nor deferred, and has
     * called nothing.
     *
     * @return void
     */
    public function testANewSignalHasNotFailed(): void
    {
        $signal = $this->signal();

        self::assertFalse($signal->hasFailed());
        self::assertFalse($signal->isFatal());
        self::assertFalse($signal->isDeferred());
        self::assertNull($signal->exceptionClass());
        self::assertSame([], $this->passedOn);
    }

    /**
     * The first failure's class is the one kept; a later one does not replace
     * it.
     *
     * @return void
     */
    public function testTheFirstFailureIsKept(): void
    {
        $signal = $this->signal();

        $signal->fail(\RuntimeException::class, false);
        $signal->fail(\LogicException::class, false);

        self::assertTrue($signal->hasFailed());
        self::assertSame(\RuntimeException::class, $signal->exceptionClass());
    }

    /**
     * The first failure's class is passed on once, however many failures follow
     * it.
     *
     * @return void
     */
    public function testTheFailureIsPassedOnOnce(): void
    {
        $signal = $this->signal();

        $signal->fail(\RuntimeException::class, false);
        $signal->fail(\LogicException::class, true);
        $signal->fail(\RuntimeException::class, false);

        self::assertSame([\RuntimeException::class], $this->passedOn);
    }

    /**
     * A callback that throws stops nothing: the failure is still kept, and a
     * later failure neither calls it again nor replaces the first.
     *
     * @return void
     */
    public function testAThrowingCallbackIsContained(): void
    {
        $calls  = 0;
        $signal = new CaptureSignal(static function () use (&$calls): never {
            $calls++;

            throw new \RuntimeException('The capture failed to say so.');
        });

        $signal->fail(\RuntimeException::class, true);
        $signal->fail(\LogicException::class, false);

        self::assertSame(1, $calls);
        self::assertTrue($signal->hasFailed());
        self::assertTrue($signal->isFatal());
        self::assertSame(\RuntimeException::class, $signal->exceptionClass());
    }

    /**
     * Once marked deferred, a signal stays deferred, and the mark neither fails
     * it nor calls the callback.
     *
     * @return void
     */
    public function testDeferralIsKept(): void
    {
        $signal = $this->signal();

        $signal->defer();
        $signal->defer();

        self::assertTrue($signal->isDeferred());
        self::assertFalse($signal->hasFailed());
        self::assertSame([], $this->passedOn);

        $signal->fail(\RuntimeException::class, false);

        self::assertTrue($signal->isDeferred());
    }

    /**
     * Whether the signal is fatal is the first failure's to say.
     *
     * @return void
     */
    public function testFatalityIsTheFirstFailures(): void
    {
        $ordinary = $this->signal();

        $ordinary->fail(\RuntimeException::class, false);
        $ordinary->fail(\RuntimeException::class, true);

        $fatal = $this->signal();

        $fatal->fail(\RuntimeException::class, true);
        $fatal->fail(\RuntimeException::class, false);

        self::assertFalse($ordinary->isFatal());
        self::assertTrue($fatal->isFatal());
    }

    /**
     * The callback is not called while the signal is built, only when it first
     * fails.
     *
     * @return void
     */
    public function testNothingIsPassedOnBeforeAFailure(): void
    {
        $signal = $this->signal();

        self::assertSame([], $this->passedOn);

        $signal->fail(\LogicException::class, false);

        self::assertSame([\LogicException::class], $this->passedOn);
    }

    /**
     * A signal whose callback keeps the class of each failure passed on.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\CaptureSignal
     */
    private function signal(): CaptureSignal
    {
        return new CaptureSignal(function (string $exceptionClass): void {
            $this->passedOn[] = $exceptionClass;
        });
    }
}
