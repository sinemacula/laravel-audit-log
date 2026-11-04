<?php

declare(strict_types = 1);

namespace Tests\Unit\Runtime;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Runtime\ReadGuard;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;

/**
 * Unit tests for the guard that refuses a read of the trail entered while a
 * read, or the notification of a package record, is running: when it is active,
 * what it returns, that it lets go however the work ends, and that only the
 * first refusal in a window is said.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReadGuard::class)]
final class ReadGuardTest extends TestCase
{
    /**
     * A new guard is inactive, and it is inactive again once a window has
     * ended.
     *
     * @return void
     */
    public function testInactiveOutsideAWindow(): void
    {
        $guard = new ReadGuard;

        self::assertFalse($guard->isActive());

        $guard->during(static fn (): null => null);

        self::assertFalse($guard->isActive());
    }

    /**
     * The guard is active while the work runs, and what the work returns is
     * returned as it is, `null` included.
     *
     * @return void
     */
    public function testActiveInsideAWindow(): void
    {
        $guard  = new ReadGuard;
        $object = new \stdClass;

        self::assertTrue($guard->during(static fn (): bool => $guard->isActive()));
        self::assertSame($object, $guard->during(static fn (): \stdClass => $object));
        self::assertNull($guard->during(static fn (): null => null));
    }

    /**
     * A window inside another leaves the guard active when it ends, until the
     * outermost one ends too, and a nested window that throws does not release
     * the outer one.
     *
     * @return void
     */
    public function testWindowsNest(): void
    {
        $guard = new ReadGuard;

        $states = $guard->during(static function () use ($guard): array {
            $inner = $guard->during(static fn (): bool => $guard->isActive());

            try {
                $guard->during(static function (): void {
                    self::raise('The listener failed.');
                });

                self::fail('Expected the inner window\'s failure to propagate.');
            } catch (\RuntimeException) {
                // The inner window's failure is what this test provokes
            }

            return [$inner, $guard->isActive()];
        });

        self::assertSame([true, true], $states);
        self::assertFalse($guard->isActive());
    }

    /**
     * Work that throws closes the window, and its exception propagates as it
     * is.
     *
     * @return void
     */
    public function testAThrowingWorkClosesTheWindow(): void
    {
        $guard = new ReadGuard;

        try {
            $guard->during(static function (): void {
                self::raise('The query failed.');
            });

            self::fail('Expected the work\'s exception to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The query failed.', $exception->getMessage());
        }

        self::assertFalse($guard->isActive());
    }

    /**
     * The first refusal in a window is the first and every later one in the
     * same window, a nested window's included, is not; the end of the outermost
     * window, by a return or a throw, forgets it, so the next window says its
     * first refusal again.
     *
     * @return void
     */
    public function testTheFirstRefusalIsOncePerWindow(): void
    {
        $guard = new ReadGuard;

        $refusals = $guard->during(static function () use ($guard): array {
            $first = $guard->during(static fn (): bool => $guard->isFirstRefusal());
            $guard->during(static fn (): null => null);

            return [$first, $guard->isFirstRefusal(), $guard->during(static fn (): bool => $guard->isFirstRefusal())];
        });

        self::assertSame([true, false, false], $refusals);
        self::assertTrue($guard->during(static fn (): bool => $guard->isFirstRefusal()));

        try {
            $guard->during(static function () use ($guard): void {
                $guard->isFirstRefusal();

                self::raise('The reporter failed.');
            });

            self::fail('Expected the window\'s failure to propagate.');
        } catch (\RuntimeException) {
            // The window's failure is what this test provokes
        }

        self::assertTrue($guard->during(static fn (): bool => $guard->isFirstRefusal()));
    }

    /**
     * Outside a window nothing is refused, so nothing is the first refusal and
     * nothing is remembered for the next window, which would otherwise lose its
     * own first refusal.
     *
     * @return void
     */
    public function testNothingIsRememberedOutsideAWindow(): void
    {
        $guard = new ReadGuard;

        $outside = [$guard->isFirstRefusal(), $guard->isFirstRefusal()];
        $inside  = $guard->during(static fn (): bool => $guard->isFirstRefusal());

        self::assertSame([false, false, true], [...$outside, $inside]);
    }

    /**
     * The read guard's window is its own: a read window opens no write window,
     * and a write window, on the scoped write guard, opens no read window.
     *
     * @return void
     */
    public function testTheWindowIsItsOwn(): void
    {
        $reads  = new ReadGuard;
        $writes = new WriteGuard;

        self::assertFalse($reads->during(static fn (): bool => $writes->isActive()));
        self::assertFalse($writes->during(static fn (): bool => $reads->isActive()));
    }

    /**
     * The work is marked sensitive, because it captures a viewer and what is
     * read, so a stack trace through the guard never shows it.
     *
     * @return void
     */
    public function testTheWorkIsMarkedSensitive(): void
    {
        $parameter = (new \ReflectionMethod(ReadGuard::class, 'during'))->getParameters()[0];

        self::assertSame('work', $parameter->getName());
        self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * An exception thrown from the work shows the guard's frame with the work
     * withheld, even with the arguments kept, as a development setting keeps
     * them.
     *
     * @return void
     */
    public function testAThrownFailureWithholdsTheWork(): void
    {
        $guard    = new ReadGuard;
        $previous = ini_set('zend.exception_ignore_args', '0');

        try {
            $guard->during(static function (): void {
                self::raise('A read failed.');
            });

            self::fail('Expected the work\'s exception to propagate.');
        } catch (\RuntimeException $exception) {
            $isTheGuards = static fn (array $frame): bool => ($frame['class'] ?? null) === ReadGuard::class && $frame['function'] === 'during';
            $frames      = array_values(array_filter($exception->getTrace(), $isTheGuards));

            self::assertCount(1, $frames);
            self::assertInstanceOf(\SensitiveParameterValue::class, $frames[0]['args'][0] ?? null);
        } finally {
            ini_set('zend.exception_ignore_args', $previous === false ? '0' : $previous);
        }
    }

    /**
     * Fail as work that cannot read does, from inside the work, so the
     * exception's trace passes through the guard.
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
