<?php

declare(strict_types = 1);

namespace Tests\Unit\Runtime;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;

/**
 * Unit tests for the guard that refuses a record made while the package writes
 * one or handles a failed write: when it is active, what it returns, that it
 * lets go however the work ends, and that only the first refusal in a window is
 * said.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WriteGuard::class)]
final class WriteGuardTest extends TestCase
{
    /**
     * A new guard is inactive, and nothing but work makes it active.
     *
     * @return void
     */
    public function testIsInactiveUntilWorkRuns(): void
    {
        $guard = new WriteGuard;

        self::assertFalse($guard->isActive());

        $guard->during(static fn (): null => null);

        self::assertFalse($guard->isActive());
    }

    /**
     * The guard is active while the work runs.
     *
     * @return void
     */
    public function testIsActiveDuringWork(): void
    {
        $guard = new WriteGuard;

        self::assertTrue($guard->during(static fn (): bool => $guard->isActive()));
    }

    /**
     * What the work returns is returned as it is, `null` included.
     *
     * @return void
     */
    public function testReturnsWhatTheWorkReturns(): void
    {
        $guard  = new WriteGuard;
        $object = new \stdClass;

        self::assertSame('written', $guard->during(static fn (): string => 'written'));
        self::assertSame($object, $guard->during(static fn (): \stdClass => $object));
        self::assertNull($guard->during(static fn (): null => null));
    }

    /**
     * Work that throws lets go of the guard, and its exception propagates as it
     * is.
     *
     * @return void
     */
    public function testReleasesWhenTheWorkThrows(): void
    {
        $guard = new WriteGuard;

        try {
            $guard->during(static function (): void {
                self::raise('The store is down.');
            });

            self::fail('Expected the work\'s exception to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The store is down.', $exception->getMessage());
        }

        self::assertFalse($guard->isActive());
    }

    /**
     * A window inside another leaves the guard active when it ends, until the
     * outermost one ends too, and a nested window that throws does not release
     * the outer one.
     *
     * @return void
     */
    public function testNestedWorkKeepsItActiveUntilTheOutermostEnds(): void
    {
        $guard = new WriteGuard;

        $states = $guard->during(static function () use ($guard): array {
            $inner = $guard->during(static fn (): bool => $guard->isActive());

            try {
                $guard->during(static function (): void {
                    self::raise('The reporter is down.');
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
     * The first refusal in a window is the first, and every later one in the
     * same window is not.
     *
     * @return void
     */
    public function testTheFirstRefusalIsTheOnlyFirst(): void
    {
        $guard = new WriteGuard;

        $refusals = $guard->during(static fn (): array => [$guard->isFirstRefusal(), $guard->isFirstRefusal(), $guard->isFirstRefusal()]);

        self::assertSame([true, false, false], $refusals);
    }

    /**
     * The end of a window forgets its refusal, so the next window's first
     * refusal is said again; a window that ends by throwing forgets it too.
     *
     * @return void
     */
    public function testAWindowEndingClearsTheRefusal(): void
    {
        $guard = new WriteGuard;

        $guard->during(static fn (): bool => $guard->isFirstRefusal());

        self::assertTrue($guard->during(static fn (): bool => $guard->isFirstRefusal()));

        try {
            $guard->during(static function () use ($guard): void {
                $guard->isFirstRefusal();

                self::raise('The spill channel is down.');
            });

            self::fail('Expected the window\'s failure to propagate.');
        } catch (\RuntimeException) {
            // The window's failure is what this test provokes
        }

        self::assertTrue($guard->during(static fn (): bool => $guard->isFirstRefusal()));
    }

    /**
     * A nested window's end leaves the refusal remembered, so a recursion
     * refused again further up the same outermost window is not said twice.
     *
     * @return void
     */
    public function testNestedEndsDoNotClearTheRefusal(): void
    {
        $guard = new WriteGuard;

        $refusals = $guard->during(static function () use ($guard): array {
            $first = $guard->during(static fn (): bool => $guard->isFirstRefusal());
            $guard->during(static fn (): null => null);

            return [$first, $guard->isFirstRefusal(), $guard->during(static fn (): bool => $guard->isFirstRefusal())];
        });

        self::assertSame([true, false, false], $refusals);
    }

    /**
     * Outside a window nothing is refused, so nothing is the first refusal and
     * nothing is remembered for the next window, which would otherwise lose its
     * own first refusal.
     *
     * @return void
     */
    public function testOutsideAWindowNothingIsRefused(): void
    {
        $guard = new WriteGuard;

        $outside = [$guard->isFirstRefusal(), $guard->isFirstRefusal()];
        $inside  = $guard->during(static fn (): bool => $guard->isFirstRefusal());

        self::assertSame([false, false, true], [...$outside, $inside]);
    }

    /**
     * The work is marked sensitive, because it captures a record, so a stack
     * trace through the guard never shows it.
     *
     * @return void
     */
    public function testTheWorkIsMarkedSensitive(): void
    {
        $parameter = (new \ReflectionMethod(WriteGuard::class, 'during'))->getParameters()[0];

        self::assertSame('work', $parameter->getName());
        self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * An exception thrown from the work shows the guard's frame with the work
     * withheld, so nothing the work captured reaches a trace, even with the
     * arguments kept, as a development setting keeps them.
     *
     * @return void
     */
    public function testAThrownFailureWithholdsTheWork(): void
    {
        $guard    = new WriteGuard;
        $previous = ini_set('zend.exception_ignore_args', '0');

        try {
            $guard->during(static function (): void {
                self::raise('A write failed.');
            });

            self::fail('Expected the work\'s exception to propagate.');
        } catch (\RuntimeException $exception) {
            $isTheGuards = static fn (array $frame): bool => ($frame['class'] ?? null) === WriteGuard::class && $frame['function'] === 'during';
            $frames      = array_values(array_filter($exception->getTrace(), $isTheGuards));

            self::assertCount(1, $frames);
            self::assertInstanceOf(\SensitiveParameterValue::class, $frames[0]['args'][0] ?? null);
        } finally {
            ini_set('zend.exception_ignore_args', $previous === false ? '0' : $previous);
        }
    }

    /**
     * Fail as work that cannot write does, from inside the work, so the
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
