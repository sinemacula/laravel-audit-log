<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException;

/**
 * Unit tests for the exception thrown once every attempt lost to contention.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleContentionException::class)]
final class LifecycleContentionExceptionTest extends TestCase
{
    /**
     * The message names the number of attempts and says nothing was committed.
     *
     * @return void
     */
    public function testTheMessageNamesTheAttempts(): void
    {
        self::assertSame(
            'A lifecycle operation lost to concurrent operations 4 times and was abandoned; nothing it attempted was committed.',
            LifecycleContentionException::after(4)->getMessage(),
        );

        self::assertSame(
            'A lifecycle operation lost to concurrent operations 1 times and was abandoned; nothing it attempted was committed.',
            LifecycleContentionException::after(1)->getMessage(),
        );
    }

    /**
     * It carries no previous exception or code, so no failed statement leaks.
     *
     * @return void
     */
    public function testItCarriesNoPreviousException(): void
    {
        $exception = LifecycleContentionException::after(4);

        self::assertNull($exception->getPrevious());
        self::assertSame(0, $exception->getCode());
        self::assertInstanceOf(\RuntimeException::class, $exception);
    }
}
