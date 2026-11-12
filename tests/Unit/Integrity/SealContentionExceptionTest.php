<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\SealContentionException;

/**
 * Unit tests for the seal contention exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SealContentionException::class)]
final class SealContentionExceptionTest extends TestCase
{
    /**
     * The exception names the attempts in its fixed message and keeps them.
     *
     * @return void
     */
    public function testTheMessageIsPinned(): void
    {
        $exception = SealContentionException::after(5);

        self::assertSame('Sealing gave up after 5 attempts lost to concurrent writers; the next run tries again.', $exception->getMessage());
        self::assertSame(0, $exception->getCode());
        self::assertSame('Sealing gave up after 12 attempts lost to concurrent writers; the next run tries again.', SealContentionException::after(12)->getMessage());
    }

    /**
     * The exception the package raises never carries another, so no failure's
     * message or bindings reach a report through it.
     *
     * @return void
     */
    public function testHasNoPrevious(): void
    {
        $named = new \ReflectionMethod(SealContentionException::class, 'after');

        self::assertNull(SealContentionException::after(1)->getPrevious());
        self::assertSame(['attempts'], array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $named->getParameters()));
    }

    /**
     * The exception is a final runtime exception: the next run tries again.
     *
     * @return void
     */
    public function testIsARuntimeException(): void
    {
        self::assertInstanceOf(\RuntimeException::class, SealContentionException::after(1));
        self::assertTrue((new \ReflectionClass(SealContentionException::class))->isFinal());
    }
}
