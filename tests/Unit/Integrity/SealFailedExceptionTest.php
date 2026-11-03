<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\SealFailedException;

/**
 * Unit tests for the exception a stopped seal run is reported as: its message
 * naming the class alone, the class it specialises, and the absence of any
 * exception it carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SealFailedException::class)]
final class SealFailedExceptionTest extends TestCase
{
    /**
     * The exception names the class in its fixed message.
     *
     * @return void
     */
    public function testTheMessageIsPinned(): void
    {
        self::assertSame('Sealing stopped with Illuminate\Database\QueryException.', SealFailedException::stoppedBy('Illuminate\Database\QueryException')->getMessage());
        self::assertSame('Sealing stopped with LogicException.', SealFailedException::stoppedBy(\LogicException::class)->getMessage());
        self::assertSame(0, SealFailedException::stoppedBy(\LogicException::class)->getCode());
    }

    /**
     * The exception never carries another, and is built from a class name
     * alone, so no failure's message or bindings reach a report through it.
     *
     * @return void
     */
    public function testHasNoPrevious(): void
    {
        $named = new \ReflectionMethod(SealFailedException::class, 'stoppedBy');

        self::assertNull(SealFailedException::stoppedBy(\RuntimeException::class)->getPrevious());
        self::assertSame(['class'], array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $named->getParameters()));
    }

    /**
     * The exception is a final runtime exception: the next run tries again.
     *
     * @return void
     */
    public function testIsARuntimeException(): void
    {
        self::assertInstanceOf(\RuntimeException::class, SealFailedException::stoppedBy(\RuntimeException::class));
        self::assertTrue((new \ReflectionClass(SealFailedException::class))->isFinal());
    }
}
