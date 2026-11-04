<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Querying\InvalidCursorException;

/**
 * Unit tests for the exception a refused cursor is thrown as: one message
 * whatever the cause, no exception it carries, and the class it specialises.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidCursorException::class)]
final class InvalidCursorExceptionTest extends TestCase
{
    /**
     * Every refusal says the same, and the constructor takes nothing that could
     * make one differ, so a refusal tells nothing of its cause.
     *
     * @return void
     */
    public function testTheMessageIsUniform(): void
    {
        $first  = InvalidCursorException::refused();
        $second = InvalidCursorException::refused();

        self::assertSame('The cursor was refused.', $first->getMessage());
        self::assertSame($first->getMessage(), $second->getMessage());
        self::assertSame(0, $first->getCode());
        self::assertSame([], (new \ReflectionMethod(InvalidCursorException::class, 'refused'))->getParameters());
    }

    /**
     * The refusal carries no other exception, and is a final invalid argument:
     * the cursor is the caller's.
     *
     * @return void
     */
    public function testCarriesNoPreviousAndIsAnInvalidArgument(): void
    {
        $exception = InvalidCursorException::refused();

        self::assertNull($exception->getPrevious());
        self::assertInstanceOf(\InvalidArgumentException::class, $exception);
        self::assertTrue((new \ReflectionClass(InvalidCursorException::class))->isFinal());
    }
}
