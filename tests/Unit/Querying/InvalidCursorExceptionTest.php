<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Querying\InvalidCursorException;

/**
 * Unit tests for the exception a refused cursor is thrown as.
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
     * Every refusal has one message, so it reveals nothing of its cause.
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
     * It carries no previous exception and is a final invalid argument.
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
