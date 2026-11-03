<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity\Anchors;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\AnchorConflictException;

/**
 * Unit tests for the anchor conflict exception: the message naming the
 * sequence, the sequence it keeps for a caller, the class it specialises, and
 * the absence of any exception it could carry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AnchorConflictException::class)]
final class AnchorConflictExceptionTest extends TestCase
{
    /**
     * The exception for a sequence names it in its fixed message and keeps it.
     *
     * @return void
     */
    public function testNamesTheSequence(): void
    {
        $exception = AnchorConflictException::forSequence(42);

        self::assertSame('The anchor already holds another digest for seal 42; the local log or the anchor has been altered.', $exception->getMessage());
        self::assertSame(42, $exception->sequence);
        self::assertSame(0, $exception->getCode());
        self::assertSame(7, AnchorConflictException::forSequence(7)->sequence);
    }

    /**
     * The exception never carries another, and cannot be given one: a conflict
     * is evidence, so nothing it holds can reach an entry.
     *
     * @return void
     */
    public function testHasNoPrevious(): void
    {
        $constructor = new \ReflectionMethod(AnchorConflictException::class, '__construct');

        self::assertNull(AnchorConflictException::forSequence(1)->getPrevious());
        self::assertTrue($constructor->isPrivate());
        self::assertSame(['sequence'], array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $constructor->getParameters()));
    }

    /**
     * The exception is a final runtime exception, never an invalid argument:
     * the seal is well formed, and the anchor disagrees with it.
     *
     * @return void
     */
    public function testIsARuntimeException(): void
    {
        $exception = AnchorConflictException::forSequence(1);

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertNotInstanceOf(\InvalidArgumentException::class, $exception);
        self::assertTrue((new \ReflectionClass(AnchorConflictException::class))->isFinal());
    }
}
