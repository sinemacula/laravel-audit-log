<?php

declare(strict_types = 1);

namespace Tests\Unit\Keys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Keys\OwnerLockTimeoutException;

/**
 * Unit tests for the owner lock timeout exception, which names the wait and
 * never the owner or the lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OwnerLockTimeoutException::class)]
final class OwnerLockTimeoutExceptionTest extends TestCase
{
    /**
     * The exception names the wait it ran out of, and nothing else: no owner,
     * no lock key or name, and no previous exception whose message could.
     *
     * @return void
     */
    public function testNamesTheWaitAlone(): void
    {
        $exception = OwnerLockTimeoutException::after(10);

        self::assertSame('An owner\'s lock was not granted within 10 seconds; nothing that waited for it was committed.', $exception->getMessage());
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
        self::assertSame('An owner\'s lock was not granted within 3 seconds; nothing that waited for it was committed.', OwnerLockTimeoutException::after(3)->getMessage());
    }

    /**
     * The exception is a final runtime exception, never an invalid argument:
     * the lock was held by another, not asked for wrongly.
     *
     * @return void
     */
    public function testIsAFinalRuntimeException(): void
    {
        $exception = OwnerLockTimeoutException::after(1);

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertNotInstanceOf(\InvalidArgumentException::class, $exception);
        self::assertNotInstanceOf(\UnexpectedValueException::class, $exception);
        self::assertTrue((new \ReflectionClass(OwnerLockTimeoutException::class))->isFinal());
    }
}
