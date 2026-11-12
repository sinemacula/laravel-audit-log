<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;

/**
 * Unit tests for the unknown key exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnknownKeyException::class)]
final class UnknownKeyExceptionTest extends TestCase
{
    /**
     * The exception for a key names the key id in its message and keeps it.
     *
     * @return void
     */
    public function testNamesTheKeyIdAndKeepsIt(): void
    {
        $exception = UnknownKeyException::forKey('retired-2025');

        self::assertSame('The integrity key [retired-2025] is not in the key ring; its rows cannot be verified until it is configured again.', $exception->getMessage());
        self::assertSame('retired-2025', $exception->keyId);
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
    }

    /**
     * The constructor keeps the message and the key id it is given.
     *
     * @return void
     */
    public function testKeepsTheMessageAndTheKeyIdGiven(): void
    {
        $exception = new UnknownKeyException('What is wrong.', 'k1');

        self::assertSame('What is wrong.', $exception->getMessage());
        self::assertSame('k1', $exception->keyId);
    }

    /**
     * The exception is a runtime exception, never an invalid argument: the key
     * is missing from the ring, not malformed.
     *
     * @return void
     */
    public function testIsARuntimeException(): void
    {
        $exception = UnknownKeyException::forKey('k1');

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertNotInstanceOf(\InvalidArgumentException::class, $exception);
        self::assertTrue((new \ReflectionClass(UnknownKeyException::class))->isFinal());
    }
}
