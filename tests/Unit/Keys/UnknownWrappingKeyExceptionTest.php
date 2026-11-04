<?php

declare(strict_types = 1);

namespace Tests\Unit\Keys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Keys\UnknownWrappingKeyException;

/**
 * Unit tests for the unknown wrapping key exception: the message naming the key
 * id alone, the id it keeps for a caller, and the class it specialises.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnknownWrappingKeyException::class)]
final class UnknownWrappingKeyExceptionTest extends TestCase
{
    /**
     * The exception for a key names the key id in its message, and nothing
     * else, and keeps it.
     *
     * @return void
     */
    public function testNamesTheKeyIdAndKeepsIt(): void
    {
        $exception = UnknownWrappingKeyException::forKey('d-0996c88d0aec29cf');

        $expected = 'The wrapping key [d-0996c88d0aec29cf] is not in the wrapping ring; the keys it wrapped cannot be unwrapped until it is'
            . ' configured again.';

        self::assertSame($expected, $exception->getMessage());
        self::assertSame('d-0996c88d0aec29cf', $exception->keyId);
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
    }

    /**
     * The constructor names the key id it is given and keeps it, as the named
     * constructor does.
     *
     * @return void
     */
    public function testTheConstructorNamesTheKeyIdItIsGiven(): void
    {
        $exception = new UnknownWrappingKeyException('w1');

        self::assertSame('w1', $exception->keyId);
        self::assertSame(UnknownWrappingKeyException::forKey('w1')->getMessage(), $exception->getMessage());
        self::assertStringContainsString('[w1]', $exception->getMessage());
    }

    /**
     * The exception is a runtime exception, never an invalid argument: the key
     * is missing from the ring, not malformed.
     *
     * @return void
     */
    public function testIsARuntimeException(): void
    {
        $exception = UnknownWrappingKeyException::forKey('w1');

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertNotInstanceOf(\InvalidArgumentException::class, $exception);
        self::assertNotInstanceOf(\UnexpectedValueException::class, $exception);
        self::assertTrue((new \ReflectionClass(UnknownWrappingKeyException::class))->isFinal());
    }
}
