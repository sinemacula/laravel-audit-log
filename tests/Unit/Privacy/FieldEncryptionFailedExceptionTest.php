<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\FieldContext;
use SineMacula\Laravel\AuditLog\Privacy\FieldEncryptionFailedException;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the exception reported when a field encrypter fails: it names
 * the encrypter's class and nothing else, and it cannot carry what the
 * encrypter threw.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FieldEncryptionFailedException::class)]
final class FieldEncryptionFailedExceptionTest extends TestCase
{
    /**
     * The message names the encrypter's class in full and says what happened.
     *
     * @return void
     */
    public function testNamesOnlyTheEncrypterClass(): void
    {
        $exception = FieldEncryptionFailedException::for(new NoFieldEncrypter);

        self::assertSame('The field encrypter ' . NoFieldEncrypter::class . ' failed, so the value was dropped.', $exception->getMessage());
    }

    /**
     * An anonymous encrypter is named by the contract it implements, with
     * neither the file it is in nor the null byte its class name holds.
     *
     * @return void
     */
    public function testAnAnonymousEncrypterIsNamedWithoutItsPath(): void
    {
        $encrypter = new class implements FieldEncrypter {
            /**
             * No envelope.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
             * @param  string  $plaintext
             * @param  \SineMacula\Laravel\AuditLog\Privacy\FieldContext  $context
             * @return null
             */
            #[\Override]
            public function encrypt(Reference $owner, #[\SensitiveParameter] string $plaintext, FieldContext $context): null
            {
                return null;
            }
        };

        $message = FieldEncryptionFailedException::for($encrypter)->getMessage();

        self::assertSame('The field encrypter ' . FieldEncrypter::class . '@anonymous failed, so the value was dropped.', $message);
        self::assertStringNotContainsString(basename(__FILE__), $message);
        self::assertStringNotContainsString("\0", $message);
    }

    /**
     * The exception chains nothing, because what an encrypter threw could hold
     * the plaintext in its message.
     *
     * @return void
     */
    public function testHasNoPreviousException(): void
    {
        self::assertNull(FieldEncryptionFailedException::for(new NoFieldEncrypter)->getPrevious());
    }

    /**
     * Only the named constructor can make one, and the constructor takes only a
     * message, so nothing can ever hand it a previous exception.
     *
     * @return void
     */
    public function testNothingCanGiveItAPreviousException(): void
    {
        $constructor = new \ReflectionMethod(FieldEncryptionFailedException::class, '__construct');

        self::assertTrue($constructor->isPrivate());
        self::assertSame(['message'], array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $constructor->getParameters()));
    }

    /**
     * The encrypter is marked sensitive, so the frame of the exception's own
     * trace does not carry an object that may hold key material.
     *
     * @return void
     */
    public function testNoFrameOfItsTraceCarriesTheEncrypter(): void
    {
        $ignored = ini_set('zend.exception_ignore_args', '0');

        try {
            $exception = FieldEncryptionFailedException::for(new NoFieldEncrypter);
        } finally {
            ini_set('zend.exception_ignore_args', (string) $ignored);
        }

        $frame = $exception->getTrace()[0];

        self::assertSame('for', $frame['function']);
        self::assertInstanceOf(\SensitiveParameterValue::class, ($frame['args'] ?? [])[0] ?? null);
    }
}
