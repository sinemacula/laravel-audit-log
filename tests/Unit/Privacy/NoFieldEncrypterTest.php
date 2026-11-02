<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the default field encrypter: it holds no key for anyone, and
 * marks the plaintext it is given as sensitive.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NoFieldEncrypter::class)]
final class NoFieldEncrypterTest extends TestCase
{
    /**
     * Every owner is told there is no key, whatever the plaintext.
     *
     * @return void
     */
    public function testHasNoKeyForAnyOwner(): void
    {
        $encrypter = new NoFieldEncrypter;

        self::assertNull($encrypter->encrypt(Reference::of('user', 1), 'a value'));
        self::assertNull($encrypter->encrypt(Reference::of('tenant', 'acme'), ''));
    }

    /**
     * The plaintext is marked sensitive, so it stays out of a stack trace.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testThePlaintextParameterIsSensitive(): void
    {
        $parameter = new \ReflectionParameter([NoFieldEncrypter::class, 'encrypt'], 'plaintext');

        self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class));
    }
}
