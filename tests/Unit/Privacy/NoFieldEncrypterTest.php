<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\FieldContext;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for the field encrypter that never encrypts: it holds no key for
 * anyone and marks its plaintext as sensitive.
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
     * Every owner is told there is no key, whatever the plaintext and wherever
     * it would be sealed.
     *
     * @return void
     */
    public function testHasNoKeyForAnyOwner(): void
    {
        $encrypter = new NoFieldEncrypter;
        $owner     = Reference::of('user', 1);
        $entryId   = '0192f1c4-7b8e-7c3a-9d2e-5f6a7b8c9d0e';

        self::assertNull($encrypter->encrypt($owner, '"a value"', new FieldContext($entryId, ['properties', 'card'], 'app-eu-1', null, 'general', [$owner])));
        self::assertNull($encrypter->encrypt(Reference::of('tenant', 'acme'), '""', new FieldContext($entryId, ['ip'], 'app-eu-1', $owner, 'finance', [])));
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
