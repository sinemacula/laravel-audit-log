<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Config\SecretSetting;
use SineMacula\Laravel\AuditLog\Integrity\IntegrityKey;

/**
 * Unit tests for the secret reader every settings class shares: a raw secret, a
 * `base64:` secret, what it refuses, and the value it keeps out of a stack
 * trace.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SecretSetting::class)]
final class SecretSettingTest extends TestCase
{
    /**
     * The reader is a utility container and cannot be instantiated.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(SecretSetting::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(SecretSetting::class, $instance);
    }

    /**
     * A string of 32 bytes or more that has no `base64:` prefix is its own
     * bytes, whatever it holds.
     *
     * @return void
     */
    public function testKeepsARawSecretOfAtLeast32Bytes(): void
    {
        self::assertSame(str_repeat('a', 32), SecretSetting::decode(str_repeat('a', 32)));
        self::assertSame(str_repeat('a', 64), SecretSetting::decode(str_repeat('a', 64)));
        self::assertSame(str_repeat("\xFF", 32), SecretSetting::decode(str_repeat("\xFF", 32)));
    }

    /**
     * A prefix further into the string is not a prefix, so the whole string is
     * the secret.
     *
     * @return void
     */
    public function testAPrefixOnlyCountsAtTheStart(): void
    {
        $secret = ' base64:' . base64_encode(str_repeat('a', 32));

        self::assertSame($secret, SecretSetting::decode($secret));
    }

    /**
     * What follows a `base64:` prefix is decoded, and the length that counts is
     * the decoded one.
     *
     * @return void
     */
    public function testDecodesABase64Secret(): void
    {
        $bytes = str_repeat("\xAB", 32);

        self::assertSame($bytes, SecretSetting::decode('base64:' . base64_encode($bytes)));
    }

    /**
     * Rows of `[value]`: what is not a secret of at least 32 bytes.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideRefusedValues(): iterable
    {
        yield from [
            '31 raw bytes'                                    => [str_repeat('a', 31)],
            'base64 of 31 bytes, its form longer than 32'     => ['base64:' . base64_encode(str_repeat('a', 31))],
            'malformed base64 that would decode leniently'    => ['base64:!' . base64_encode(str_repeat('a', 32))],
            'malformed base64 of more than 32 raw characters' => ['base64:' . str_repeat('*', 40)],
            'a bare prefix'                                   => ['base64:'],
            'an empty string'                                 => [''],
            'null'                                            => [null],
            'an integer'                                      => [12345678901234567],
            'a float'                                         => [1.5],
            'true'                                            => [true],
            'an array'                                        => [[str_repeat('a', 32)]],
            'an object that can be a string'                  => [new class implements \Stringable {
                /**
                 * A string long enough to pass for a secret.
                 *
                 * @return string
                 */
                #[\Override]
                public function __toString(): string
                {
                    return str_repeat('a', 32);
                }
            }],
        ];
    }

    /**
     * Each refused value reads as no secret.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testRefusesAValueThatIsNotASecret(mixed $value): void
    {
        self::assertNull(SecretSetting::decode($value));
    }

    /**
     * The value is marked sensitive, so a stack trace through the reader never
     * shows the key material.
     *
     * @return void
     */
    public function testTheValueIsMarkedSensitive(): void
    {
        $parameter = (new \ReflectionMethod(SecretSetting::class, 'decode'))->getParameters()[0];

        self::assertSame('value', $parameter->getName());
        self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * The reader's minimum is a literal, since `Config` names nothing of the
     * integrity layer, so this holds it to an integrity key's and it cannot
     * drift.
     *
     * @return void
     */
    public function testTheMinimumIsThatOfAnIntegrityKey(): void
    {
        self::assertSame(IntegrityKey::MIN_SECRET_BYTES, SecretSetting::MIN_BYTES);
    }
}
