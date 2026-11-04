<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\EncryptedField;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;

/**
 * Unit tests for an encrypted fragment of an entry: the entry, path and
 * envelope it keeps, the envelope's own rules its constructor holds it to, and
 * the `null` it is made of for anything that is not exactly an envelope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EncryptedField::class)]
final class EncryptedFieldTest extends TestCase
{
    /** @var string An entry id. */
    private const string ENTRY_ID = '01932b4e-8a40-7000-8000-000000000001';

    /**
     * An envelope, as a decoded object or an array in any order, is kept with
     * its entry and path, each part as stored.
     *
     * @return void
     */
    public function testKeepsAnEnvelopeAndItsPath(): void
    {
        $fromObject = EncryptedField::fromEnvelope(self::ENTRY_ID, 'properties._audit.note', (object) ['v' => 1, 'k' => 'key_42', 'c' => 'Y2lwaGVy']);
        $fromArray  = EncryptedField::fromEnvelope(self::ENTRY_ID, 'ip', ['c' => 'Y2lwaGVy', 'v' => ValueNormaliser::MAX_SAFE_INTEGER, 'k' => 'key_42']);

        self::assertInstanceOf(EncryptedField::class, $fromObject);
        self::assertSame(self::ENTRY_ID, $fromObject->entryId);
        self::assertSame('properties._audit.note', $fromObject->path);
        self::assertSame(1, $fromObject->version);
        self::assertSame('key_42', $fromObject->keyReference);
        self::assertSame('Y2lwaGVy', $fromObject->ciphertext);

        self::assertInstanceOf(EncryptedField::class, $fromArray);
        self::assertSame('ip', $fromArray->path);
        self::assertSame(ValueNormaliser::MAX_SAFE_INTEGER, $fromArray->version);
    }

    /**
     * Rows of `[value]`: values that are not exactly an envelope.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<array-key, mixed>|\stdClass}>
     */
    public static function provideNonEnvelopes(): iterable
    {
        yield from [
            'an extra key'                => [['v' => 1, 'k' => 'key_42', 'c' => 'Y2lwaGVy', 'x' => 'y']],
            'a missing key'               => [['v' => 1, 'k' => 'key_42']],
            'version 0'                   => [['v' => 0, 'k' => 'key_42', 'c' => 'Y2lwaGVy']],
            'a version beyond the safe'   => [['v' => ValueNormaliser::MAX_SAFE_INTEGER + 1, 'k' => 'key_42', 'c' => 'Y2lwaGVy']],
            'a version as a string'       => [['v' => '1', 'k' => 'key_42', 'c' => 'Y2lwaGVy']],
            'an empty key'                => [['v' => 1, 'k' => '', 'c' => 'Y2lwaGVy']],
            'a key that is not clean'     => [['v' => 1, 'k' => "key\x0042", 'c' => 'Y2lwaGVy']],
            'a non-string ciphertext'     => [['v' => 1, 'k' => 'key_42', 'c' => 42]],
            'an empty ciphertext'         => [['v' => 1, 'k' => 'key_42', 'c' => '']],
            'a list'                      => [[1, 'key_42', 'Y2lwaGVy']],
            'an empty object'             => [new \stdClass],
            'an object with an extra key' => [(object) ['v' => 1, 'k' => 'key_42', 'c' => 'Y2lwaGVy', 'n' => null]],
        ];
    }

    /**
     * Anything that is not exactly an envelope, each part of its type and as
     * its rules require, holds no encrypted field.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>|\stdClass  $value
     * @return void
     */
    #[DataProvider('provideNonEnvelopes')]
    public function testFromEnvelopeIsNullForAnythingElse(array|\stdClass $value): void
    {
        self::assertNull(EncryptedField::fromEnvelope(self::ENTRY_ID, 'properties.card', $value));
    }

    /**
     * Rows of `[version, key reference, ciphertext, message]`: envelopes whose
     * own rules the constructor refuses.
     *
     * @return iterable<string, array{0: int, 1: string, 2: string, 3: string}>
     */
    public static function provideRefusedEnvelopes(): iterable
    {
        $version = sprintf('An encrypted field\'s version must be an integer from 1 to %d.', ValueNormaliser::MAX_SAFE_INTEGER);
        $text    = 'An encrypted field\'s key reference and ciphertext must be non-empty clean text.';

        yield from [
            'version 0'               => [0, 'key_42', 'Y2lwaGVy', $version],
            'a version beyond'        => [ValueNormaliser::MAX_SAFE_INTEGER + 1, 'key_42', 'Y2lwaGVy', $version],
            'an empty key'            => [1, '', 'Y2lwaGVy', $text],
            'a key that is not clean' => [1, "key\n42", 'Y2lwaGVy', $text],
            'an empty ciphertext'     => [1, 'key_42', '', $text],
            'a ciphertext not clean'  => [1, 'key_42', "Y2lw\x00aGVy", $text],
        ];
    }

    /**
     * The constructor holds an envelope to the rules it was sealed under,
     * naming the rule and never the value.
     *
     * @param  int  $version
     * @param  string  $keyReference
     * @param  string  $ciphertext
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedEnvelopes')]
    public function testTheConstructorRefusesWhatNoEnvelopeHolds(int $version, string $keyReference, string $ciphertext, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new EncryptedField(self::ENTRY_ID, 'properties.card', $version, $keyReference, $ciphertext);
    }

    /**
     * The ciphertext and the path are kept out of a stack trace's frames.
     *
     * @return void
     */
    public function testTheCiphertextAndThePathAreSensitive(): void
    {
        foreach (['path', 'ciphertext'] as $parameter) {
            self::assertCount(1, (new \ReflectionParameter([EncryptedField::class, '__construct'], $parameter))->getAttributes(\SensitiveParameter::class), $parameter);
        }

        foreach (['path', 'envelope'] as $parameter) {
            self::assertCount(1, (new \ReflectionParameter([EncryptedField::class, 'fromEnvelope'], $parameter))->getAttributes(\SensitiveParameter::class), $parameter);
        }
    }
}
