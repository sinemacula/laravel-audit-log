<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\EncryptedField;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;

/**
 * Unit tests for an encrypted fragment of an entry: built only by its factory,
 * the entry, segments and envelope it keeps, its path the dotted form of its
 * segments, the `null` it is made of for anything that is not exactly an
 * envelope, the segments it refuses, and the parameters kept out of a stack
 * trace.
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
     * Only the factory builds a field: the constructor is private, so no caller
     * can make one of an envelope of its own and hand it to a reader.
     *
     * @return void
     */
    public function testOnlyTheFactoryBuildsOne(): void
    {
        $constructor = (new \ReflectionClass(EncryptedField::class))->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());
        self::assertInstanceOf(EncryptedField::class, EncryptedField::fromEnvelope(self::ENTRY_ID, ['ip'], ['v' => 1, 'k' => 'key_42', 'c' => 'Y2lwaGVy']));
    }

    /**
     * An envelope, as a decoded object or an array in any order, is kept with
     * its entry and segments, each part as stored.
     *
     * @return void
     */
    public function testKeepsAnEnvelopeAndItsSegments(): void
    {
        $fromObject = EncryptedField::fromEnvelope(self::ENTRY_ID, ['properties', '_audit', 'note'], (object) ['v' => 1, 'k' => 'key_42', 'c' => 'Y2lwaGVy']);
        $fromArray  = EncryptedField::fromEnvelope(self::ENTRY_ID, ['ip'], ['c' => 'Y2lwaGVy', 'v' => ValueNormaliser::MAX_SAFE_INTEGER, 'k' => 'key_42']);

        self::assertInstanceOf(EncryptedField::class, $fromObject);
        self::assertSame(self::ENTRY_ID, $fromObject->entryId);
        self::assertSame(['properties', '_audit', 'note'], $fromObject->segments);
        self::assertSame(1, $fromObject->version);
        self::assertSame('key_42', $fromObject->keyReference);
        self::assertSame('Y2lwaGVy', $fromObject->ciphertext);

        self::assertInstanceOf(EncryptedField::class, $fromArray);
        self::assertSame(['ip'], $fromArray->segments);
        self::assertSame('ip', $fromArray->path);
        self::assertSame(ValueNormaliser::MAX_SAFE_INTEGER, $fromArray->version);
    }

    /**
     * The segments are kept as given, each map key a string and each list index
     * an integer, a key of digits staying a string, and the path is their
     * dotted form.
     *
     * @return void
     */
    public function testTheSegmentsAreKeptAndThePathIsTheirDottedForm(): void
    {
        $envelope = ['v' => 1, 'k' => 'key_42', 'c' => 'Y2lwaGVy'];

        $inAList = EncryptedField::fromEnvelope(self::ENTRY_ID, ['properties', 'items', 0, 'iban'], $envelope);
        $byDigit = EncryptedField::fromEnvelope(self::ENTRY_ID, ['context', 'by_id', '7'], $envelope);

        self::assertInstanceOf(EncryptedField::class, $inAList);
        self::assertSame(['properties', 'items', 0, 'iban'], $inAList->segments);
        self::assertSame('properties.items.0.iban', $inAList->path);

        self::assertInstanceOf(EncryptedField::class, $byDigit);
        self::assertSame(['context', 'by_id', '7'], $byDigit->segments);
        self::assertSame('context.by_id.7', $byDigit->path);
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
            'a ciphertext not clean'      => [['v' => 1, 'k' => 'key_42', 'c' => "Y2lw\x00aGVy"]],
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
        self::assertNull(EncryptedField::fromEnvelope(self::ENTRY_ID, ['properties', 'card'], $value));
    }

    /**
     * Whether a value is well formed is exactly whether the factory builds a
     * field of it, so the projector can tell a malformed envelope from one it
     * shows sealed without building a field of either.
     *
     * @return void
     */
    public function testIsWellFormedExactlyWhenTheFactoryBuildsOne(): void
    {
        $values = [
            ['v' => 1, 'k' => 'key_42', 'c' => 'Y2lwaGVy'],
            (object) ['c' => 'Y2lwaGVy', 'k' => 'key_42', 'v' => 2],
            ...array_map(static fn (array $row): array|\stdClass => $row[0], iterator_to_array(self::provideNonEnvelopes())),
        ];

        foreach ($values as $index => $value) {
            self::assertSame(EncryptedField::fromEnvelope(self::ENTRY_ID, ['ip'], $value) !== null, EncryptedField::isWellFormed($value), (string) $index);
        }

        self::assertTrue(EncryptedField::isWellFormed($values[0]));
        self::assertFalse(EncryptedField::isWellFormed(['v' => 1, 'k' => 'key_42']));
    }

    /**
     * Rows of `[segments]`: segments that do not say where a fragment sits.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<array-key, mixed>}>
     */
    public static function provideRefusedSegments(): iterable
    {
        yield from [
            'none'                    => [[]],
            'a map'                   => [['column' => 'properties']],
            'a list with a gap'       => [[0 => 'properties', 2 => 'card']],
            'an index for the column' => [[0, 'card']],
            'an empty column'         => [['', 'card']],
            'a negative index'        => [['properties', 'items', -1]],
            'a float'                 => [['properties', 1.5]],
            'null'                    => [['properties', null]],
            'a list as a segment'     => [['properties', ['card']]],
        ];
    }

    /**
     * Segments that are not a column followed by strings and indexes from 0 are
     * refused, naming the rule and never the segments.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $segments
     * @return void
     */
    #[DataProvider('provideRefusedSegments')]
    public function testRefusesSegmentsThatSayNowhere(array $segments): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An encrypted field\'s segments must be its column, then strings and indexes from 0.');

        EncryptedField::fromEnvelope(self::ENTRY_ID, $segments, ['v' => 1, 'k' => 'key_42', 'c' => 'Y2lwaGVy']);
    }

    /**
     * The segments, the ciphertext and the envelope are kept out of a stack
     * trace's frames.
     *
     * @return void
     */
    public function testTheCiphertextAndTheSegmentsAreSensitive(): void
    {
        foreach (['segments', 'ciphertext'] as $parameter) {
            self::assertCount(1, (new \ReflectionParameter([EncryptedField::class, '__construct'], $parameter))->getAttributes(\SensitiveParameter::class), $parameter);
        }

        foreach (['segments', 'envelope'] as $parameter) {
            self::assertCount(1, (new \ReflectionParameter([EncryptedField::class, 'fromEnvelope'], $parameter))->getAttributes(\SensitiveParameter::class), $parameter);
        }
    }

    /**
     * A member's segment is its key as PHP keys it: an integer from 0 as that
     * integer, and a negative integer or any other key as a string; so a map
     * key and a list index at the same position are named alike.
     *
     * @return void
     */
    public function testASegmentIsTheKeyAsPhpKeysIt(): void
    {
        self::assertSame([0, 7, '-1', 'a', '05', ''], array_map(EncryptedField::segment(...), [0, 7, -1, 'a', '05', '']));
        $listed = array_map(EncryptedField::segment(...), array_keys(['x', 'y']));
        $mapped = array_map(EncryptedField::segment(...), array_keys(get_object_vars((object) ['0' => 'x', '1' => 'y'])));

        self::assertSame($listed, $mapped);
    }
}
