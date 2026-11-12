<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use Tests\Unit\Stubs\Enums\StubColour;

/**
 * Unit tests for the canonical encoder of integrity version 1.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CanonicalEncoder::class)]
final class CanonicalEncoderTest extends TestCase
{
    /**
     * Rows of `[value, expected]`: encodings from a reference implementation,
     * byte-identical on PHP 8.3, 8.4 and 8.5.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideGoldenVectors(): iterable
    {
        $nested = ['b' => 1, 'a' => ['y' => null, 'x' => true], 'c' => [3, 1, 2], 'd' => [], 'é' => 'ü/"😀'];

        yield from [
            'nested map'                => [$nested, '{"a":{"x":true,"y":null},"b":1,"c":[3,1,2],"d":[],"é":"ü/\"😀"}'],
            'numeric-key map'           => [[2 => 'b', 10 => 'a'], '{"10":"a","2":"b"}'],
            'decoded {"0":"a"}'         => [json_decode('{"0":"a"}'), '{"0":"a"}'],
            'decoded {"1":"x","0":"y"}' => [json_decode('{"1":"x","0":"y"}'), '{"0":"y","1":"x"}'],
            'empty object'              => [json_decode('{}'), '{}'],
            'empty list'                => [[], '[]'],
            'scalars'                   => [[false, null, -42, PHP_INT_MAX], '[false,null,-42,9223372036854775807]'],
            'line separator'            => ["line\u{2028}sep", '"line\u2028sep"'],
            'paragraph separator'       => ["para\u{2029}sep", '"para\u2029sep"'],
            'controls'                  => ["\x00\x01", '"\u0000\u0001"'],
            'bytewise order'            => [['B' => 1, 'a' => 2, 'é' => 3, 'z' => 4], '{"B":1,"a":2,"z":4,"é":3}'],
            'slash'                     => ['a/b', '"a/b"'],
            'quote and backslash'       => ['a"b\c', '"a\"b\\\c"'],
            'whitespace controls'       => ["\t\n\r", '"\t\n\r"'],
            'null'                      => [null, 'null'],
            'true'                      => [true, 'true'],
            'false'                     => [false, 'false'],
            'zero'                      => [0, '0'],
            'least integer'             => [PHP_INT_MIN, '-9223372036854775808'],
            'empty string'              => ['', '""'],
            'decoded nested objects'    => [json_decode('{"b":{"d":[],"c":{}},"a":[{"z":1,"y":2}]}'), '{"a":[{"y":2,"z":1}],"b":{"c":{},"d":[]}}'],
        ];
    }

    /**
     * Each value encodes to exactly its golden bytes.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  string  $expected
     * @return void
     */
    #[DataProvider('provideGoldenVectors')]
    public function testEncodesEachGoldenVectorByteForByte(mixed $value, string $expected): void
    {
        self::assertSame($expected, CanonicalEncoder::encode($value));
    }

    /**
     * The line and paragraph separators are escaped, so the encoding is the
     * same wherever JSON is read as JavaScript.
     *
     * @return void
     */
    public function testLineTerminatorsAreEscaped(): void
    {
        $encoded = CanonicalEncoder::encode(["\u{2028}" => "\u{2029}"]);

        self::assertSame('{"\u2028":"\u2029"}', $encoded);
        self::assertStringNotContainsString("\u{2028}", $encoded);
        self::assertStringNotContainsString("\u{2029}", $encoded);
    }

    /**
     * An array map and the `stdClass` its JSON decodes to encode the same, so a
     * record signed from its values verifies from its decoded row.
     *
     * @return void
     */
    public function testAMapAndADecodedObjectWithTheSameMembersEncodeTheSame(): void
    {
        $map = ['zeta' => ['k' => 'v', 'a' => [1, 2]], 'alpha' => 'x', '7' => true, 'empty' => ['nested' => []]];

        self::assertSame(CanonicalEncoder::encode($map), CanonicalEncoder::encode(json_decode(json_encode($map, JSON_THROW_ON_ERROR))));
    }

    /**
     * Keys sort bytewise: `10` before `2`, `B` before `a` and `z` before `é`,
     * which protects against a natural, numeric or case-insensitive sort.
     *
     * @return void
     */
    public function testKeysSortBytewise(): void
    {
        self::assertSame('{"10":1,"2":2}', CanonicalEncoder::encode(['2' => 2, '10' => 1]));
        self::assertSame('{"B":1,"a":2}', CanonicalEncoder::encode(['a' => 2, 'B' => 1]));
        self::assertSame('{"z":1,"é":2}', CanonicalEncoder::encode(['é' => 2, 'z' => 1]));
        self::assertSame('{"a":1,"a1":2,"b":3}', CanonicalEncoder::encode(['b' => 3, 'a1' => 2, 'a' => 1]));
        self::assertSame('{"-1":1,"1":2}', CanonicalEncoder::encode([1 => 2, -1 => 1]));
    }

    /**
     * A map whose keys are the integers of a list, but out of order, stays a
     * map once sorted and is never written as a list.
     *
     * @return void
     */
    public function testANumericKeyMapStaysAMap(): void
    {
        self::assertSame('{"0":"b","1":"a"}', CanonicalEncoder::encode([1 => 'a', 0 => 'b']));
        self::assertSame('{"0":"a"}', CanonicalEncoder::encode(json_decode('{"0":"a"}')));
    }

    /**
     * An empty `stdClass` is the empty map and an empty array the empty list,
     * nested too.
     *
     * @return void
     */
    public function testAnEmptyObjectIsNotAnEmptyList(): void
    {
        self::assertSame('{}', CanonicalEncoder::encode(new \stdClass));
        self::assertSame('[]', CanonicalEncoder::encode([]));
        self::assertSame('[{},[]]', CanonicalEncoder::encode([new \stdClass, []]));
    }

    /**
     * A list keeps the order of its members, and its members are never sorted,
     * nested maps inside it included.
     *
     * @return void
     */
    public function testListOrderIsKept(): void
    {
        self::assertSame('[3,1,2]', CanonicalEncoder::encode([3, 1, 2]));
        self::assertSame('["b","a"]', CanonicalEncoder::encode(['b', 'a']));
        self::assertSame('[{"a":1,"b":2},[2,1]]', CanonicalEncoder::encode([['b' => 2, 'a' => 1], [2, 1]]));
    }

    /**
     * A string is encoded as given: a bidirectional override is kept and a
     * control character escaped, never stripped.
     *
     * @return void
     */
    public function testNeverRepairsWhatItEncodes(): void
    {
        self::assertSame("\"a\u{202E}b\"", CanonicalEncoder::encode("a\u{202E}b"));
        self::assertSame('"\u0001"', CanonicalEncoder::encode("\x01"));
        self::assertSame('" padded "', CanonicalEncoder::encode(' padded '));
        self::assertSame("\"e\u{0301}\"", CanonicalEncoder::encode("e\u{0301}"));
        self::assertSame('"' . str_repeat('a', 10000) . '"', CanonicalEncoder::encode(str_repeat('a', 10000)));
    }

    /**
     * Rows of `[value]`: floats, a whole one and zero included, alone and
     * nested.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideFloats(): iterable
    {
        yield from [
            'a fraction'          => [1.5],
            'a whole float'       => [1.0],
            'zero'                => [0.0],
            'negative zero'       => [-0.0],
            'infinity'            => [INF],
            'not a number'        => [NAN],
            'in a list'           => [[1, 2.5]],
            'in a map'            => [['price' => 9.99]],
            'in a decoded object' => [json_decode('{"price":9.5}')],
        ];
    }

    /**
     * A float has no canonical form, whatever its value, wherever it sits.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideFloats')]
    public function testRefusesAFloat(mixed $value): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A float cannot be encoded canonically; the package stores decimals as strings.');

        CanonicalEncoder::encode($value);
    }

    /**
     * Rows of `[value, type]`: values of a type with no canonical form, and the
     * type the refusal names.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideUnsupportedValues(): iterable
    {
        $stringable = new class implements \Stringable {
            /**
             * The text the object would give.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return 'text';
            }
        };

        yield from [
            'a date'              => [new \DateTimeImmutable('2026-11-01T12:00:00Z'), \DateTimeImmutable::class],
            'a stringable'        => [$stringable, get_debug_type($stringable)],
            'a backed enum case'  => [StubColour::RED, StubColour::class],
            'a JSON serialisable' => [new \ArrayObject([1]), \ArrayObject::class],
            'a closure'           => [static fn (): int => 1, \Closure::class],
            'nested in a map'     => [['when' => new \DateTimeImmutable('2026-11-01T12:00:00Z')], \DateTimeImmutable::class],
            'nested in a list'    => [[1, StubColour::RED], StubColour::class],
            'nested in an object' => [(object) ['colour' => StubColour::RED], StubColour::class],
            'a stdClass subclass' => [new class extends \stdClass {}, 'stdClass@anonymous'],
            'a resource'          => [STDIN, 'resource (stream)'],
        ];
    }

    /**
     * Each value of a type with no canonical form is refused, naming the type,
     * alone or nested.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  string  $type
     * @return void
     */
    #[DataProvider('provideUnsupportedValues')]
    public function testRefusesAValueWithNoCanonicalForm(mixed $value, string $type): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(sprintf('A value of type %s cannot be encoded canonically.', $type));

        CanonicalEncoder::encode($value);
    }

    /**
     * Rows of `[value]`: invalid UTF-8 as a value and as a map key, alone and
     * nested.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideInvalidUtf8(): iterable
    {
        yield from [
            'a value'                   => ["\xB1"],
            'a map key'                 => [["\xB1" => 'a']],
            'a value in a list'         => [['ok', "a\xB1"]],
            'a key of a decoded object' => [(object) ["\xB1" => 1]],
        ];
    }

    /**
     * A string that is not valid UTF-8 is refused, value or key, keeping the
     * JSON error as the previous exception.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideInvalidUtf8')]
    public function testRefusesInvalidUtf8(mixed $value): void
    {
        try {
            CanonicalEncoder::encode($value);
            self::fail('Expected the invalid UTF-8 to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame('A string that is not valid UTF-8 cannot be encoded canonically.', $exception->getMessage());
            self::assertSame(0, $exception->getCode());
            self::assertInstanceOf(\JsonException::class, $exception->getPrevious());
        }
    }

    /**
     * The flags of every string are fixed for version 1: unescaped unicode and
     * slashes, and errors thrown.
     *
     * @return void
     */
    public function testTheJsonFlagsAreFixed(): void
    {
        self::assertSame(JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR, CanonicalEncoder::JSON_FLAGS);
    }

    /**
     * The constructor is private; reflection invokes it for coverage.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(CanonicalEncoder::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(CanonicalEncoder::class, $instance);
    }
}
