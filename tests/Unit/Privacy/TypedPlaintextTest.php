<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\TypedPlaintext;

/**
 * Unit tests for typed plaintext: every type as its canonical JSON, a string
 * apart from the boolean it spells, a string cut on a character boundary to the
 * longest prefix whose encoding fits, any other value over the limit dropped,
 * and decoding that gives every type back and refuses anything else without
 * naming it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TypedPlaintext::class)]
final class TypedPlaintextTest extends TestCase
{
    /** @var string Why a plaintext is refused. */
    private const string MALFORMED = 'A typed plaintext must be the JSON of a value that is not a float.';

    /**
     * Rows of `[value, its encoding]`: a value of every type the package
     * stores.
     *
     * @return iterable<string, array{0: array<array-key, int|string>|bool|int|\stdClass|string|null, 1: string}>
     */
    public static function provideValues(): iterable
    {
        yield from [
            'null'                => [null, 'null'],
            'true'                => [true, 'true'],
            'false'               => [false, 'false'],
            'zero'                => [0, '0'],
            'a negative integer'  => [-42, '-42'],
            'a string'            => ['4242', '"4242"'],
            'an empty string'     => ['', '""'],
            'a string of unicode' => ['café', '"café"'],
            'a slash'             => ['a/b', '"a/b"'],
            'a quote'             => ['a"b', '"a\"b"'],
            'a list'              => [[1, 'a'], '[1,"a"]'],
            'a map'               => [['b' => 1, 'a' => 'x'], '{"a":"x","b":1}'],
            'an empty list'       => [[], '[]'],
            'an empty object'     => [new \stdClass, '{}'],
        ];
    }

    /**
     * Each value is its canonical JSON: a string a JSON string, a map with its
     * keys sorted, and nothing escaped that JSON leaves alone.
     *
     * @param  array<array-key, int|string>|bool|int|\stdClass|string|null  $value
     * @param  string  $encoded
     * @return void
     */
    #[DataProvider('provideValues')]
    public function testEveryTypeEncodesAsItsCanonicalJson(array|bool|int|\stdClass|string|null $value, string $encoded): void
    {
        self::assertSame($encoded, TypedPlaintext::encode($value));
        self::assertSame(1024, TypedPlaintext::MAX_BYTES);
    }

    /**
     * The string `"true"` and the boolean `true` are sealed apart and read back
     * as what they were, as are a digit string and its integer and the string
     * `"null"` and `null`.
     *
     * @return void
     */
    public function testAStringTrueIsNotTheBooleanTrue(): void
    {
        self::assertSame('"true"', TypedPlaintext::encode('true'));
        self::assertSame('true', TypedPlaintext::encode(true));
        self::assertSame('"7"', TypedPlaintext::encode('7'));
        self::assertSame('7', TypedPlaintext::encode(7));
        self::assertSame('"null"', TypedPlaintext::encode('null'));

        self::assertSame('true', TypedPlaintext::decode('"true"'));
        self::assertTrue(TypedPlaintext::decode('true'));
        self::assertSame('7', TypedPlaintext::decode('"7"'));
        self::assertSame(7, TypedPlaintext::decode('7'));
        self::assertNull(TypedPlaintext::decode('null'));
    }

    /**
     * Rows of `[string, the encoding it is cut to]`: strings over the limit, of
     * characters that encode to one, two and six bytes, and a mixture whose
     * first cut overshoots.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideLongStrings(): iterable
    {
        yield from [
            'one byte over'            => [str_repeat('a', 1023), '"' . str_repeat('a', 1022) . '"'],
            'far over'                 => [str_repeat('a', 5000), '"' . str_repeat('a', 1022) . '"'],
            'quotes, two bytes each'   => [str_repeat('"', 600), '"' . str_repeat('\"', 511) . '"'],
            'controls, six bytes each' => [str_repeat("\x01", 600), '"' . str_repeat('\u0001', 170) . '"'],
            'letters, then controls'   => [str_repeat('a', 1000) . str_repeat("\x01", 100), '"' . str_repeat('a', 1000) . str_repeat('\u0001', 3) . '"'],
            'letters, then a quote'    => [str_repeat('a', 1021) . '"b', '"' . str_repeat('a', 1021) . '"'],
        ];
    }

    /**
     * A string over the limit is cut to the longest prefix whose encoding fits,
     * measured after encoding: one more character of the string would not fit.
     *
     * @param  string  $value
     * @param  string  $encoded
     * @return void
     */
    #[DataProvider('provideLongStrings')]
    public function testAStringIsCutSoItsEncodingFits(string $value, string $encoded): void
    {
        $cut = (string) TypedPlaintext::encode($value);

        self::assertSame($encoded, $cut);
        self::assertLessThanOrEqual(TypedPlaintext::MAX_BYTES, strlen($cut));

        $prefix = json_decode($cut, false, 2, JSON_THROW_ON_ERROR);

        self::assertIsString($prefix);

        $longer = mb_substr($value, 0, mb_strlen($prefix) + 1);

        self::assertStringStartsWith($prefix, $value);
        self::assertGreaterThan(TypedPlaintext::MAX_BYTES, strlen((string) json_encode($longer, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)));
    }

    /**
     * A string whose encoding is exactly the limit is kept whole.
     *
     * @return void
     */
    public function testAStringWhoseEncodingIsTheLimitIsKeptWhole(): void
    {
        $value = str_repeat('a', 1022);

        self::assertSame('"' . $value . '"', TypedPlaintext::encode($value));
    }

    /**
     * Rows of `[character]`: characters of two, three and four bytes.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideWideCharacters(): iterable
    {
        yield from [
            'two bytes'   => ['é'],
            'three bytes' => ['€'],
            'four bytes'  => ["\u{1F600}"],
        ];
    }

    /**
     * A cut never splits a character: the cut string is valid UTF-8, made of
     * whole characters, as long as fits.
     *
     * @param  string  $character
     * @return void
     */
    #[DataProvider('provideWideCharacters')]
    public function testACutNeverSplitsACharacter(string $character): void
    {
        $cut   = (string) TypedPlaintext::encode(str_repeat($character, 1000));
        $whole = intdiv(1022, strlen($character));

        self::assertTrue(mb_check_encoding($cut, 'UTF-8'));
        self::assertSame('"' . str_repeat($character, $whole) . '"', $cut);
    }

    /**
     * Any value but a string whose encoding passes the limit is `null`, and one
     * whose encoding is the limit is kept: a list of 511 ones encodes to 1023
     * bytes and one of 512 to 1025.
     *
     * @return void
     */
    public function testAnyOtherValueOverTheLimitIsNull(): void
    {
        self::assertSame(1023, strlen((string) TypedPlaintext::encode(array_fill(0, 511, 1))));
        self::assertNull(TypedPlaintext::encode(array_fill(0, 512, 1)));
        self::assertNull(TypedPlaintext::encode(['key' => str_repeat('a', 1100)]));
        self::assertNull(TypedPlaintext::encode([str_repeat('a', 1100)]));
    }

    /**
     * A value with no canonical encoding is refused as the encoder refuses it.
     *
     * @return void
     */
    public function testAValueWithNoCanonicalEncodingIsRefused(): void
    {
        $this->expectException(\UnexpectedValueException::class);

        TypedPlaintext::encode(1.5);
    }

    /**
     * A string that is not UTF-8 is refused before it could be cut, whatever
     * its length.
     *
     * @return void
     */
    public function testALongStringThatIsNotUtf8IsRefused(): void
    {
        $this->expectException(\UnexpectedValueException::class);

        TypedPlaintext::encode(str_repeat("\xFF", 2000));
    }

    /**
     * Rows of `[plaintext, the value it decodes to]`: the encoding of every
     * type, a map read back as an associative array.
     *
     * @return iterable<string, array{0: string, 1: array<array-key, int|list<int>|string>|bool|int|string|null}>
     */
    public static function provideDecodedValues(): iterable
    {
        yield from [
            'null'          => ['null', null],
            'true'          => ['true', true],
            'false'         => ['false', false],
            'an integer'    => ['-42', -42],
            'a string'      => ['"café"', 'café'],
            'a list'        => ['[1,"a"]', [1, 'a']],
            'a map'         => ['{"a":"x","b":[1]}', ['a' => 'x', 'b' => [1]]],
            'an empty list' => ['[]', []],
        ];
    }

    /**
     * Decoding the encoding of each type gives the value back with its type.
     *
     * @param  string  $plaintext
     * @param  array<array-key, int|list<int>|string>|bool|int|string|null  $value
     * @return void
     */
    #[DataProvider('provideDecodedValues')]
    public function testDecodeRoundTripsEveryType(string $plaintext, array|bool|int|string|null $value): void
    {
        self::assertSame($value, TypedPlaintext::decode($plaintext));
        self::assertSame($plaintext, TypedPlaintext::encode(TypedPlaintext::decode($plaintext)));
    }

    /**
     * Rows of `[plaintext]`: text that is not JSON, JSON of a float, and JSON
     * nested deeper than 64 levels.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedPlaintexts(): iterable
    {
        yield from [
            'empty'              => [''],
            'not JSON'           => ['secret-text'],
            'a cut-off map'      => ['{"secret":'],
            'a float'            => ['1.5'],
            'an exponent'        => ['1e3'],
            'not UTF-8'          => ["\"\xFF\""],
            'nested 65 levels'   => [str_repeat('[', 64) . '1' . str_repeat(']', 64)],
            'two values'         => ['1 2'],
            'a trailing comma'   => ['[1,]'],
            'a single quote'     => ['\'secret\''],
            'an unquoted string' => ['secret'],
        ];
    }

    /**
     * Each malformed plaintext is refused, and the refusal names nothing of the
     * text.
     *
     * @param  string  $plaintext
     * @return void
     */
    #[DataProvider('provideMalformedPlaintexts')]
    public function testDecodeRefusesMalformedText(string $plaintext): void
    {
        try {
            TypedPlaintext::decode($plaintext);

            self::fail('Expected the plaintext to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame(self::MALFORMED, $exception->getMessage());
            self::assertNull($exception->getPrevious());
        }
    }

    /**
     * A plaintext nested exactly 64 levels deep is read.
     *
     * @return void
     */
    public function testDecodeReadsSixtyFourLevels(): void
    {
        self::assertIsArray(TypedPlaintext::decode(str_repeat('[', 63) . '1' . str_repeat(']', 63)));
    }

    /**
     * `TypedPlaintext` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(TypedPlaintext::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(TypedPlaintext::class, $instance);
    }
}
