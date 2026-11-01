<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * Unit tests for the text sanitiser: the text it keeps, the invalid UTF-8 it
 * repairs byte by byte, the controls it turns into spaces or removes, the caps
 * it cuts without splitting a character, and what it counts as clean.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TextSanitizer::class)]
final class TextSanitizerTest extends TestCase
{
    /** @var string U+FFFD, the replacement character. */
    private const string REPLACEMENT = "\u{FFFD}";

    /**
     * Rows of `[text]`: text that is already safe to store, including the
     * characters that look like controls but are not.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideKeptText(): iterable
    {
        yield from [
            'ASCII'                  => ['invoice.approved by app:ticket-123'],
            'empty'                  => [''],
            'a four-byte emoji'      => ['😀'],
            'a combining sequence'   => ["e\u{0301}"],
            'a ZWJ family'           => ["👩\u{200D}👩\u{200D}👧"],
            'a zero-width space'     => ["a\u{200B}b"],
            'a byte order mark'      => ["\u{FEFF}a"],
            'a left-to-right mark'   => ["a\u{200E}b"],
            'a right-to-left mark'   => ["a\u{200F}b"],
            'CJK'                    => ['漢字'],
            'a space'                => [' '],
            'a no-break space'       => ["a\u{00A0}b"],
            'the last ASCII printed' => ['~'],
            'Latin-1 accented'       => ['é'],
            'astral plane maximum'   => ["\u{10FFFD}"],
        ];
    }

    /**
     * Each text that is already safe comes back unchanged.
     *
     * @param  string  $text
     * @return void
     */
    #[DataProvider('provideKeptText')]
    public function testKeepsText(string $text): void
    {
        self::assertSame($text, TextSanitizer::clean($text));
    }

    /**
     * Rows of `[text, cleaned]`: text that is not well-formed UTF-8, and what
     * it becomes, one replacement character for each offending byte.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideInvalidUtf8(): iterable
    {
        yield from [
            'a lone continuation byte'    => ["\x80", self::REPLACEMENT],
            'a truncated sequence'        => ["\xC3", self::REPLACEMENT],
            'an overlong form'            => ["\xC0\xAF", str_repeat(self::REPLACEMENT, 2)],
            'a surrogate'                 => ["\xED\xA0\x80", str_repeat(self::REPLACEMENT, 3)],
            'above U+10FFFF'              => ["\xF4\x90\x80\x80", str_repeat(self::REPLACEMENT, 4)],
            'between valid characters'    => ["a\xFFb", 'a' . self::REPLACEMENT . 'b'],
            'beside a valid multibyte'    => ["é\xFF😀", 'é' . self::REPLACEMENT . '😀'],
            'a truncated four-byte'       => ["\xF0\x9F\x98", str_repeat(self::REPLACEMENT, 3)],
            'a three-byte overlong'       => ["\xE0\x80\xAF", str_repeat(self::REPLACEMENT, 3)],
            'a four-byte overlong'        => ["\xF0\x80\x80\xAF", str_repeat(self::REPLACEMENT, 4)],
            'a repaired control stripped' => ["\xFF\0", self::REPLACEMENT],
        ];
    }

    /**
     * Each malformed byte becomes U+FFFD, the bytes of every well-formed
     * sequence around it are kept, and the repaired text is then cleaned like
     * any other.
     *
     * @param  string  $text
     * @param  string  $cleaned
     * @return void
     */
    #[DataProvider('provideInvalidUtf8')]
    public function testRepairsInvalidUtf8(string $text, string $cleaned): void
    {
        self::assertSame($cleaned, TextSanitizer::clean($text));
    }

    /**
     * Rows of `[text, cleaned]`: text holding a control character other than
     * the whitespace controls, or a bidirectional control.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideControls(): iterable
    {
        yield from [
            'NUL'                         => ["a\0b", 'ab'],
            'BEL'                         => ["a\x07b", 'ab'],
            'an escape sequence'          => ["\e[31mred", '[31mred'],
            'U+001F'                      => ["a\x1Fb", 'ab'],
            'DEL'                         => ["a\x7Fb", 'ab'],
            'U+0080'                      => ["a\u{0080}b", 'ab'],
            'U+0085'                      => ["a\u{0085}b", 'ab'],
            'U+009B'                      => ["a\u{009B}b", 'ab'],
            'U+009F'                      => ["a\u{009F}b", 'ab'],
            'left-to-right embedding'     => ["a\u{202A}b", 'ab'],
            'right-to-left embedding'     => ["a\u{202B}b", 'ab'],
            'pop directional formatting'  => ["a\u{202C}b", 'ab'],
            'left-to-right override'      => ["a\u{202D}b", 'ab'],
            'right-to-left override'      => ["a\u{202E}b", 'ab'],
            'left-to-right isolate'       => ["a\u{2066}b", 'ab'],
            'right-to-left isolate'       => ["a\u{2067}b", 'ab'],
            'first strong isolate'        => ["a\u{2068}b", 'ab'],
            'pop directional isolate'     => ["a\u{2069}b", 'ab'],
            'every control in one string' => ["\0a\u{202E}b\u{0085}c\x7F", 'abc'],
        ];
    }

    /**
     * Each control and bidirectional control is removed, and the text around it
     * is kept.
     *
     * @param  string  $text
     * @param  string  $cleaned
     * @return void
     */
    #[DataProvider('provideControls')]
    public function testStripsControlsAndBidiControls(string $text, string $cleaned): void
    {
        self::assertSame($cleaned, TextSanitizer::clean($text));
    }

    /**
     * Rows of `[text, cleaned]`: text holding the whitespace controls U+0009 to
     * U+000D.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideWhitespaceControls(): iterable
    {
        yield from [
            'a line feed'      => ["a\nb", 'a b'],
            'CRLF'             => ["a\r\nb", 'a  b'],
            'a carriage'       => ["a\rb", 'a b'],
            'a tab'            => ["a\tb", 'a b'],
            'a vertical tab'   => ["a\vb", 'a b'],
            'a form feed'      => ["a\fb", 'a b'],
            'each in sequence' => ["\t\n\v\f\r", '     '],
        ];
    }

    /**
     * Each whitespace control becomes one space, so words either side of it are
     * never glued together.
     *
     * @param  string  $text
     * @param  string  $cleaned
     * @return void
     */
    #[DataProvider('provideWhitespaceControls')]
    public function testWhitespaceControlsBecomeSpaces(string $text, string $cleaned): void
    {
        self::assertSame($cleaned, TextSanitizer::clean($text));
    }

    /**
     * A cap cuts at a character boundary at or below it, never through a
     * character; text exactly at the cap is kept whole, which protects against
     * an off-by-one mutation of the cut.
     *
     * @return void
     */
    public function testCutsAtAByteCapWithoutSplittingACharacter(): void
    {
        self::assertSame('aé', TextSanitizer::cut('aé😀', 4));
        self::assertSame('😀', TextSanitizer::cut('😀😀', 5));
        self::assertSame('abc', TextSanitizer::cut('abc', 3));
        self::assertSame('ab', TextSanitizer::cut('abc', 2));
        self::assertSame('a', TextSanitizer::cut('a', 1));
        self::assertSame('', TextSanitizer::cut('é', 1));
    }

    /**
     * A cap below one byte is refused rather than cutting to nothing.
     *
     * @return void
     */
    public function testRefusesACapBelowOneByte(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A cap must be at least one byte.');

        TextSanitizer::cut('a', 0);
    }

    /**
     * Cleaning also refuses a cap below one byte.
     *
     * @return void
     */
    public function testCleanRefusesACapBelowOneByte(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A cap must be at least one byte.');

        TextSanitizer::clean('a', -1);
    }

    /**
     * Text is cleaned before it is cut, so a removed control does not count
     * against the cap, and no cap leaves the text at any length.
     *
     * @return void
     */
    public function testCleansBeforeCutting(): void
    {
        self::assertSame('aaaaa', TextSanitizer::clean("\0" . str_repeat('a', 10), 5));
        self::assertSame(str_repeat('a', 10), TextSanitizer::clean(str_repeat('a', 10)));
    }

    /**
     * Rows of `[text, whether it is clean]`.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideCleanness(): iterable
    {
        yield from [
            'ASCII'                    => ['abc', true],
            'empty'                    => ['', true],
            'a line feed'              => ["a\nb", false],
            'invalid UTF-8'            => ["\xC3", false],
            'a right-to-left override' => ["\u{202E}", false],
            'a right-to-left mark'     => ["a\u{200F}b", true],
            'a left-to-right mark'     => ["a\u{200E}b", true],
            'a four-byte emoji'        => ['😀', true],
            'a replacement already'    => [self::REPLACEMENT, true],
            'a NUL'                    => ["a\0", false],
            'a combining sequence'     => ["e\u{0301}", true],
        ];
    }

    /**
     * Text is clean exactly when cleaning would leave it unchanged.
     *
     * @param  string  $text
     * @param  bool  $clean
     * @return void
     */
    #[DataProvider('provideCleanness')]
    public function testIsCleanOnlyForTextCleaningWouldNotChange(string $text, bool $clean): void
    {
        self::assertSame($clean, TextSanitizer::isClean($text));
    }

    /**
     * `TextSanitizer` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(TextSanitizer::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(TextSanitizer::class, $instance);
    }
}
