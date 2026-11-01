<?php

declare(strict_types = 1);

namespace Tests\Unit\Definitions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Definitions\FieldPath;

/**
 * Unit tests for the field path grammar: the paths it parses, the paths it
 * refuses and in what order, how a pattern matches a concrete path, which of
 * two paths is more specific, and when one may lie beneath another.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FieldPath::class)]
final class FieldPathTest extends TestCase
{
    /** @var string The message a path that is not clean text fails with. */
    private const string UNCLEAN_MESSAGE = 'A field path must be valid UTF-8 with no control characters.';

    /** @var string The message a path outside the grammar fails with. */
    private const string GRAMMAR_MESSAGE = 'A field path must be dot-separated keys, each non-empty, with `*` alone matching one key or list index.';

    /** @var string The message a path of more than eight segments fails with. */
    private const string LENGTH_MESSAGE = 'A field path must have at most 8 segments.';

    /** @var string The message a path with a reserved segment fails with. */
    private const string RESERVED_MESSAGE = 'A field path\'s segments may not begin `_audit`, which is reserved for the package\'s own metadata.';

    /**
     * Raise every PHP warning as an exception, so each path is also parsed,
     * matched and compared quietly: inside a Laravel application a warning
     * becomes an exception, which would turn a field rule into an error.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        set_error_handler(static function (int $level, string $message): never {
            throw new \ErrorException($message, 0, $level);
        });
    }

    /**
     * Restore the error handler after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        restore_error_handler();

        parent::tearDown();
    }

    /**
     * The deepest path is eight segments, and `*` is the wildcard.
     *
     * @return void
     */
    public function testTheLimitAndTheWildcard(): void
    {
        self::assertSame(8, FieldPath::MAX_SEGMENTS);
        self::assertSame('*', FieldPath::WILDCARD);
    }

    /**
     * Rows of `[path, segments]`: paths within the grammar and the segments
     * they parse to.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideValidPaths(): iterable
    {
        yield from [
            'one key'                      => ['amount', ['amount']],
            'nested keys'                  => ['card.holder', ['card', 'holder']],
            'a wildcard between keys'      => ['items.*.price', ['items', '*', 'price']],
            'a leading wildcard'           => ['*.email', ['*', 'email']],
            'a wildcard alone'             => ['*', ['*']],
            'eight segments'               => ['a.b.c.d.e.f.g.h', ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']],
            'a unicode key'                => ['naïve', ['naïve']],
            'a digit'                      => ['items.0', ['items', '0']],
            'a key containing audit'       => ['my_audit', ['my_audit']],
            'a key ending with the prefix' => ['meta.x_audit', ['meta', 'x_audit']],
            'a space inside a key'         => ['first name', ['first name']],
        ];
    }

    /**
     * A path within the grammar parses to its segments, each exactly as
     * written.
     *
     * @param  string  $path
     * @param  list<string>  $segments
     * @return void
     */
    #[DataProvider('provideValidPaths')]
    public function testParsesAValidPath(string $path, array $segments): void
    {
        self::assertSame($segments, FieldPath::parse($path));
    }

    /**
     * Rows of `[path]`: paths with an empty segment, or with `*` inside a
     * segment rather than as the whole of one.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedPaths(): iterable
    {
        yield from [
            'empty'                     => [''],
            'leading dot'               => ['.a'],
            'trailing dot'              => ['a.'],
            'empty middle segment'      => ['a..b'],
            'a dot alone'               => ['.'],
            'a trailing star in a key'  => ['a*'],
            'a leading star in a key'   => ['*a'],
            'two stars'                 => ['a.**'],
            'a star inside a later key' => ['a.b*c'],
        ];
    }

    /**
     * Each path outside the grammar is refused with the grammar message.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideMalformedPaths')]
    public function testRefusesAMalformedPath(string $path): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::GRAMMAR_MESSAGE);

        FieldPath::parse($path);
    }

    /**
     * A path of nine segments, one past the normaliser's depth, is refused.
     *
     * @return void
     */
    public function testRefusesMoreThanEightSegments(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::LENGTH_MESSAGE);

        FieldPath::parse('a.b.c.d.e.f.g.h.i');
    }

    /**
     * Rows of `[path]`: paths that cleaning would change, through invalid
     * UTF-8, a control character or a bidirectional control.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUncleanPaths(): iterable
    {
        yield from [
            'NUL'               => ["a\0b"],
            'line feed'         => ["a\nb"],
            'tab'               => ["a\tb"],
            'DEL'               => ["a\x7Fb"],
            'next line (C1)'    => ["a\u{0085}b"],
            'right-to-left'     => ["a\u{202E}b"],
            'left-to-right iso' => ["a\u{2066}b"],
            'invalid UTF-8'     => ["a\xC3"],
        ];
    }

    /**
     * Each path that is not already clean text is refused, never cleaned.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideUncleanPaths')]
    public function testRefusesAPathWithControlCharacters(string $path): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::UNCLEAN_MESSAGE);

        FieldPath::parse($path);
    }

    /**
     * Rows of `[path]`: paths with a segment beginning `_audit`, at the top or
     * further down.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReservedPaths(): iterable
    {
        yield from [
            'the metadata itself'    => ['_audit'],
            'beneath the metadata'   => ['_audit.note'],
            'a key beginning _audit' => ['_auditor'],
            'a nested reserved key'  => ['meta._audit'],
            'a reserved key last'    => ['a.b.c.d.e.f.g._audit'],
            'a prefixed nested key'  => ['meta._auditor'],
            'a prefixed key first'   => ['_auditlog.x'],
        ];
    }

    /**
     * Each path with a segment beginning `_audit` is refused, since those keys
     * belong to the package's own metadata.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideReservedPaths')]
    public function testRefusesAPathWithAReservedSegment(string $path): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::RESERVED_MESSAGE);

        FieldPath::parse($path);
    }

    /**
     * Rows of `[path, message]`: paths wrong in more than one way, and the
     * message of the check that comes first.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideOrderedRefusals(): iterable
    {
        yield from [
            'unclean and malformed'    => ["a..\0", self::UNCLEAN_MESSAGE],
            'unclean and reserved'     => ["_audit\n", self::UNCLEAN_MESSAGE],
            'malformed and too long'   => ['a..b.c.d.e.f.g.h.i', self::GRAMMAR_MESSAGE],
            'malformed after reserved' => ['_audit.a*', self::GRAMMAR_MESSAGE],
            'too long and reserved'    => ['_audit.b.c.d.e.f.g.h.i', self::LENGTH_MESSAGE],
        ];
    }

    /**
     * The checks run in order: clean text, then the grammar of every segment,
     * then the length, then the reserved prefix.
     *
     * @param  string  $path
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideOrderedRefusals')]
    public function testTheChecksApplyInOrder(string $path, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        FieldPath::parse($path);
    }

    /**
     * A list of segments has a wildcard only when one of them is exactly `*`.
     *
     * @return void
     */
    public function testHasWildcard(): void
    {
        self::assertTrue(FieldPath::hasWildcard(['a', '*']));
        self::assertTrue(FieldPath::hasWildcard(['*']));
        self::assertFalse(FieldPath::hasWildcard(['a', 'b']));
        self::assertFalse(FieldPath::hasWildcard([]));
    }

    /**
     * Rows of `[pattern, concrete path, whether it matches]`.
     *
     * @return iterable<string, array{0: list<string>, 1: list<int|string>, 2: bool}>
     */
    public static function provideMatches(): iterable
    {
        yield from [
            'exact'                              => [['a', 'b'], ['a', 'b'], true],
            'a wildcard on a key'                => [['a', '*'], ['a', 'b'], true],
            'a wildcard on an index'             => [['items', '*'], ['items', 0], true],
            'a literal digit on an index'        => [['items', '0'], ['items', 0], true],
            'a literal digit on a digit key'     => [['items', '0'], ['items', '0'], true],
            'a negative literal on an index'     => [['items', '-1'], ['items', -1], true],
            'a padded literal on an index'       => [['items', '00'], ['items', 0], false],
            'a padded literal on a padded key'   => [['items', '00'], ['items', '00'], true],
            'another index'                      => [['items', '1'], ['items', 0], false],
            'a wildcard on a key with a dot'     => [['*'], ['a.b'], true],
            'a literal pair on a key with a dot' => [['a', 'b'], ['a.b'], false],
            'a wildcard on the key *'            => [['*'], ['*'], true],
            'a shorter path'                     => [['a', 'b'], ['a'], false],
            'a longer path'                      => [['a'], ['a', 'b'], false],
            'one literal differs'                => [['a', 'b', 'c'], ['a', 'x', 'c'], false],
            'the last literal differs'           => [['a', 'b'], ['a', 'c'], false],
            'nothing against nothing'            => [[], [], true],
        ];
    }

    /**
     * A pattern matches a concrete path of its own length when each of its
     * segments is `*` or equals the decimal string of the key or index there.
     *
     * @param  list<string>  $pattern
     * @param  list<int|string>  $path
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('provideMatches')]
    public function testMatches(array $pattern, array $path, bool $expected): void
    {
        self::assertSame($expected, FieldPath::matches($pattern, $path));
    }

    /**
     * Rows of `[a, b, sign of the comparison]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideSpecificity(): iterable
    {
        yield from [
            'more segments'                   => ['a.b', 'a', 1],
            'fewer segments'                  => ['a', 'a.b', -1],
            'more segments, all wildcards'    => ['*.*.*', 'a.b', 1],
            'a literal first'                 => ['a.*', '*.b', 1],
            'a wildcard first'                => ['*.b', 'a.*', -1],
            'a literal last'                  => ['a.b', 'a.*', 1],
            'a wildcard last'                 => ['a.*', 'a.b', -1],
            'decided at the second position'  => ['a.b.*', 'a.*.c', 1],
            'the same pattern'                => ['a.*', 'a.*', 0],
            'all wildcards'                   => ['*.*', '*.*', 0],
            'different literals, equal shape' => ['a.b', 'c.d', 0],
        ];
    }

    /**
     * More segments is more specific; at equal length, the first position where
     * one has a literal and the other `*` decides, for the literal. Only the
     * sign is asserted.
     *
     * @param  string  $a
     * @param  string  $b
     * @param  int  $sign
     * @return void
     */
    #[DataProvider('provideSpecificity')]
    public function testComparesSpecificity(string $a, string $b, int $sign): void
    {
        self::assertSame($sign, FieldPath::compare(FieldPath::parse($a), FieldPath::parse($b)) <=> 0);
    }

    /**
     * Rows of `[path, ancestor, whether it may lie beneath]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: bool}>
     */
    public static function provideAncestry(): iterable
    {
        yield from [
            'a child'                        => ['a.b', 'a', true],
            'a grandchild'                   => ['a.b.c', 'a', true],
            'beneath a wildcard ancestor'    => ['a.b.c', 'a.*', true],
            'a wildcard over a literal'      => ['*.b', 'a', true],
            'a wildcard ancestor'            => ['a.b', '*', true],
            'wildcards on both sides'        => ['*.b.c', 'a.*', true],
            'another branch'                 => ['a.b', 'b', false],
            'the same path'                  => ['a', 'a', false],
            'the same length with wildcards' => ['a.*', '*.b', false],
            'a longer ancestor'              => ['a', 'a.b', false],
            'a later segment differs'        => ['a.b.c', 'a.x', false],
        ];
    }

    /**
     * A path may lie beneath an ancestor of fewer segments whose every segment
     * equals the path's at that position, or where either is `*`.
     *
     * @param  string  $path
     * @param  string  $ancestor
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('provideAncestry')]
    public function testMayBeBeneath(string $path, string $ancestor, bool $expected): void
    {
        self::assertSame($expected, FieldPath::mayBeBeneath(FieldPath::parse($path), FieldPath::parse($ancestor)));
    }

    /**
     * `FieldPath` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(FieldPath::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(FieldPath::class, $instance);
    }
}
