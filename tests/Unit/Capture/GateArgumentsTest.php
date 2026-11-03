<?php

declare(strict_types = 1);

namespace Tests\Unit\Capture;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\GateArguments;
use Tests\Unit\Stubs\Enums\StubColour;
use Tests\Unit\Stubs\StubDocument;

/**
 * Unit tests for the arguments a Gate denial keeps: a model as its reference, a
 * class name as itself without a leading backslash, the marker for anything
 * else, at most eight kept and every one counted, and nothing converted to a
 * string, serialised or traversed on the way.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GateArguments::class)]
final class GateArgumentsTest extends TestCase
{
    /** @var string The namespace the aliases a test makes are declared in. */
    private const string ALIAS_PREFIX = 'Tests\Unit\Capture\\';

    /**
     * `GateArguments` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(GateArguments::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(GateArguments::class, $instance);
    }

    /**
     * A model is kept as its reference alone, the type and the id, and none of
     * its other attributes.
     *
     * @return void
     */
    public function testAModelBecomesItsReference(): void
    {
        $document = (new StubDocument)->forceFill(['id' => 'doc-1', 'title' => 'Quarterly figures']);

        self::assertSame([['type' => StubDocument::class, 'id' => 'doc-1']], GateArguments::of([$document]));
    }

    /**
     * A class name is kept as itself, as the class an ability to create is
     * checked against, even one with the longest name a reference type keeps.
     *
     * @return void
     */
    public function testAClassStringIsKept(): void
    {
        $longest = self::aliasOfLength(191);

        self::assertSame([StubDocument::class, \ArrayObject::class, $longest], GateArguments::of([StubDocument::class, \ArrayObject::class, $longest]));
    }

    /**
     * A class name written with its leading backslash is kept without it, and
     * one backslash only is dropped: two are no class name.
     *
     * @return void
     */
    public function testALeadingBackslashIsDropped(): void
    {
        self::assertSame([StubDocument::class, GateArguments::MARKER], GateArguments::of(['\\' . StubDocument::class, '\\\\' . StubDocument::class]));
    }

    /**
     * A class name longer than a reference type keeps is the marker, even when
     * the class exists, so the length is judged on its own; the leading
     * backslash is not counted.
     *
     * @return void
     */
    public function testAClassNameLongerThanAReferenceTypeIsTheMarker(): void
    {
        $longest = self::aliasOfLength(191);
        $over    = self::aliasOfLength(192);

        self::assertTrue(class_exists($over));
        self::assertSame([GateArguments::MARKER, $longest], GateArguments::of([$over, '\\' . $longest]));
    }

    /**
     * Rows of `[argument]`: arguments that are neither a model with a key nor
     * the name of a class that exists.
     *
     * @return iterable<string, array{0: \Closure(): (array<int, int>|int|object|string|null)}>
     */
    public static function provideMarkedArguments(): iterable
    {
        yield from [
            'a plain string'                      => [static fn (): string => 'Quarterly figures'],
            'an empty string'                     => [static fn (): string => ''],
            'a string of class grammar, no class' => [static fn (): string => 'App\Models\Missing'],
            'a 192-character class-like string'   => [static fn (): string => 'App\\' . str_repeat('A', 188)],
            'an interface name'                   => [static fn (): string => \Stringable::class],
            'a path'                              => [static fn (): string => '../../etc/passwd'],
            'a trailing separator'                => [static fn (): string => StubDocument::class . '\\'],
            'a name starting with a digit'        => [static fn (): string => '1Stub'],
            'a class name with a line feed'       => [static fn (): string => StubDocument::class . "\n"],
            'an integer'                          => [static fn (): int => 42],
            'an array'                            => [static fn (): array => [42]],
            'a stringable whose string fails'     => [static fn (): object => self::failingStringable()],
            'a closure'                           => [static fn (): \Closure => static fn (): string => StubDocument::class],
            'an unsaved model'                    => [static fn (): object => new StubDocument],
            'an enum case'                        => [static fn (): object => StubColour::RED],
            'null'                                => [static fn (): null => null],
        ];
    }

    /**
     * Each argument that is neither a model with a key nor a class name is the
     * marker.
     *
     * @param  \Closure(): (array<int, int>|int|object|string|null)  $argument
     * @return void
     */
    #[DataProvider('provideMarkedArguments')]
    public function testAnythingElseIsTheMarker(\Closure $argument): void
    {
        self::assertSame([GateArguments::MARKER], GateArguments::of([$argument()]));
    }

    /**
     * Only the first eight arguments are kept, in order, whatever their keys,
     * and the count is of all ten.
     *
     * @return void
     */
    public function testAtMostEightAreKept(): void
    {
        $arguments = ['first' => StubDocument::class, 'second' => 2, 3, 4, 5, 6, 7, 'eighth' => \ArrayObject::class, 9 => StubDocument::class, 10 => StubDocument::class];

        $kept = GateArguments::of($arguments);

        self::assertCount(GateArguments::MAX_ARGUMENTS, $kept);
        self::assertSame([StubDocument::class, ...array_fill(0, 6, GateArguments::MARKER), \ArrayObject::class], $kept);
        self::assertSame(10, GateArguments::count($arguments));
    }

    /**
     * The count is of every argument given, kept, marked or past the eighth,
     * and none is no argument.
     *
     * @return void
     */
    public function testTheCountIsOfEveryArgument(): void
    {
        self::assertSame(0, GateArguments::count([]));
        self::assertSame([], GateArguments::of([]));
        self::assertSame(1, GateArguments::count([null]));
        self::assertSame(3, GateArguments::count(['a' => [1, 2, 3], 'b' => null, 'c' => new StubDocument]));
        self::assertSame(20, GateArguments::count(array_fill(0, 20, StubDocument::class)));
    }

    /**
     * No argument is cast to a string, serialised, encoded or traversed: an
     * object that fails the test on each of those is only marked.
     *
     * @return void
     */
    public function testNothingIsConvertedToAString(): void
    {
        $failing = new class implements \IteratorAggregate, \JsonSerializable, \Stringable {
            /**
             * Fail the test: nothing traverses an argument.
             *
             * @return \Traversable<int, int>
             */
            #[\Override]
            public function getIterator(): \Traversable
            {
                TestCase::fail('An argument was traversed.');
            }

            /**
             * Fail the test: nothing encodes an argument.
             *
             * @return never
             */
            #[\Override]
            public function jsonSerialize(): never
            {
                TestCase::fail('An argument was encoded.');
            }

            /**
             * Fail the test: nothing casts an argument to a string.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                TestCase::fail('An argument was cast to a string.');
            }

            /**
             * Fail the test: nothing serialises an argument.
             *
             * @return array<string, string>
             */
            public function __serialize(): array
            {
                TestCase::fail('An argument was serialised.');
            }
        };

        self::assertSame([GateArguments::MARKER, GateArguments::MARKER], GateArguments::of([$failing, self::failingStringable()]));
    }

    /**
     * A stringable object whose string form fails the test.
     *
     * @return \Stringable
     */
    private static function failingStringable(): \Stringable
    {
        return new class implements \Stringable {
            /**
             * Fail the test: nothing casts an argument to a string.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                TestCase::fail('An argument was cast to a string.');
            }
        };
    }

    /**
     * The name of an alias of a stub class, made once, of exactly the length
     * given, so a class of that long a name exists.
     *
     * @param  int  $length
     * @return string
     */
    private static function aliasOfLength(int $length): string
    {
        $alias = self::ALIAS_PREFIX . str_repeat('A', $length - strlen(self::ALIAS_PREFIX));

        if (!class_exists($alias, false)) {
            class_alias(StubDocument::class, $alias);
        }

        return $alias;
    }
}
