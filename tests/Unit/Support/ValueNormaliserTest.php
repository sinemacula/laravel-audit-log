<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Collection;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Ramsey\Uuid\Codec\StringCodec;
use Ramsey\Uuid\Uuid as RamseyUuid;
use Ramsey\Uuid\UuidFactory;
use Ramsey\Uuid\UuidInterface;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\Normalised;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;
use Symfony\Component\Uid\Ulid;
use Symfony\Component\Uid\Uuid;
use Tests\Unit\Stubs\Enums\StubColour;
use Tests\Unit\Stubs\Enums\StubPriority;
use Tests\Unit\Stubs\Enums\StubSuit;
use Tests\Unit\Stubs\StubDocument;
use Tests\Unit\Stubs\StubSealedUser;
use Tests\Unit\Stubs\StubUid;
use Tests\Unit\Stubs\StubUser;

/**
 * Unit tests for the value normaliser: each of its rules in order, models
 * first, the safe integer range, the shortest round-trip float format under any
 * precision setting, the depth bound, and the bounded diagnostics of keys that
 * collide once cleaned.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ValueNormaliser::class)]
#[CoversClass(Normalised::class)]
final class ValueNormaliserTest extends TestCase
{
    /** @var string The `precision` setting before the test. */
    private string $precision = '';

    /** @var string The `serialize_precision` setting before the test. */
    private string $serializePrecision = '';

    /**
     * Remember the precision settings a test may change.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->precision          = ini_get('precision');
        $this->serializePrecision = (string) ini_get('serialize_precision');
    }

    /**
     * Restore the precision settings and clear the morph map after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        ini_set('precision', $this->precision);
        ini_set('serialize_precision', $this->serializePrecision);
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * A model is normalised without its other attributes being read, without
     * being turned into an array or JSON or cast to a string, and without a
     * query, each of which this model refuses by throwing.
     *
     * @return void
     */
    public function testAModelIsNeverSerialisedOrQueried(): void
    {
        $user = (new StubSealedUser)->forceFill(['id' => 1, 'email' => 'someone@example.com']);

        self::assertSame(['type' => StubSealedUser::class, 'id' => '1'], ValueNormaliser::normalise($user)->value);
    }

    /**
     * A model becomes its reference and never carries its attributes, though
     * its `__toString()` and `toJson()` would serialise them.
     *
     * @return void
     */
    public function testAModelBecomesItsReferenceNeverItsAttributes(): void
    {
        $user = (new StubUser)->forceFill(['id' => 1, 'password' => 'hunter2']);

        $normalised = ValueNormaliser::normalise($user);

        self::assertSame(['type' => StubUser::class, 'id' => '1'], $normalised->value);
        self::assertStringNotContainsString('hunter2', (string) json_encode($normalised->value));
    }

    /**
     * A model is referred to by its morph alias where the map names it.
     *
     * @return void
     */
    public function testAModelUsesItsMorphAlias(): void
    {
        Relation::morphMap(['user' => StubUser::class]);

        self::assertSame(['type' => 'user', 'id' => '1'], ValueNormaliser::normalise((new StubUser)->forceFill(['id' => 1]))->value);
    }

    /**
     * An unsaved model cannot be referred to, so it is refused rather than
     * stored without a key.
     *
     * @return void
     */
    public function testAnUnsavedModelIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A model must have a key before it can be referenced; save it first.');

        ValueNormaliser::normalise(new StubUser);
    }

    /**
     * A reference becomes its type and id pair.
     *
     * @return void
     */
    public function testAReferenceBecomesItsShape(): void
    {
        self::assertSame(['type' => 'invoice', 'id' => '42'], ValueNormaliser::normalise(Reference::of('invoice', 42))->value);
    }

    /**
     * A backed enum becomes its value, a string or an integer.
     *
     * @return void
     */
    public function testABackedEnumBecomesItsValue(): void
    {
        self::assertSame('red', ValueNormaliser::normalise(StubColour::RED)->value);
        self::assertSame(1, ValueNormaliser::normalise(StubPriority::HIGH)->value);
    }

    /**
     * A unit enum becomes its name.
     *
     * @return void
     */
    public function testAUnitEnumBecomesItsName(): void
    {
        self::assertSame('HEARTS', ValueNormaliser::normalise(StubSuit::HEARTS)->value);
    }

    /**
     * Rows of `[date, the ISO string]`: immutable and mutable dates, in UTC and
     * away from it.
     *
     * @return iterable<string, array{0: \DateTimeInterface, 1: string}>
     */
    public static function provideDates(): iterable
    {
        yield from [
            'UTC with microseconds' => [new \DateTimeImmutable('2026-11-01 09:30:15.123456', new \DateTimeZone('UTC')), '2026-11-01T09:30:15.123456Z'],
            'a mutable date'        => [new \DateTime('2026-11-01 09:30:15', new \DateTimeZone('UTC')), '2026-11-01T09:30:15.000000Z'],
            'Auckland'              => [CarbonImmutable::parse('2026-11-01 22:30:15.5', 'Pacific/Auckland'), '2026-11-01T09:30:15.500000Z'],
            'an offset'             => [new \DateTimeImmutable('2026-11-01T04:30:15-05:00'), '2026-11-01T09:30:15.000000Z'],
        ];
    }

    /**
     * Each date becomes the same instant as ISO-8601 in UTC with microseconds,
     * and a mutable date is left in its own zone.
     *
     * @param  \DateTimeInterface  $date
     * @param  string  $iso
     * @return void
     */
    #[DataProvider('provideDates')]
    public function testADateBecomesUtcWithMicroseconds(\DateTimeInterface $date, string $iso): void
    {
        $zone = $date->getTimezone()->getName();

        self::assertSame($iso, ValueNormaliser::normalise($date)->value);
        self::assertSame($zone, $date->getTimezone()->getName());
    }

    /**
     * A ramsey UUID becomes its canonical string.
     *
     * @return void
     */
    public function testARamseyUuidBecomesItsString(): void
    {
        $uuid = RamseyUuid::uuid4();

        self::assertSame($uuid->toString(), ValueNormaliser::normalise($uuid)->value);
    }

    /**
     * A Symfony UUID or ULID becomes its canonical string.
     *
     * @return void
     */
    public function testASymfonyUidBecomesItsString(): void
    {
        $uuid = Uuid::v7();
        $ulid = new Ulid;

        self::assertSame($uuid->toRfc4122(), ValueNormaliser::normalise($uuid)->value);
        self::assertSame($ulid->toBase32(), ValueNormaliser::normalise($ulid)->value);
    }

    /**
     * A UUID of any class but its library's own, a named subclass or an
     * anonymous one, can write anything, so it is marked without its methods
     * being called.
     *
     * @return void
     */
    public function testAUidOfAnotherClassIsNeverCalled(): void
    {
        $uid       = Uuid::v7()->toRfc4122();
        $anonymous = new class ($uid) extends Uuid {
            /**
             * Fail the test if called.
             *
             * @return never
             *
             * @throws \LogicException
             */
            #[\Override]
            public function __toString(): never
            {
                throw new \LogicException('The normaliser called __toString().');
            }
        };

        self::assertSame(ValueNormaliser::UNSERIALISABLE, ValueNormaliser::normalise(new StubUid($uid))->value);
        self::assertSame(ValueNormaliser::UNSERIALISABLE, ValueNormaliser::normalise($anonymous)->value);
    }

    /**
     * A UUID of its library's own class still writes through the codec its
     * factory was given, which may be the application's, so its string is
     * cleaned and always encodes.
     *
     * @return void
     */
    public function testAUidsStringIsSanitised(): void
    {
        $factory = new UuidFactory;

        $factory->setCodec(new class ($factory->getUuidBuilder()) extends StringCodec {
            /**
             * Write a string that is not clean text.
             *
             * @param  \Ramsey\Uuid\UuidInterface  $uuid
             * @return non-empty-string
             */
            #[\Override]
            public function encode(UuidInterface $uuid): string
            {
                return "x\0\xC3\u{202E}y";
            }
        });

        $value = ValueNormaliser::normalise($factory->uuid4())->value;

        self::assertSame("x\u{FFFD}y", $value);
        self::assertSame('"x\ufffdy"', json_encode($value, JSON_THROW_ON_ERROR));
    }

    /**
     * Rows of `[value]`: booleans, `null` and clean strings.
     *
     * @return iterable<string, array{0: bool|string|null}>
     */
    public static function provideScalars(): iterable
    {
        yield from [
            'true'         => [true],
            'false'        => [false],
            'null'         => [null],
            'a string'     => ['invoice.approved'],
            'empty'        => [''],
            'an emoji'     => ['😀'],
            'a digit text' => ['42'],
        ];
    }

    /**
     * Booleans, `null` and clean strings stay exactly as they are.
     *
     * @param  bool|string|null  $value
     * @return void
     */
    #[DataProvider('provideScalars')]
    public function testBooleansNullAndStringsStay(bool|string|null $value): void
    {
        self::assertSame($value, ValueNormaliser::normalise($value)->value);
    }

    /**
     * A string is cleaned, and no cap applies at capture.
     *
     * @return void
     */
    public function testStringsAreSanitised(): void
    {
        self::assertSame('ab', ValueNormaliser::normalise("a\0b\u{202E}")->value);
        self::assertSame(str_repeat('a', 5000), ValueNormaliser::normalise(str_repeat('a', 5000))->value);
    }

    /**
     * A backed enum's value is normalised as the scalar it is: a string is
     * cleaned like any other, and an integer beyond the safe range, either way,
     * becomes its decimal string.
     *
     * @return void
     */
    public function testABackedEnumsValueIsNormalisedAsAScalar(): void
    {
        self::assertSame('a b', ValueNormaliser::normalise(StubColour::DIRTY)->value);
        self::assertSame('9223372036854775807', ValueNormaliser::normalise(StubPriority::HUGE)->value);
        self::assertSame('-9007199254740992', ValueNormaliser::normalise(StubPriority::BELOW)->value);
    }

    /**
     * Rows of `[integer, what it becomes]`: the safe range's bounds stay
     * integers, and anything beyond them becomes its decimal string.
     *
     * @return iterable<string, array{0: int, 1: int|string}>
     */
    public static function provideIntegers(): iterable
    {
        yield from [
            'zero'                         => [0, 0],
            'the safe maximum'             => [ValueNormaliser::MAX_SAFE_INTEGER, 9007199254740991],
            'the safe minimum'             => [-ValueNormaliser::MAX_SAFE_INTEGER, -9007199254740991],
            'two to the fifty-third'       => [2 ** 53, '9007199254740992'],
            'minus two to the fifty-third' => [-(2 ** 53), '-9007199254740992'],
            'PHP_INT_MAX'                  => [PHP_INT_MAX, '9223372036854775807'],
            'PHP_INT_MIN'                  => [PHP_INT_MIN, '-9223372036854775808'],
            'a negative safe number'       => [-42, -42],
        ];
    }

    /**
     * Each integer within ±(2^53 − 1) stays an integer, and each beyond it
     * becomes its decimal string, so no JSON reader rounds it.
     *
     * @param  int  $value
     * @param  int|string  $expected
     * @return void
     */
    #[DataProvider('provideIntegers')]
    public function testIntegersBeyondTheSafeRangeBecomeStrings(int $value, int|string $expected): void
    {
        self::assertSame($expected, ValueNormaliser::normalise($value)->value);
    }

    /**
     * Rows of `[float, its string]`: the ECMAScript examples, both zeros, each
     * boundary between positional and exponential form, and powers of two,
     * where the shortest digits that read back are not the rounded ones.
     *
     * @return iterable<string, array{0: float, 1: string}>
     */
    public static function provideFloats(): iterable
    {
        yield from [
            'a tenth'                                        => [0.1, '0.1'],
            'one and a half'                                 => [1.5, '1.5'],
            'a hundred'                                      => [100.0, '100'],
            'a tenth plus two tenths'                        => [0.1 + 0.2, '0.30000000000000004'],
            'ten to the twentieth'                           => [1e20, '100000000000000000000'],
            'ten to the twenty-first'                        => [1e21, '1e+21'],
            'one and a half times ten to the twenty-first'   => [1.5e21, '1.5e+21'],
            'nine digits times ten to the twenty-first'      => [1.23456789e21, '1.23456789e+21'],
            'a millionth'                                    => [1e-6, '0.000001'],
            'one and a half millionths'                      => [1.5e-6, '0.0000015'],
            'a ten-millionth'                                => [1e-7, '1e-7'],
            'one and a quarter ten-millionths'               => [1.25e-7, '1.25e-7'],
            'the least subnormal'                            => [5e-324, '5e-324'],
            'the greatest float'                             => [PHP_FLOAT_MAX, '1.7976931348623157e+308'],
            'the least normal float'                         => [PHP_FLOAT_MIN, '2.2250738585072014e-308'],
            'minus two and a half'                           => [-2.5, '-2.5'],
            'minus a ten-millionth'                          => [-1e-7, '-1e-7'],
            'minus ten to the twenty-first'                  => [-1e21, '-1e+21'],
            'nine digits and an eighth'                      => [123456789.125, '123456789.125'],
            'two to the fifty-third'                         => [2.0 ** 53, '9007199254740992'],
            'two to the minus twenty-fourth, a tie'          => [2.0 ** -24, '5.960464477539063e-8'],
            'two to the minus forty-fourth'                  => [2.0 ** -44, '5.684341886080802e-14'],
            'two to the eighty-ninth'                        => [2.0 ** 89, '6.189700196426902e+26'],
            'two to the minus one thousand and seventeenth'  => [2.0 ** -1017, '7.120236347223045e-307'],
            'the float above two to the minus twenty-fourth' => [2.0 ** -24 + 2.0 ** -76, '5.960464477539064e-8'],
            'one'                                            => [1.0, '1'],
            'a half'                                         => [0.5, '0.5'],
            'twelve and a half'                              => [12.5, '12.5'],
            'a third'                                        => [1 / 3, '0.3333333333333333'],
            'a thousandth'                                   => [0.001, '0.001'],
            'five digits times ten to the twentieth'         => [1.2345e20, '123450000000000000000'],
            'twenty-one digits, rounded'                     => [123456789012345678901.0, '123456789012345680000'],
            'zero'                                           => [0.0, '0'],
            'negative zero'                                  => [-0.0, '0'],
        ];
    }

    /**
     * Each finite float becomes the fewest digits that read back as it, in the
     * form ECMAScript writes, and reads back as the same float (negative zero
     * equals zero).
     *
     * @param  float  $value
     * @param  string  $expected
     * @return void
     */
    #[DataProvider('provideFloats')]
    public function testAFiniteFloatBecomesItsShortestRoundTripString(float $value, string $expected): void
    {
        self::assertSame($expected, ValueNormaliser::normalise($value)->value);
        self::assertSame($expected, ValueNormaliser::float($value));

        self::assertSame($value, (float) $expected);
    }

    /**
     * The precision settings change nothing: the digits never come from them.
     *
     * @return void
     */
    public function testFloatsIgnoreThePrecisionSettings(): void
    {
        ini_set('precision', '3');
        ini_set('serialize_precision', '5');

        self::assertSame('0.30000000000000004', ValueNormaliser::normalise(0.1 + 0.2)->value);
        self::assertSame('0.3333333333333333', ValueNormaliser::normalise(1 / 3)->value);
    }

    /**
     * Rows of `[float]`: the non-finite floats.
     *
     * @return iterable<string, array{0: float}>
     */
    public static function provideNonFiniteFloats(): iterable
    {
        yield from [
            'INF'  => [INF],
            '-INF' => [-INF],
            'NAN'  => [NAN],
        ];
    }

    /**
     * Each non-finite float, which JSON cannot hold, is marked.
     *
     * @param  float  $value
     * @return void
     */
    #[DataProvider('provideNonFiniteFloats')]
    public function testANonFiniteFloatIsMarked(float $value): void
    {
        self::assertSame(ValueNormaliser::NONFINITE, ValueNormaliser::normalise($value)->value);
        self::assertSame('[NONFINITE]', ValueNormaliser::float($value));
    }

    /**
     * A list stays a list, in order.
     *
     * @return void
     */
    public function testAListStaysAList(): void
    {
        $value = ValueNormaliser::normalise(['a', 1, true, null])->value;

        self::assertSame(['a', 1, true, null], $value);
        self::assertSame('["a",1,true,null]', json_encode($value));
    }

    /**
     * A map keeps its keys and their order, so it encodes as an object even
     * when its keys are digits out of order.
     *
     * @return void
     */
    public function testAMapKeepsItsKeysAsAMap(): void
    {
        $value = ValueNormaliser::normalise([1 => 'a', 0 => 'b'])->value;

        self::assertSame([1 => 'a', 0 => 'b'], $value);
        self::assertSame('{"1":"a","0":"b"}', json_encode($value));
        self::assertSame('{"name":"x","2":"y"}', json_encode(ValueNormaliser::normalise(['name' => 'x', 2 => 'y'])->value));
    }

    /**
     * An empty array is an empty list.
     *
     * @return void
     */
    public function testAnEmptyArrayIsAnEmptyList(): void
    {
        $value = ValueNormaliser::normalise([])->value;

        self::assertSame([], $value);
        self::assertSame('[]', json_encode($value));
    }

    /**
     * Rows of `[value]`: objects of no supported class and resources, open or
     * closed.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideUnserialisableValues(): iterable
    {
        $closed = fopen('php://memory', 'r');

        if ($closed !== false) {
            fclose($closed);
        }

        yield from [
            'a Stringable' => [new class implements \Stringable {
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
            }],
            'a JsonSerializable' => [new class implements \JsonSerializable {
                /**
                 * The value the object would give.
                 *
                 * @return array<string, string>
                 */
                #[\Override]
                public function jsonSerialize(): array
                {
                    return ['secret' => 'value'];
                }
            }],
            'an Arrayable'      => [new Collection(['a' => 1])],
            'a closure'         => [static fn (): string => 'value'],
            'a plain object'    => [new \stdClass],
            'an open resource'  => [fopen('php://memory', 'r')],
            'a closed resource' => [$closed],
        ];
    }

    /**
     * Each value of no supported type is marked unserialisable, never cast and
     * never called.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideUnserialisableValues')]
    public function testOtherValuesAreUnserialisable(mixed $value): void
    {
        self::assertSame(ValueNormaliser::UNSERIALISABLE, ValueNormaliser::normalise($value)->value);
        self::assertSame('[UNSERIALISABLE]', ValueNormaliser::normalise([$value])->value[0] ?? null);
    }

    /**
     * A `Stringable` whose `__toString()` throws is marked without its method
     * being called.
     *
     * @return void
     */
    public function testAStringableIsNeverCalled(): void
    {
        $value = new class implements \Stringable {
            /**
             * Fail the test if called.
             *
             * @return string
             *
             * @throws \LogicException
             */
            #[\Override]
            public function __toString(): string
            {
                throw new \LogicException('The normaliser called __toString().');
            }
        };

        self::assertSame(ValueNormaliser::UNSERIALISABLE, ValueNormaliser::normalise($value)->value);
    }

    /**
     * Eight nested arrays are kept whole, with the scalar at the bottom.
     *
     * @return void
     */
    public function testEightLevelsOfNestingAreKept(): void
    {
        $value = self::nested(8, 'bottom');

        self::assertSame($value, ValueNormaliser::normalise($value)->value);
    }

    /**
     * The ninth nested array becomes `[TRUNCATED]`, while the eighth array's
     * scalars stay; one level shallower would keep it, and one deeper would
     * lose the eighth array's scalars.
     *
     * @return void
     */
    public function testTheNinthLevelIsTruncated(): void
    {
        $value    = self::nested(7, ['kept' => 'scalar', 'deeper' => ['lost']]);
        $expected = self::nested(7, ['kept' => 'scalar', 'deeper' => ValueNormaliser::TRUNCATED]);

        self::assertSame($expected, ValueNormaliser::normalise($value)->value);
        self::assertSame(self::nested(8, ValueNormaliser::TRUNCATED), ValueNormaliser::normalise(self::nested(9, 'x'))->value);
    }

    /**
     * A list of nested lists is bounded the same way as a map.
     *
     * @return void
     */
    public function testNestedListsAreTruncatedAtTheSameDepth(): void
    {
        $value = [[[[[[[[['too deep']]]]]]]]];

        self::assertSame([[[[[[[[ValueNormaliser::TRUNCATED]]]]]]]], ValueNormaliser::normalise($value)->value);
    }

    /**
     * A self-referencing array ends in `[TRUNCATED]` at the ninth level rather
     * than recursing for ever.
     *
     * @return void
     */
    public function testASelfReferencingArrayIsBounded(): void
    {
        $value         = ['name' => 'loop'];
        $value['self'] = &$value;

        $normalised = ValueNormaliser::normalise($value)->value;

        for ($depth = 1; $depth < ValueNormaliser::MAX_DEPTH; $depth++) {
            self::assertIsArray($normalised);
            self::assertSame('loop', $normalised['name']);
            $normalised = $normalised['self'];
        }

        self::assertIsArray($normalised);
        self::assertSame(['name' => 'loop', 'self' => ValueNormaliser::TRUNCATED], $normalised);
    }

    /**
     * Values nested in lists and maps are normalised by the same rules.
     *
     * @return void
     */
    public function testNestedValuesAreNormalised(): void
    {
        $value = [
            'items' => [
                (new StubDocument)->forceFill(['id' => 'doc-1']),
                StubSuit::HEARTS,
                new \DateTimeImmutable('2026-11-01T09:30:15Z'),
                ['amount' => 1.5, 'big' => PHP_INT_MAX, 'text' => "a\nb"],
            ],
        ];

        self::assertSame([
            'items' => [
                ['type' => StubDocument::class, 'id' => 'doc-1'],
                'HEARTS',
                '2026-11-01T09:30:15.000000Z',
                ['amount' => '1.5', 'big' => '9223372036854775807', 'text' => 'a b'],
            ],
        ], ValueNormaliser::normalise($value)->value);
    }

    /**
     * Map keys are cleaned like any other string, and integer keys become
     * strings that PHP keeps as integers.
     *
     * @return void
     */
    public function testKeysAreSanitised(): void
    {
        self::assertSame(['ab' => 1, 'c d' => 2], ValueNormaliser::normalise(["a\0b" => 1, "c\nd" => 2])->value);
    }

    /**
     * Keys that collide once cleaned keep the first value, and the collision is
     * diagnosed by its path, never its value.
     *
     * @return void
     */
    public function testCollidingKeysKeepTheFirstAndAreDiagnosed(): void
    {
        $normalised = ValueNormaliser::normalise(['a' => 1, "a\0" => 2]);

        self::assertSame(['a' => 1], $normalised->value);
        self::assertSame([['a']], $normalised->collisions);
        self::assertSame(1, $normalised->collisionCount);
    }

    /**
     * The value of a collided key is never normalised, so an unsaved model in
     * it cannot fail the capture.
     *
     * @return void
     */
    public function testACollidedValueIsNeverNormalised(): void
    {
        $normalised = ValueNormaliser::normalise(['a' => 1, "a\0" => new StubUser]);

        self::assertSame(['a' => 1], $normalised->value);
        self::assertSame(1, $normalised->collisionCount);
    }

    /**
     * A collision is named by its segments: map keys cleaned, list indices kept
     * as integers.
     *
     * @return void
     */
    public function testACollisionIsNamedByItsSegments(): void
    {
        $normalised = ValueNormaliser::normalise([
            'items' => [['x' => 1, "x\0" => 2]],
            "me\ta" => ['k' => 1, "\u{202E}k" => 2],
        ]);

        self::assertSame([['items', 0, 'x'], ['me a', 'k']], $normalised->collisions);
        self::assertSame(2, $normalised->collisionCount);
        self::assertSame([[0, 'x']], ValueNormaliser::normalise([['x' => 1, "x\0" => 2]])->collisions);
    }

    /**
     * A literal dot in a key stays inside its one segment, so the path cannot
     * be mistaken for a deeper one.
     *
     * @return void
     */
    public function testALiteralDotInACollidedKeyStaysOneSegment(): void
    {
        self::assertSame([['a.b', 'x']], ValueNormaliser::normalise(['a.b' => ['x' => 1, "x\0" => 2]])->collisions);
        self::assertSame([['a', 'b', 'x']], ValueNormaliser::normalise(['a' => ['b' => ['x' => 1, "x\0" => 2]]])->collisions);
    }

    /**
     * A list index in a collision is the element's own index, as an integer, so
     * two elements of one list are told apart.
     *
     * @return void
     */
    public function testAListIndexInACollisionIsAnInteger(): void
    {
        $normalised = ValueNormaliser::normalise(['items' => [['x' => 1], ['x' => 1, "x\0" => 2], [[], ['y' => 1, "y\0" => 2]]]]);

        self::assertSame([['items', 1, 'x'], ['items', 2, 1, 'y']], $normalised->collisions);
    }

    /**
     * An integer key of a map is a map key, so it is kept as its string, unlike
     * a list index; a key that collides with one only once cleaned is named the
     * same way.
     *
     * @return void
     */
    public function testAnIntegerMapKeyInACollisionIsAString(): void
    {
        self::assertSame([['5', 'x']], ValueNormaliser::normalise([5 => ['x' => 1, "x\0" => 2]])->collisions);
        self::assertSame([['5']], ValueNormaliser::normalise([5 => 1, "5\0" => 2])->collisions);
    }

    /**
     * A collision's keys are named as they were cleaned, at every depth, never
     * as they were given.
     *
     * @return void
     */
    public function testACollisionPathHoldsOnlyCleanedKeys(): void
    {
        $normalised = ValueNormaliser::normalise(["o\0uter" => ["in\u{202E}ner" => ['k' => 1, "k\0" => 2]]]);

        self::assertSame([['outer', 'inner', 'k']], $normalised->collisions);
    }

    /**
     * A collision is still named at the deepest array kept, and a collision in
     * an array beyond it is not met, since that array is truncated unread.
     *
     * @return void
     */
    public function testACollisionIsNamedAtTheDeepestArrayKept(): void
    {
        $deepest = ValueNormaliser::normalise(self::nested(7, ['x' => 1, "x\0" => 2]));
        $beyond  = ValueNormaliser::normalise(self::nested(8, ['x' => 1, "x\0" => 2]));

        self::assertSame([[...array_fill(0, 7, 'level'), 'x']], $deepest->collisions);
        self::assertSame([], $beyond->collisions);
        self::assertSame(0, $beyond->collisionCount);
    }

    /**
     * Every parameter that holds a raw value, a raw key or a diagnostic is
     * marked sensitive, on the entry point and on each helper it passes
     * through, because `Reference::to()` can throw from inside them.
     *
     * @return void
     */
    public function testTheRawValueParametersAreSensitive(): void
    {
        $values = ['normalise', 'value', 'object', 'collection', 'list', 'map', 'scalar', 'backed', 'uid', 'integer', 'date', 'float', 'shortestDigits', 'readsBack'];
        $paths  = ['value', 'collection', 'list', 'map', 'collide'];

        foreach ($values as $method) {
            self::assertTrue(self::isSensitive(ValueNormaliser::class, $method, 'value'), "{$method}() does not mark its value.");
        }

        foreach ($paths as $method) {
            self::assertTrue(self::isSensitive(ValueNormaliser::class, $method, 'path'), "{$method}() does not mark its path.");
            self::assertTrue(self::isSensitive(ValueNormaliser::class, $method, 'collisions'), "{$method}() does not mark its collisions.");
        }

        self::assertTrue(self::isSensitive(Normalised::class, '__construct', 'value'));
        self::assertTrue(self::isSensitive(Normalised::class, '__construct', 'collisions'));
    }

    /**
     * The depth and the count hold no payload, so they stay readable in a stack
     * trace.
     *
     * @return void
     */
    public function testTheStructuralParametersAreNotSensitive(): void
    {
        self::assertFalse(self::isSensitive(ValueNormaliser::class, 'value', 'depth'));
        self::assertFalse(self::isSensitive(ValueNormaliser::class, 'value', 'count'));
    }

    /**
     * A failure from inside the normaliser leaves no value and no key in the
     * exception's stack trace, even with every frame keeping its arguments.
     *
     * @return void
     */
    public function testAFailureLeavesNoRawValueInTheStackTrace(): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');

        try {
            ValueNormaliser::normalise(['planted-key' => ['planted-sibling' => 'planted-value', 'model' => new StubUser]]);
            self::fail('Expected the unsaved model to be refused.');
        } catch (\InvalidArgumentException $exception) {
            $trace = print_r($exception->getTrace(), true);

            self::assertStringContainsString(\SensitiveParameterValue::class, $trace);
            self::assertStringNotContainsString('planted', $trace);
            self::assertStringNotContainsString('planted', (string) $exception);
        } finally {
            ini_set('zend.exception_ignore_args', $previous === false ? '0' : $previous);
        }
    }

    /**
     * At most 32 collision paths are kept, the first met, while the count
     * covers every one; the boundary rows protect against an off-by-one
     * mutation of the bound.
     *
     * @return void
     */
    public function testCollisionDiagnosticsAreBounded(): void
    {
        $normalised = ValueNormaliser::normalise(self::collisions(40));

        self::assertCount(Normalised::MAX_COLLISIONS, $normalised->collisions);
        self::assertSame(array_map(static fn (int $i): array => ['k' . $i], range(0, 31)), $normalised->collisions);
        self::assertSame(40, $normalised->collisionCount);
        self::assertCount(32, ValueNormaliser::normalise(self::collisions(33))->collisions);
        self::assertCount(31, ValueNormaliser::normalise(self::collisions(31))->collisions);
    }

    /**
     * A scalar root is normalised on its own, with no collisions.
     *
     * @return void
     */
    public function testAScalarRootIsNormalised(): void
    {
        $normalised = ValueNormaliser::normalise('x');

        self::assertSame('x', $normalised->value);
        self::assertSame([], $normalised->collisions);
        self::assertSame(0, $normalised->collisionCount);
    }

    /**
     * A normalised value given without diagnostics has no collisions.
     *
     * @return void
     */
    public function testANormalisedValueAloneHasNoCollisions(): void
    {
        $normalised = new Normalised(['a' => 1]);

        self::assertSame(['a' => 1], $normalised->value);
        self::assertSame([], $normalised->collisions);
        self::assertSame(0, $normalised->collisionCount);
    }

    /**
     * `ValueNormaliser` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ValueNormaliser::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ValueNormaliser::class, $instance);
    }

    /**
     * The value nested in maps to the depth given, the outermost map at
     * depth 1.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  int  $depth
     * @param  mixed  $bottom
     * @return array<string, mixed>
     */
    private static function nested(int $depth, mixed $bottom): array
    {
        $value = ['level' => $bottom];

        for ($level = 1; $level < $depth; $level++) {
            $value = ['level' => $value];
        }

        return $value;
    }

    /**
     * Whether the method marks the parameter of that name sensitive.
     *
     * @param  class-string  $class
     * @param  string  $method
     * @param  string  $name
     * @return bool
     */
    private static function isSensitive(string $class, string $method, string $name): bool
    {
        foreach ((new \ReflectionMethod($class, $method))->getParameters() as $parameter) {
            if ($parameter->getName() !== $name) {
                continue;
            }

            return $parameter->getAttributes(\SensitiveParameter::class) !== [];
        }

        self::fail("{$method}() has no parameter \${$name}.");
    }

    /**
     * A map with as many keys colliding once cleaned as given: `kN` and `kN`
     * followed by a NUL, for each N.
     *
     * @param  int  $count
     * @return array<string, int>
     */
    private static function collisions(int $count): array
    {
        $map = [];

        for ($index = 0; $index < $count; $index++) {
            $map['k' . $index]        = $index;
            $map['k' . $index . "\0"] = $index;
        }

        return $map;
    }
}
