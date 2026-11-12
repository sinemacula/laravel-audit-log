<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\PruneBitmap;

/**
 * Unit tests for the prune bitmap.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneBitmap::class)]
final class PruneBitmapTest extends TestCase
{
    /** @var string The golden prune vectors. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Integrity/prune-v2.json';

    /**
     * The golden records' positions encode to their golden bitmaps, which
     * decode to their golden bytes and back to their positions.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testEncodesTheGoldenBitmaps(): void
    {
        foreach (['first', 'second'] as $name) {
            $record    = self::golden('prune_' . $name);
            $positions = self::golden('prune_' . $name . '_positions');

            self::assertIsArray($record);
            self::assertIsArray($positions);

            /** @var list<int> $positions */
            $encoded = PruneBitmap::encode($positions, 3);
            $bytes   = PruneBitmap::decode($encoded, 3);

            self::assertSame($record['pruned'] ?? null, $encoded, $name);
            self::assertSame(self::golden('prune_' . $name . '_bytes'), bin2hex($bytes), $name);
            self::assertSame($positions, PruneBitmap::positions($bytes, 3), $name);
        }
    }

    /**
     * Rows of `[position, members, the bytes in hex]`: bit `i` is bit `i % 8`,
     * least significant first, of byte `i / 8`.
     *
     * @return iterable<string, array{0: int, 1: int, 2: string}>
     */
    public static function provideSingleBits(): iterable
    {
        yield from [
            'the first'           => [0, 16, '0100'],
            'the second'          => [1, 16, '0200'],
            'the last of a byte'  => [7, 16, '8000'],
            'the first of byte 1' => [8, 16, '0001'],
            'the ninth of ten'    => [9, 10, '0002'],
            'the last of all'     => [15, 16, '0080'],
        ];
    }

    /**
     * Each position sets exactly its own bit, and nothing else.
     *
     * @param  int  $position
     * @param  int  $members
     * @param  string  $hex
     * @return void
     */
    #[DataProvider('provideSingleBits')]
    public function testBitIIsBitIModEightOfByteIDivEight(int $position, int $members, string $hex): void
    {
        $bytes = PruneBitmap::decode(PruneBitmap::encode([$position], $members), $members);

        self::assertSame($hex, bin2hex($bytes));
        self::assertSame([$position], PruneBitmap::positions($bytes, $members));
    }

    /**
     * The bitmap is exactly the bytes its members need, never one more: 1 to 8
     * members take one byte, 9 two.
     *
     * @return void
     */
    public function testTheLengthIsExactlyTheMembersInBytes(): void
    {
        foreach ([1 => 1, 7 => 1, 8 => 1, 9 => 2, 16 => 2, 17 => 3] as $members => $length) {
            self::assertSame($length, strlen(PruneBitmap::decode(PruneBitmap::encode([0], $members), $members)), (string) $members);
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A prune bitmap of 8 members must be 1 bytes.');

        PruneBitmap::decode(PruneBitmap::encode([0], 9), 8);
    }

    /**
     * A bit set past the last member, in the padding of the last byte, is
     * refused, however few the padding bits.
     *
     * @return void
     */
    public function testRefusesAPaddingBitSet(): void
    {
        foreach ([[3, "\x08"], [3, "\x80"], [7, "\x80"], [9, "\x01\x02"]] as [$members, $bytes]) {
            try {
                PruneBitmap::decode(self::text($bytes), $members);
                self::fail(sprintf('Expected a padding bit of %d members to be refused.', $members));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A prune bitmap must not set a bit past its last member.', $exception->getMessage());
            }
        }

        self::assertSame("\x80", PruneBitmap::decode(self::text("\x80"), 8));
    }

    /**
     * A bitmap written with base64's padding is refused, though it holds the
     * right bytes.
     *
     * @return void
     */
    public function testRefusesPadding(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A prune bitmap must not be padded.');

        PruneBitmap::decode('BQ==', 3);
    }

    /**
     * Rows of `[stored bitmap]`: characters of base64 that are not base64url,
     * and other characters.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideForeignCharacters(): iterable
    {
        yield from [
            'a plus'     => ['+w'],
            'a slash'    => ['/w'],
            'a space'    => ['B Q'],
            'a new line' => ["BQ\n"],
            'a dot'      => ['B.'],
            'a nul'      => ["B\0"],
        ];
    }

    /**
     * A character outside the base64url alphabet is refused.
     *
     * @param  string  $encoded
     * @return void
     */
    #[DataProvider('provideForeignCharacters')]
    public function testRefusesAForeignCharacter(string $encoded): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A prune bitmap must be base64url: letters, digits, hyphens and underscores.');

        PruneBitmap::decode($encoded, 3);
    }

    /**
     * A text whose unused low bits are not zero decodes to the same bytes as
     * the canonical text but is not it, and is refused.
     *
     * @return void
     */
    public function testRefusesANonCanonicalEncoding(): void
    {
        foreach (['BR', 'BT', 'Ah', 'AQJ'] as $encoded) {
            try {
                PruneBitmap::decode($encoded, strlen($encoded) === 3 ? 16 : 3);
                self::fail(sprintf('Expected `%s` to be refused.', $encoded));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A prune bitmap must be the canonical encoding of its bytes.', $exception->getMessage(), $encoded);
            }
        }
    }

    /**
     * A length base64 cannot have, one character past a whole group, is
     * refused, as is the empty text for any member.
     *
     * @return void
     */
    public function testRefusesALengthBase64CannotHave(): void
    {
        foreach (['B', 'BQBQB'] as $encoded) {
            try {
                PruneBitmap::decode($encoded, 3);
                self::fail(sprintf('Expected `%s` to be refused.', $encoded));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A prune bitmap must have a length base64 can encode.', $exception->getMessage(), $encoded);
            }
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A prune bitmap of 3 members must be 1 bytes.');

        PruneBitmap::decode('', 3);
    }

    /**
     * Rows of `[positions, members, message]`: a position below 0, one at the
     * member count, and one given twice.
     *
     * @return iterable<string, array{0: list<int>, 1: int, 2: string}>
     */
    public static function provideRefusedPositions(): iterable
    {
        yield from [
            'below the first' => [[-1], 3, 'A prune bitmap\'s positions must be from 0 to 2.'],
            'at the count'    => [[3], 3, 'A prune bitmap\'s positions must be from 0 to 2.'],
            'far past it'     => [[0, 64], 9, 'A prune bitmap\'s positions must be from 0 to 8.'],
            'given twice'     => [[1, 2, 1], 3, 'A prune bitmap must set each position once.'],
        ];
    }

    /**
     * A position outside the members, or given twice, is refused.
     *
     * @param  list<int>  $positions
     * @param  int  $members
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedPositions')]
    public function testRefusesAPositionOutOfRangeOrRepeated(array $positions, int $members, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        PruneBitmap::encode($positions, $members);
    }

    /**
     * A bitmap that sets no member is refused, and so is one over no member,
     * written or read.
     *
     * @return void
     */
    public function testRefusesAnEmptySet(): void
    {
        $refusals = [
            'no position'      => [static fn (): string => PruneBitmap::encode([], 3), 'A prune bitmap must set at least one member.'],
            'no member'        => [static fn (): string => PruneBitmap::encode([0], 0), 'A prune bitmap must be over at least one member.'],
            'reading none'     => [static fn (): string => PruneBitmap::decode('', 0), 'A prune bitmap must be over at least one member.'],
            'reading negative' => [static fn (): string => PruneBitmap::decode('AA', -1), 'A prune bitmap must be over at least one member.'],
        ];

        foreach ($refusals as $what => [$call, $message]) {
            try {
                $call();
                self::fail(sprintf('Expected %s to be refused.', $what));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage(), $what);
            }
        }
    }

    /**
     * A seal's most members, 50000, take 6250 bytes, written in the golden
     * length of text, and every member set reads back.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testFiftyThousandMembersIsSixThousandTwoHundredFiftyBytes(): void
    {
        $all     = range(0, 49999);
        $encoded = PruneBitmap::encode($all, 50000);
        $bytes   = PruneBitmap::decode($encoded, 50000);

        self::assertSame(self::golden('bitmap_50000_bytes'), strlen($bytes));
        self::assertSame(self::golden('bitmap_50000_length'), strlen($encoded));
        self::assertSame(50000, PruneBitmap::count($bytes));
        self::assertSame($all, PruneBitmap::positions($bytes, 50000));
        self::assertSame(str_repeat("\xff", 6250), $bytes);
    }

    /**
     * The count is every bit the bytes set, and a position is set only within
     * the bytes: before them and past them it is not.
     *
     * @return void
     */
    public function testCountAndIsSet(): void
    {
        $bytes = PruneBitmap::decode(PruneBitmap::encode([0, 3, 8, 9, 15], 16), 16);

        self::assertSame(5, PruneBitmap::count($bytes));
        self::assertSame(0, PruneBitmap::count("\0\0"));
        self::assertSame(16, PruneBitmap::count("\xff\xff"));
        self::assertSame(3, PruneBitmap::count("\x07"));

        $set = array_values(array_filter(range(-2, 20), static fn (int $position): bool => PruneBitmap::isSet($bytes, $position)));

        self::assertSame([0, 3, 8, 9, 15], $set);
        self::assertFalse(PruneBitmap::isSet('', 0));
    }

    /**
     * Positions are read only within the members given and the bytes held: a
     * bit past the members, or a member past the bytes, is not one.
     *
     * @return void
     */
    public function testPositionsStayWithinTheMembersAndTheBytes(): void
    {
        self::assertSame([0, 1], PruneBitmap::positions("\xff", 2));
        self::assertSame([7], PruneBitmap::positions("\x80", 9));
        self::assertSame([], PruneBitmap::positions("\xff", 0));
        self::assertSame([9], PruneBitmap::positions("\x00\x02\xff", 10));
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
        $reflection  = new \ReflectionClass(PruneBitmap::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(PruneBitmap::class, $instance);
    }

    /**
     * The strict base64url text of the bytes, written here as the bitmap is.
     *
     * @param  string  $bytes
     * @return string
     */
    private static function text(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * The golden value under the key given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $field
     * @return mixed
     *
     * @throws \JsonException
     */
    private static function golden(string $field): mixed
    {
        $golden = json_decode((string) file_get_contents(self::GOLDEN), true, 512, JSON_THROW_ON_ERROR);

        return is_array($golden) && array_key_exists($field, $golden) ? $golden[$field] : self::fail(sprintf('The golden prune vectors have no `%s`.', $field));
    }
}
