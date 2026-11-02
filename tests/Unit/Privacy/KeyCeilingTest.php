<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\KeyCeiling;
use SineMacula\Laravel\AuditLog\Privacy\OmissionLog;

/**
 * Unit tests for the key ceiling: where it falls, that a longer key goes with
 * its whole branch at every depth, and what is said about it, in the properties
 * and the context alike.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyCeiling::class)]
final class KeyCeilingTest extends TestCase
{
    /** @var string The value that must reach no diagnostic. */
    private const string PLANTED = 's3cr3t';

    /**
     * The ceiling stays well under the 65,535 bytes MySQL allows a JSON key,
     * and it is the one the rest of the layer reads.
     *
     * @return void
     */
    public function testTheCeilingIsWellUnderWhatEveryEngineStores(): void
    {
        self::assertSame(1024, KeyCeiling::MAX_BYTES);
    }

    /**
     * A key at the ceiling is within it, and one byte more is not.
     *
     * @return void
     */
    public function testTheCeilingFallsAtItsLastByte(): void
    {
        self::assertFalse(KeyCeiling::isExceededBy(str_repeat('k', KeyCeiling::MAX_BYTES)));
        self::assertTrue(KeyCeiling::isExceededBy(str_repeat('k', KeyCeiling::MAX_BYTES + 1)));
    }

    /**
     * The ceiling counts bytes, not characters, because a byte is what an
     * engine and the tokeniser spend.
     *
     * @return void
     */
    public function testTheCeilingCountsBytes(): void
    {
        self::assertTrue(KeyCeiling::isExceededBy(str_repeat('é', KeyCeiling::MAX_BYTES / 2 + 1)));
    }

    /**
     * A record with no key past the ceiling is left exactly as it was, and
     * nothing is logged.
     *
     * @return void
     */
    public function testNothingWithinTheCeilingChanges(): void
    {
        $omissions = new OmissionLog;
        $values    = ['kept' => 1, 'nested' => ['deep' => ['leaf' => 'x']], 'items' => [['a' => 1], 'b'], 'none' => [], str_repeat('k', KeyCeiling::MAX_BYTES) => 'at the ceiling'];

        self::assertSame($values, KeyCeiling::properties($values, $omissions));
        self::assertNull($omissions->toArray());
    }

    /**
     * Rows of `[values holding a longer key, what is left]`: the key at each
     * depth, within a map and within a map in a list, with its siblings kept.
     * The key is built in the test, so the data set does not print it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: \Closure(string): array<array-key, mixed>, 1: array<array-key, mixed>}>
     */
    public static function provideLongerKeys(): iterable
    {
        yield from [
            'at the top' => [
                static fn (string $key): array => [$key => self::PLANTED, 'kept' => 1],
                ['kept' => 1],
            ],
            'in a map' => [
                static fn (string $key): array => ['outer' => [$key => self::PLANTED, 'kept' => 1]],
                ['outer' => ['kept' => 1]],
            ],
            'in a map in a list' => [
                static fn (string $key): array => ['items' => [['kept' => 1], [$key => self::PLANTED, 'kept' => 2]]],
                ['items' => [['kept' => 1], ['kept' => 2]]],
            ],
            'at the deepest kept' => [
                static fn (string $key): array => ['a' => ['b' => ['c' => ['d' => ['e' => ['f' => ['g' => [$key => self::PLANTED]]]]]]]],
                ['a' => ['b' => ['c' => ['d' => ['e' => ['f' => ['g' => []]]]]]]],
            ],
            'over a whole branch' => [
                static fn (string $key): array => [$key => ['deep' => ['password' => self::PLANTED]], 'kept' => 1],
                ['kept' => 1],
            ],
            'alone in a map, which stays' => [
                static fn (string $key): array => ['outer' => [$key => self::PLANTED]],
                ['outer' => []],
            ],
        ];
    }

    /**
     * A longer key goes with its whole branch at any depth, counted once under
     * `*` wherever it was, and its siblings stay.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(string): array<array-key, mixed>  $values
     * @param  array<array-key, mixed>  $left
     * @return void
     */
    #[DataProvider('provideLongerKeys')]
    public function testALongerPropertyKeyGoesWithItsBranch(\Closure $values, array $left): void
    {
        $omissions = new OmissionLog;

        self::assertSame($left, KeyCeiling::properties($values(self::longerKey()), $omissions));
        self::assertSame(['count' => 1, 'paths' => ['*']], $omissions->toArray());
    }

    /**
     * A longer key in the context goes the same way, counted under the
     * context's masked path.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(string): array<array-key, mixed>  $values
     * @param  array<array-key, mixed>  $left
     * @return void
     */
    #[DataProvider('provideLongerKeys')]
    public function testALongerContextKeyGoesWithItsBranch(\Closure $values, array $left): void
    {
        $omissions = new OmissionLog;

        self::assertSame($left, KeyCeiling::context($values(self::longerKey()), $omissions));
        self::assertSame(['count' => 1, 'paths' => ['context.*']], $omissions->toArray());
    }

    /**
     * Each longer key is counted, however many there are, under the one path,
     * and neither a key nor a value reaches the log.
     *
     * @return void
     */
    public function testEachLongerKeyIsCounted(): void
    {
        $omissions = new OmissionLog;
        $first     = self::PLANTED . self::longerKey();
        $second    = self::PLANTED . self::longerKey() . 'b';

        $left = KeyCeiling::properties([$first => self::PLANTED, 'outer' => [$second => self::PLANTED], 'kept' => 1], $omissions);

        self::assertSame(['outer' => [], 'kept' => 1], $left);
        self::assertSame(['count' => 2, 'paths' => ['*']], $omissions->toArray());
    }

    /**
     * A utility container cannot be instantiated.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(KeyCeiling::class, '__construct'))->isPrivate());
    }

    /**
     * A key one byte past the ceiling.
     *
     * @return string
     */
    private static function longerKey(): string
    {
        return str_repeat('k', KeyCeiling::MAX_BYTES + 1);
    }
}
