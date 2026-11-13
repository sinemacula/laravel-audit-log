<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Support\UuidV7;

/**
 * Unit tests for the package's UUID v7s of a given time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UuidV7::class)]
final class UuidV7Test extends TestCase
{
    /** @var string Pattern of a lower-case UUID v7 with the RFC 9562 variant. */
    private const string PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/';

    /**
     * An id is a lower-case UUID v7 carrying the given time's millisecond, then
     * its sub-millisecond microseconds.
     *
     * @return void
     */
    public function testAnIdIsAUuidV7OfTheGivenMillisecond(): void
    {
        $time = new CarbonImmutable('2026-03-04T05:06:07.123456Z');

        $id = UuidV7::at($time);

        self::assertMatchesRegularExpression(self::PATTERN, $id);
        self::assertSame($time->getTimestampMs(), self::millisecondOf($id));
        self::assertSame('71c8', substr($id, 14, 4));
    }

    /**
     * Ids of one time are distinct.
     *
     * @return void
     */
    public function testIdsOfOneTimeAreDistinct(): void
    {
        $time = new CarbonImmutable('2026-03-04T05:06:07.123456Z');
        $ids  = [];

        for ($made = 0; $made < 500; $made++) {
            $ids[] = UuidV7::at($time);
        }

        self::assertCount(500, array_unique($ids));

        foreach ($ids as $id) {
            self::assertMatchesRegularExpression(self::PATTERN, $id);
        }
    }

    /**
     * Ids sort by their time to the microsecond, whichever was made first.
     *
     * @return void
     */
    public function testIdsSortByTimeToTheMicrosecond(): void
    {
        $times = ['2026-03-04T05:06:07.124000Z', '2026-03-04T05:06:07.123999Z', '2026-03-04T05:06:07.123001Z', '2026-03-04T05:06:07.123000Z'];
        $ids   = array_map(static fn (string $time): string => UuidV7::at(new CarbonImmutable($time)), $times);

        $sorted = $ids;
        sort($sorted, SORT_STRING);

        self::assertSame(array_reverse($ids), $sorted);
    }

    /**
     * Ids one instance makes of one instant count up by one, so they sort in
     * the order they were made.
     *
     * @return void
     */
    public function testNextIdsOfOneInstantSortInTheOrderMade(): void
    {
        $generator = new UuidV7;
        $time      = new CarbonImmutable('2026-03-04T05:06:07.123456Z');
        $ids       = [];

        for ($made = 0; $made < 500; $made++) {
            $ids[] = $generator->next($time);
        }

        $sorted = $ids;
        sort($sorted, SORT_STRING);

        self::assertSame($ids, $sorted);
        self::assertCount(500, array_unique($ids));

        foreach ($ids as $id) {
            self::assertMatchesRegularExpression(self::PATTERN, $id);
            self::assertSame($time->getTimestampMs(), self::millisecondOf($id));
            self::assertSame('71c8', substr($id, 14, 4));
        }

        for ($made = 1; $made < 500; $made++) {
            self::assertSame(self::tailOf($ids[$made - 1]) + 1, self::tailOf($ids[$made]));
        }
    }

    /**
     * An id of another instant is drawn afresh, never placed after the last.
     *
     * @return void
     */
    public function testNextIdsOfAnotherInstantFollowTheirTime(): void
    {
        $generator = new UuidV7;
        $later     = $generator->next(new CarbonImmutable('2026-03-04T05:06:07.123457Z'));
        $earlier   = $generator->next(new CarbonImmutable('2026-03-04T05:06:07.123456Z'));

        self::assertLessThan(0, strcmp($earlier, $later));
        self::assertSame('71c8', substr($earlier, 14, 4));
    }

    /**
     * A time ahead of the clock leaves Laravel's generator at the present.
     *
     * @return void
     */
    public function testLaravelsGeneratorIsLeftAlone(): void
    {
        $future = (new CarbonImmutable)->addYears(10);

        UuidV7::at($future);

        $present = self::millisecondOf(Str::uuid7()->toString());

        self::assertLessThan($future->getTimestampMs(), $present);
    }

    /**
     * The last 64 bits of a UUID, as a signed integer.
     *
     * @param  string  $id
     * @return int
     */
    private static function tailOf(string $id): int
    {
        $unpacked = unpack('J', (string) hex2bin(substr(str_replace('-', '', $id), 16)));

        self::assertIsArray($unpacked);
        self::assertIsInt($unpacked[1]);

        return $unpacked[1];
    }

    /**
     * The millisecond a UUID v7 carries.
     *
     * @param  string  $id
     * @return int
     */
    private static function millisecondOf(string $id): int
    {
        return (int) hexdec(substr(str_replace('-', '', $id), 0, 12));
    }
}
