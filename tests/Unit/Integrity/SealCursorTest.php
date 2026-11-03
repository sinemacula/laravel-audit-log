<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\SealCursor;

/**
 * Unit tests for the seal cursor: a position from an instant, after an entry,
 * and as progress keeps it; the malformed progress it reads as none; the
 * position of a malformed row it keeps as given; and the lengths it refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SealCursor::class)]
final class SealCursorTest extends TestCase
{
    /**
     * A position from an instant starts at it: its time is the instant as the
     * database stores it, and it names no entry, so the row at the instant is
     * read too.
     *
     * @return void
     */
    public function testFromAnInstantStartsAtIt(): void
    {
        $cursor = SealCursor::from('2026-11-01T12:00:00.250000Z');

        self::assertSame('2026-11-01 12:00:00.250000', $cursor->recordedAt);
        self::assertSame('', $cursor->id);
        self::assertTrue($cursor->startsAtItsTime());
    }

    /**
     * An instant that is not in the package's form is refused.
     *
     * @return void
     */
    public function testFromRefusesATimeThatIsNoInstant(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        SealCursor::from('2026-11-01 12:00:00');
    }

    /**
     * A position after an entry keeps its time and id as given, and does not
     * start at its time.
     *
     * @return void
     */
    public function testAfterKeepsTheEntrysPosition(): void
    {
        $cursor = SealCursor::after('2026-11-01 12:00:00.2', '01932b4e-8a40-7000-8000-000000000001');

        self::assertSame('2026-11-01 12:00:00.2', $cursor->recordedAt);
        self::assertSame('01932b4e-8a40-7000-8000-000000000001', $cursor->id);
        self::assertFalse($cursor->startsAtItsTime());
    }

    /**
     * A position round-trips through the progress it is kept in, either form,
     * with whether it starts at its time kept apart from its id.
     *
     * @return void
     */
    public function testRoundTripsThroughProgress(): void
    {
        $after = SealCursor::after('2026-11-01 12:00:00.000001', '01932b4e-8a40-7000-8000-000000000001');
        $from  = SealCursor::from('2026-11-01T12:00:00.000000Z');

        self::assertSame(['recorded_at' => '2026-11-01 12:00:00.000001', 'id' => '01932b4e-8a40-7000-8000-000000000001', 'from_its_time' => false], $after->toProgress());
        self::assertSame(['recorded_at' => '2026-11-01 12:00:00.000000', 'id' => '', 'from_its_time' => true], $from->toProgress());
        self::assertEquals($after, SealCursor::fromProgress($after->toProgress()));
        self::assertEquals($from, SealCursor::fromProgress($from->toProgress()));
        self::assertTrue(SealCursor::fromProgress($from->toProgress())?->startsAtItsTime());
    }

    /**
     * Progress that does not say a position starts at its time, or says so with
     * anything but `true`, is a position after the entry it names.
     *
     * @return void
     */
    public function testProgressStartsAtItsTimeOnlyWhenItSaysSo(): void
    {
        foreach ([null, 1, 'true', false] as $flag) {
            $cursor = SealCursor::fromProgress(['recorded_at' => '2026-11-01 12:00:00', 'id' => '', 'from_its_time' => $flag]);

            self::assertFalse($cursor?->startsAtItsTime(), var_export($flag, true));
        }

        self::assertFalse(SealCursor::fromProgress(['recorded_at' => '2026-11-01 12:00:00', 'id' => ''])?->startsAtItsTime());
    }

    /**
     * Rows of `[progress]`: values progress may hold that are no position.
     *
     * @return iterable<string, array{0: ?array<string, scalar|null>}>
     */
    public static function provideMalformedProgress(): iterable
    {
        yield from [
            'nothing'                 => [null],
            'an empty map'            => [[]],
            'no id'                   => [['recorded_at' => '2026-11-01 12:00:00']],
            'no time'                 => [['id' => '01932b4e-8a40-7000-8000-000000000001']],
            'a time that is a number' => [['recorded_at' => 1730462400, 'id' => '']],
            'an id that is a number'  => [['recorded_at' => '2026-11-01 12:00:00', 'id' => 7]],
            'a null id'               => [['recorded_at' => '2026-11-01 12:00:00', 'id' => null]],
        ];
    }

    /**
     * A progress value that is not a time and an id as strings is no position,
     * so a sweep starts afresh rather than fail.
     *
     * @param  ?array<string, scalar|null>  $progress
     * @return void
     */
    #[DataProvider('provideMalformedProgress')]
    public function testAMalformedProgressValueIsNoCursor(?array $progress): void
    {
        self::assertNull(SealCursor::fromProgress($progress));
    }

    /**
     * Rows of `[time, id]`: the stored keys of rows the sealer skips as
     * malformed, which a position must still name exactly: an empty time, a
     * time that is no instant, an id longer than a UUID, an empty id, and
     * multibyte text.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideMalformedKeys(): iterable
    {
        yield from [
            'an empty time'             => ['', '01932b4e-8a40-7000-8000-000000000001'],
            'a time that is no instant' => ['not a time', 'NOT-A-UUID'],
            'an overlong time'          => [str_repeat('1', 300), '01932b4e-8a40-7000-8000-000000000001'],
            'an id longer than a UUID'  => ['2026-11-01 12:00:00', '01932b4e-8a40-7000-8000-0000000000011'],
            'an empty id'               => ['2026-11-01 12:00:00', ''],
            'multibyte text'            => [str_repeat('é', 40), str_repeat('é', 40)],
        ];
    }

    /**
     * The position of a malformed row is kept exactly as the database returned
     * it, never checked, bounded or cut, and still names the row after it, an
     * empty id included, so a cursor always moves past a row the sealer skipped
     * and a malformed key at the end of a batch never stops sealing.
     *
     * @param  string  $recordedAt
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideMalformedKeys')]
    public function testKeepsThePositionOfAMalformedRow(string $recordedAt, string $id): void
    {
        $cursor = SealCursor::after($recordedAt, $id);

        self::assertSame($recordedAt, $cursor->recordedAt);
        self::assertSame($id, $cursor->id);
        self::assertFalse($cursor->startsAtItsTime());
        self::assertEquals($cursor, SealCursor::fromProgress($cursor->toProgress()));
    }
}
