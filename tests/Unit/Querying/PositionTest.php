<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Querying\Position;

/**
 * Unit tests for a place in the trail's order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Position::class)]
final class PositionTest extends TestCase
{
    /** @var string An instant in the package's form. */
    private const string TIME = '2026-11-01T12:00:00.123456Z';

    /** @var string A lower-case UUID. */
    private const string ID = '0192f5a0-7c1e-7000-8000-00000000000a';

    /**
     * An instant and an id are kept as given, and given back as a pair.
     *
     * @return void
     */
    public function testKeepsAnInstantAndAnId(): void
    {
        $position = new Position(self::TIME, self::ID);

        self::assertSame(self::TIME, $position->time);
        self::assertSame(self::ID, $position->id);
        self::assertSame([self::TIME, self::ID], $position->toArray());
    }

    /**
     * Rows of `[time, id]`: a time or an id that is not in its form.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideMalformedParts(): iterable
    {
        yield from [
            'a stored time'          => ['2026-11-01 12:00:00.123456', self::ID],
            'no microseconds'        => ['2026-11-01T12:00:00Z', self::ID],
            'an offset'              => ['2026-11-01T12:00:00.123456+00:00', self::ID],
            'a date that is not'     => ['2026-02-30T12:00:00.000000Z', self::ID],
            'an empty time'          => ['', self::ID],
            'an upper-case id'       => [self::TIME, '0192F5A0-7C1E-7000-8000-00000000000A'],
            'an id with no hyphens'  => [self::TIME, '0192f5a07c1e7000800000000000000a'],
            'an id with a line feed' => [self::TIME, self::ID . "\n"],
            'an id cut short'        => [self::TIME, substr(self::ID, 1)],
            'an id with a prefix'    => [self::TIME, 'x' . self::ID],
            'an empty id'            => [self::TIME, ''],
        ];
    }

    /**
     * Each malformed part is refused with a message that names neither.
     *
     * @param  string  $time
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideMalformedParts')]
    public function testRefusesAMalformedPart(string $time, string $id): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A position must be an instant in the package\'s form, such as 2026-11-01T12:00:00.123456Z, and a lower-case UUID.');

        new Position($time, $id);
    }
}
