<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Unit tests for the stored time: the package's ISO-8601 UTC form in storage.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StoredTime::class)]
final class StoredTimeTest extends TestCase
{
    /** @var string Why an instant is refused. */
    private const string INSTANT_MESSAGE = 'A time must be ISO-8601 UTC with microseconds, such as 2026-11-01T12:00:00.123456Z.';

    /** @var string Why a stored time is refused. */
    private const string STORED_MESSAGE = 'A stored time must be `Y-m-d H:i:s` with up to six fractional digits.';

    /** @var string The default time zone before the test, restored after it. */
    private string $timezone = 'UTC';

    /**
     * Remember the default time zone, so a test may change it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->timezone = date_default_timezone_get();
    }

    /**
     * Restore the default time zone after each test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        date_default_timezone_set($this->timezone);

        parent::tearDown();
    }

    /**
     * An instant is stored in UTC with all six fractional digits.
     *
     * @return void
     */
    public function testAnInstantIsStoredWithSixFractionalDigits(): void
    {
        self::assertSame('2026-11-01 12:00:00.123456', StoredTime::toStorage('2026-11-01T12:00:00.123456Z'));
        self::assertSame('2026-11-01 12:00:00.000000', StoredTime::toStorage('2026-11-01T12:00:00.000000Z'));
        self::assertSame('2026-11-01 12:00:00.100000', StoredTime::toStorage('2026-11-01T12:00:00.100000Z'));
    }

    /**
     * Rows of `[stored time, instant]`: six digits, fewer as PostgreSQL drops
     * zeros, and none.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideStoredTimes(): iterable
    {
        yield from [
            'six digits'            => ['2026-11-01 12:00:00.123456', '2026-11-01T12:00:00.123456Z'],
            'one digit'             => ['2026-11-01 12:00:00.1', '2026-11-01T12:00:00.100000Z'],
            'two digits'            => ['2026-11-01 12:00:00.12', '2026-11-01T12:00:00.120000Z'],
            'five digits'           => ['2026-11-01 12:00:00.12345', '2026-11-01T12:00:00.123450Z'],
            'no fraction'           => ['2026-11-01 12:00:00', '2026-11-01T12:00:00.000000Z'],
            'one microsecond'       => ['2026-11-01 12:00:00.000001', '2026-11-01T12:00:00.000001Z'],
            'six zeros'             => ['2026-11-01 12:00:00.000000', '2026-11-01T12:00:00.000000Z'],
            'the last of a day'     => ['2026-12-31 23:59:59.999999', '2026-12-31T23:59:59.999999Z'],
            'a leap day'            => ['2028-02-29 00:00:00', '2028-02-29T00:00:00.000000Z'],
            'a leading zero digit'  => ['2026-11-01 12:00:00.05', '2026-11-01T12:00:00.050000Z'],
            'the Unix epoch'        => ['1970-01-01 00:00:00', '1970-01-01T00:00:00.000000Z'],
            'before the Unix epoch' => ['1969-07-20 20:17:40.5', '1969-07-20T20:17:40.500000Z'],
        ];
    }

    /**
     * Each stored time reads back right-padded to six fractional digits.
     *
     * @param  string  $stored
     * @param  string  $instant
     * @return void
     */
    #[DataProvider('provideStoredTimes')]
    public function testAStoredTimeReadsBackAsIsoUtcWithMicroseconds(string $stored, string $instant): void
    {
        self::assertSame($instant, StoredTime::fromStorage($stored));
    }

    /**
     * An instant written for storage reads back as itself.
     *
     * @return void
     */
    public function testAnInstantSurvivesStorage(): void
    {
        foreach (['2026-11-01T12:00:00.123456Z', '2026-11-01T12:00:00.000001Z', '2026-12-31T23:59:59.999999Z', '0001-01-01T00:00:00.000000Z'] as $instant) {
            self::assertSame($instant, StoredTime::fromStorage(StoredTime::toStorage($instant)), $instant);
        }
    }

    /**
     * A stored time reads as a UTC instant, its microseconds kept.
     *
     * @return void
     */
    public function testAStoredTimeIsAnInstantInUtc(): void
    {
        $instant = StoredTime::instant('2026-11-01 12:00:00.123456');

        self::assertInstanceOf(CarbonImmutable::class, $instant);
        self::assertSame('UTC', $instant->getTimezone()->getName());
        self::assertSame(0, $instant->getOffset());
        self::assertSame(123456, $instant->microsecond);
        self::assertSame('2026-11-01T12:00:00.123456Z', StoredTime::format($instant));
        self::assertSame(100000, StoredTime::instant('2026-11-01 12:00:00.1')->microsecond);
        self::assertSame(0, StoredTime::instant('2026-11-01 12:00:00')->microsecond);
    }

    /**
     * A default time zone far from UTC changes nothing.
     *
     * @return void
     */
    public function testANonUtcDefaultTimeZoneShiftsNothing(): void
    {
        date_default_timezone_set('Pacific/Auckland');

        $instant = StoredTime::instant('2026-11-01 12:00:00.123456');

        self::assertSame('2026-11-01 12:00:00.123456', StoredTime::toStorage('2026-11-01T12:00:00.123456Z'));
        self::assertSame('2026-11-01T12:00:00.123456Z', StoredTime::fromStorage('2026-11-01 12:00:00.123456'));
        self::assertSame('UTC', $instant->getTimezone()->getName());
        self::assertSame('2026-11-01 12:00:00.123456', $instant->format('Y-m-d H:i:s.u'));
        self::assertSame(1793534400, $instant->getTimestamp());
        self::assertTrue(StoredTime::isInstant('2026-11-01T12:00:00.123456Z'));
    }

    /**
     * An instant of any time zone or class is formatted in UTC, left unchanged.
     *
     * @return void
     */
    public function testFormatsAnyInstantInUtc(): void
    {
        $expected = '2026-11-01T12:00:00.123456Z';
        $mutable  = new \DateTime('2026-11-01 07:00:00.123456', new \DateTimeZone('-05:00'));

        self::assertSame($expected, StoredTime::format(new \DateTimeImmutable('2026-11-02 01:00:00.123456', new \DateTimeZone('Pacific/Auckland'))));
        self::assertSame($expected, StoredTime::format(new \DateTimeImmutable('2026-11-01 12:00:00.123456', new \DateTimeZone('UTC'))));
        self::assertSame($expected, StoredTime::format($mutable));
        self::assertSame($expected, StoredTime::format(CarbonImmutable::parse('2026-11-01 17:30:00.123456', '+05:30')));
        self::assertSame('-05:00', $mutable->getTimezone()->getName());
    }

    /**
     * Formatting is in UTC whatever the default time zone.
     *
     * @return void
     */
    public function testFormatsInUtcWhateverTheDefaultTimeZone(): void
    {
        date_default_timezone_set('Pacific/Auckland');

        self::assertSame('2026-11-01T12:00:00.000000Z', StoredTime::format(new \DateTimeImmutable('2026-11-02 01:00:00')));
    }

    /**
     * Rows of `[value]`: values off the package's form, or impossible instants.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedInstants(): iterable
    {
        yield from [
            'no fraction'             => ['2026-11-01T12:00:00Z'],
            'three digits'            => ['2026-11-01T12:00:00.123Z'],
            'seven digits'            => ['2026-11-01T12:00:00.1234567Z'],
            'an offset for Z'         => ['2026-11-01T12:00:00.123456+00:00'],
            'no zone'                 => ['2026-11-01T12:00:00.123456'],
            'a space for T'           => ['2026-11-01 12:00:00.123456Z'],
            'the stored form'         => ['2026-11-01 12:00:00.123456'],
            'a lower-case t and z'    => ['2026-11-01t12:00:00.123456z'],
            'the thirtieth of Feb'    => ['2026-02-30T00:00:00.000000Z'],
            'a leap day in 2026'      => ['2026-02-29T00:00:00.000000Z'],
            'a thirteenth month'      => ['2026-13-01T00:00:00.000000Z'],
            'hour 24'                 => ['2026-11-01T24:00:00.000000Z'],
            'a leap second'           => ['2026-12-31T23:59:60.000000Z'],
            'a single-digit day'      => ['2026-11-1T12:00:00.123456Z'],
            'a five-digit year'       => ['12026-11-01T12:00:00.123456Z'],
            'a leading space'         => [' 2026-11-01T12:00:00.123456Z'],
            'a trailing line feed'    => ["2026-11-01T12:00:00.123456Z\n"],
            'empty'                   => [''],
            'a relative time'         => ['now'],
            'a Unix timestamp'        => ['1793534400'],
            'a comma for the decimal' => ['2026-11-01T12:00:00,123456Z'],
        ];
    }

    /**
     * Each malformed or impossible instant is refused, never rolled over.
     *
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideMalformedInstants')]
    public function testRefusesAnInstantThatIsNotIsoUtcWithMicroseconds(string $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::INSTANT_MESSAGE);

        StoredTime::toStorage($value);
    }

    /**
     * Only an existing instant in the package's form is an instant.
     *
     * @return void
     */
    public function testIsInstantAcceptsOnlyTheCanonicalForm(): void
    {
        self::assertTrue(StoredTime::isInstant('2026-11-01T12:00:00.123456Z'));
        self::assertTrue(StoredTime::isInstant('2026-11-01T00:00:00.000000Z'));
        self::assertTrue(StoredTime::isInstant('2026-12-31T23:59:59.999999Z'));
        self::assertTrue(StoredTime::isInstant('2028-02-29T12:00:00.000000Z'));

        foreach (self::provideMalformedInstants() as $label => [$value]) {
            self::assertFalse(StoredTime::isInstant($value), $label);
        }
    }

    /**
     * Rows of `[stored value]`: malformed or impossible stored times.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedStoredTimes(): iterable
    {
        yield from [
            'a T separator'          => ['2026-11-01T12:00:00.123456'],
            'the package form'       => ['2026-11-01T12:00:00.123456Z'],
            'seven digits'           => ['2026-11-01 12:00:00.1234567'],
            'a point and no digits'  => ['2026-11-01 12:00:00.'],
            'the thirtieth of Feb'   => ['2026-02-30 00:00:00'],
            'a leap day in 2026'     => ['2026-02-29 00:00:00'],
            'hour 24'                => ['2026-11-01 24:00:00'],
            'minute 60'              => ['2026-11-01 12:60:00'],
            'a leap second'          => ['2026-12-31 23:59:60'],
            'a month of zero'        => ['2026-00-01 00:00:00'],
            'a day of zero'          => ['2026-11-00 00:00:00'],
            'no seconds'             => ['2026-11-01 12:00'],
            'a date alone'           => ['2026-11-01'],
            'a zone'                 => ['2026-11-01 12:00:00+00'],
            'a trailing Z'           => ['2026-11-01 12:00:00.123456Z'],
            'a leading space'        => [' 2026-11-01 12:00:00'],
            'a trailing line feed'   => ["2026-11-01 12:00:00\n"],
            'two spaces'             => ['2026-11-01  12:00:00'],
            'a five-digit year'      => ['12026-11-01 12:00:00'],
            'a single-digit hour'    => ['2026-11-01 1:00:00'],
            'the zero date of MySQL' => ['0000-00-00 00:00:00'],
            'empty'                  => [''],
        ];
    }

    /**
     * Each malformed or impossible stored time is refused, naming the form.
     *
     * @param  string  $stored
     * @return void
     */
    #[DataProvider('provideMalformedStoredTimes')]
    public function testRefusesAStoredTimeItCannotRead(string $stored): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(self::STORED_MESSAGE);

        StoredTime::fromStorage($stored);
    }

    /**
     * A stored time that cannot be read is refused as an instant too.
     *
     * @param  string  $stored
     * @return void
     */
    #[DataProvider('provideMalformedStoredTimes')]
    public function testRefusesAStoredTimeItCannotReadAsAnInstant(string $stored): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(self::STORED_MESSAGE);

        StoredTime::instant($stored);
    }

    /**
     * An instant in milliseconds since the epoch drops its last three
     * fractional digits.
     *
     * @return void
     */
    public function testAnInstantInEpochMillisecondsTruncatesItsMicroseconds(): void
    {
        self::assertSame(1793534400123, StoredTime::epochMilliseconds('2026-11-01T12:00:00.123456Z'));
        self::assertSame(1793534400999, StoredTime::epochMilliseconds('2026-11-01T12:00:00.999999Z'));
        self::assertSame(1793534400001, StoredTime::epochMilliseconds('2026-11-01T12:00:00.001000Z'));
        self::assertSame(-1000, StoredTime::epochMilliseconds('1969-12-31T23:59:59.000000Z'));
    }

    /**
     * An instant off the package's form is refused in epoch milliseconds.
     *
     * @return void
     */
    public function testRefusesAMalformedInstantInEpochMilliseconds(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::INSTANT_MESSAGE);

        StoredTime::epochMilliseconds('2026-11-01T12:00:00Z');
    }

    /**
     * The constructor is private; reflection invokes it to cover the line.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(StoredTime::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(StoredTime::class, $instance);
    }
}
