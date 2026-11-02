<?php

declare(strict_types = 1);

namespace Tests\Unit\Casts;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Casts\UtcInstant;

/**
 * Unit tests for the UTC instant cast: a stored time read as a UTC instant with
 * its microseconds whatever the default time zone, an instant written in the
 * stored form in UTC, `null` kept both ways, and the values it refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UtcInstant::class)]
final class UtcInstantTest extends TestCase
{
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
     * Rows of `[stored time, the instant it reads as]`: a stored time keeps its
     * microseconds, and one with fewer fractional digits, as PostgreSQL returns
     * it, or none, reads right-padded to six.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideStoredTimes(): iterable
    {
        yield from [
            'six fractional digits' => ['2026-11-01 12:00:00.123456', '2026-11-01T12:00:00.123456Z'],
            'one fractional digit'  => ['2026-11-01 12:00:00.1', '2026-11-01T12:00:00.100000Z'],
            'no fractional digits'  => ['2026-11-01 12:00:00', '2026-11-01T12:00:00.000000Z'],
        ];
    }

    /**
     * A stored time reads as a `CarbonImmutable` instant in UTC with its
     * microseconds, even when the default time zone is not UTC.
     *
     * @param  string  $stored
     * @param  string  $instant
     * @return void
     */
    #[DataProvider('provideStoredTimes')]
    public function testReadsAStoredTimeAsAUtcInstant(string $stored, string $instant): void
    {
        date_default_timezone_set('Pacific/Auckland');

        $read = (new UtcInstant)->get(self::model(), 'occurred_at', $stored, ['occurred_at' => $stored]);

        self::assertInstanceOf(CarbonImmutable::class, $read);
        self::assertSame('UTC', $read->getTimezone()->getName());
        self::assertSame($instant, $read->format('Y-m-d\TH:i:s.u\Z'));
    }

    /**
     * A stored `null`, a time a nullable column lacks, reads as `null`.
     *
     * @return void
     */
    public function testReadsNullAsNull(): void
    {
        self::assertNull((new UtcInstant)->get(self::model(), 'occurred_at', null, ['occurred_at' => null]));
    }

    /**
     * Rows of `[stored value]`: values that are not a stored time, whether they
     * are not a string or not in the stored form.
     *
     * @return iterable<string, array{0: bool|\DateTimeImmutable|float|int|string}>
     */
    public static function provideMalformedStoredValues(): iterable
    {
        yield from [
            'an integer'        => [1793534400],
            'a float'           => [1793534400.5],
            'a boolean'         => [true],
            'an instant object' => [new \DateTimeImmutable('2026-11-01 12:00:00', new \DateTimeZone('UTC'))],
            'the package form'  => ['2026-11-01T12:00:00.123456Z'],
            'seven digits'      => ['2026-11-01 12:00:00.1234567'],
            'a date alone'      => ['2026-11-01'],
            'an impossible day' => ['2026-02-30 12:00:00'],
            'empty'             => [''],
        ];
    }

    /**
     * A value that is not a stored time is refused rather than read in some
     * other form, and the message never repeats the value.
     *
     * @param  bool|\DateTimeImmutable|float|int|string  $value
     * @return void
     */
    #[DataProvider('provideMalformedStoredValues')]
    public function testRefusesAValueThatIsNotAStoredTime(bool|\DateTimeImmutable|float|int|string $value): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(self::STORED_MESSAGE);

        (new UtcInstant)->get(self::model(), 'recorded_at', $value, ['recorded_at' => $value]);
    }

    /**
     * Rows of `[instant, the stored time it writes as]`: an instant in any time
     * zone, mutable or not, is written in UTC with six fractional digits.
     *
     * @return iterable<string, array{0: \DateTimeInterface, 1: string}>
     */
    public static function provideInstants(): iterable
    {
        yield from [
            'an Auckland instant'   => [CarbonImmutable::parse('2026-11-02 01:00:00.123456', 'Pacific/Auckland'), '2026-11-01 12:00:00.123456'],
            'a mutable instant'     => [new \DateTime('2026-11-01 07:00:00.5', new \DateTimeZone('America/New_York')), '2026-11-01 12:00:00.500000'],
            'a whole-second UTC'    => [new \DateTimeImmutable('2026-11-01 12:00:00', new \DateTimeZone('UTC')), '2026-11-01 12:00:00.000000'],
            'an offset, not a zone' => [new \DateTimeImmutable('2026-11-01T13:30:00.000001+01:30'), '2026-11-01 12:00:00.000001'],
        ];
    }

    /**
     * An instant is written as the database stores it, in UTC with its
     * microseconds, whatever its own time zone.
     *
     * @param  \DateTimeInterface  $instant
     * @param  string  $stored
     * @return void
     */
    #[DataProvider('provideInstants')]
    public function testWritesAnInstantInUtcWithMicroseconds(\DateTimeInterface $instant, string $stored): void
    {
        self::assertSame($stored, (new UtcInstant)->set(self::model(), 'occurred_at', $instant, []));
    }

    /**
     * `null` is written as `null`.
     *
     * @return void
     */
    public function testWritesNullAsNull(): void
    {
        self::assertNull((new UtcInstant)->set(self::model(), 'occurred_at', null, []));
    }

    /**
     * A value that is not an instant is refused, naming the attribute, rather
     * than written as it is; a string in the stored form included, since only
     * the cast decides that form.
     *
     * @return void
     */
    public function testRefusesToWriteAValueThatIsNotAnInstant(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`recorded_at` must be set to an instant or null.');

        (new UtcInstant)->set(self::model(), 'recorded_at', '2026-11-01 12:00:00.123456', []);
    }

    /**
     * The cast keeps no state, so it is a final readonly class.
     *
     * @return void
     */
    public function testIsAFinalReadonlyClass(): void
    {
        $class = new \ReflectionClass(UtcInstant::class);

        self::assertTrue($class->isFinal());
        self::assertTrue($class->isReadOnly());
    }

    /**
     * A model the cast reads and writes for; the cast never uses it.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function model(): Model
    {
        return new class extends Model {};
    }
}
