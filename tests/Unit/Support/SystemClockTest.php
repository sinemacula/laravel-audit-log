<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Support\SystemClock;

/**
 * Unit tests for the system clock, always in UTC and honouring a frozen clock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SystemClock::class)]
final class SystemClockTest extends TestCase
{
    /** @var string The default time zone before the test, restored after it. */
    private string $defaultTimezone = 'UTC';

    /**
     * Remember the default time zone, so a test may change it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->defaultTimezone = date_default_timezone_get();
    }

    /**
     * Release the frozen clock and restore the default time zone.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        date_default_timezone_set($this->defaultTimezone);

        parent::tearDown();
    }

    /**
     * The current instant is in UTC whatever the default time zone.
     *
     * @return void
     */
    public function testNowIsInUtc(): void
    {
        date_default_timezone_set('Pacific/Auckland');

        $before = microtime(true);
        $now    = (new SystemClock)->now();
        $after  = microtime(true);

        self::assertSame('UTC', $now->getTimezone()->getName());
        self::assertSame('+00:00', $now->format('P'));
        self::assertGreaterThanOrEqual(floor($before), (float) $now->getTimestamp());
        self::assertLessThanOrEqual(ceil($after), (float) $now->getTimestamp());
    }

    /**
     * A test clock frozen in Auckland is honoured as the same UTC instant.
     *
     * @return void
     */
    public function testAFrozenTestClockIsHonoured(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::createFromFormat('Y-m-d H:i:s.u', '2026-11-02 01:00:00.123456', 'Pacific/Auckland'));

        $now = (new SystemClock)->now();

        self::assertSame('2026-11-01T12:00:00.123456+00:00', $now->format('Y-m-d\TH:i:s.uP'));
        self::assertSame('UTC', $now->getTimezone()->getName());
    }

    /**
     * The system clock is the package's clock.
     *
     * @return void
     */
    public function testImplementsTheClock(): void
    {
        self::assertInstanceOf(Clock::class, new SystemClock);
    }
}
