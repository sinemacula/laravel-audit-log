<?php

declare(strict_types = 1);

namespace Tests\Unit\Console;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Console\MonitorSettings;

/**
 * Unit tests for the monitoring settings: the default of each, the bounds each
 * accepts, read again on every call, and the exact message each malformed value
 * fails closed with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MonitorSettings::class)]
final class MonitorSettingsTest extends TestCase
{
    /** @var array<string, array{0: string, 1: int, 2: int, 3: int}> Each reader, by its key under `audit-log.monitor.`: its method, default, least and greatest value. */
    private const array NUMBERS = [
        'seal_minutes'   => ['sealMinutes', 30, 5, 1440],
        'daily_minutes'  => ['dailyMinutes', 1560, 60, 10080],
        'outbox_minutes' => ['outboxMinutes', 15, 1, 1440],
    ];

    /**
     * With nothing set each limit takes its default: 30 minutes for sealing, a
     * day and two hours for the daily runs and 15 minutes for the outbox.
     *
     * @return void
     */
    public function testTheDefaultsApplyWhenNothingIsSet(): void
    {
        foreach (self::NUMBERS as [$method, $default]) {
            self::assertSame($default, self::number(new MonitorSettings(new Repository), $method), $method);
        }
    }

    /**
     * Each limit accepts its least and greatest value, as an integer or as the
     * digit string an environment line gives, and is read again on every call.
     *
     * @return void
     */
    public function testTheBoundsAreAccepted(): void
    {
        foreach (self::NUMBERS as $key => [$method, , $least, $most]) {
            foreach ([$least, $most, (string) $least, (string) $most] as $value) {
                self::assertSame((int) $value, self::number(self::settings([$key => $value]), $method), $key);
            }
        }

        $config   = new Repository(['audit-log' => ['monitor' => ['seal_minutes' => 5]]]);
        $settings = new MonitorSettings($config);

        self::assertSame(5, $settings->sealMinutes());

        $config->set('audit-log.monitor.seal_minutes', '45');

        self::assertSame(45, $settings->sealMinutes());
    }

    /**
     * Rows of `[key, method, value, message]`: one below the least and one
     * above the greatest value of each limit, and forms that name no integer.
     *
     * @return iterable<string, array{0: string, 1: string, 2: bool|float|int|string|null, 3: string}>
     */
    public static function provideLimitsOutOfRange(): iterable
    {
        foreach (self::NUMBERS as $key => [$method, , $least, $most]) {
            $message = sprintf('`audit-log.monitor.%s` must be an integer from %d to %d.', $key, $least, $most);

            yield $key . ', one below the least' => [$key, $method, $least - 1, $message];
            yield $key . ', one above the greatest' => [$key, $method, $most + 1, $message];
            yield $key . ', a fraction' => [$key, $method, 1.5, $message];
            yield $key . ', a padded digit string' => [$key, $method, ' ' . $most, $message];
            yield $key . ', null' => [$key, $method, null, $message];
            yield $key . ', true' => [$key, $method, true, $message];
        }
    }

    /**
     * Each malformed limit is refused with a message naming its key and range,
     * and never its value.
     *
     * @param  string  $key
     * @param  string  $method
     * @param  bool|float|int|string|null  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideLimitsOutOfRange')]
    public function testRefusesALimitOutsideItsRange(string $key, string $method, bool|float|int|string|null $value, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::number(self::settings([$key => $value]), $method);
    }

    /**
     * The value of the reader the method names.
     *
     * @param  \SineMacula\Laravel\AuditLog\Console\MonitorSettings  $settings
     * @param  string  $method
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private static function number(MonitorSettings $settings, string $method): int
    {
        return match ($method) {
            'sealMinutes'   => $settings->sealMinutes(),
            'dailyMinutes'  => $settings->dailyMinutes(),
            'outboxMinutes' => $settings->outboxMinutes(),
            default         => self::fail(sprintf('No reader is named %s.', $method)),
        };
    }

    /**
     * The settings over the monitoring configuration given.
     *
     * @param  array<string, bool|float|int|string|null>  $monitor
     * @return \SineMacula\Laravel\AuditLog\Console\MonitorSettings
     */
    private static function settings(array $monitor): MonitorSettings
    {
        return new MonitorSettings(new Repository(['audit-log' => ['monitor' => $monitor]]));
    }
}
