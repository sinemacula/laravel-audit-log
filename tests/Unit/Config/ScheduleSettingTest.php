<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Config\ScheduleSetting;

/**
 * Unit tests for the schedule setting reader every settings class shares: the
 * default, `null` or empty for none, a cron expression, and the message it
 * fails with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ScheduleSetting::class)]
final class ScheduleSettingTest extends TestCase
{
    /** @var string The key the tests read. */
    private const string KEY = 'audit-log.example.schedule';

    /**
     * A setting that is not configured takes the default, which the caller
     * chooses, `null` included.
     *
     * @return void
     */
    public function testTheDefaultAppliesWhenTheKeyIsNotSet(): void
    {
        self::assertSame('30 3 * * *', ScheduleSetting::read(new Repository, self::KEY, '30 3 * * *'));
        self::assertNull(ScheduleSetting::read(new Repository, self::KEY, null));
    }

    /**
     * Rows of `[value, what the reader returns]`: `null` and empty schedule
     * nothing, and a cron expression is returned as it is.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideAcceptedValues(): iterable
    {
        yield from [
            'null'           => [null, null],
            'empty'          => ['', null],
            'a cron'         => ['*/5 * * * *', '*/5 * * * *'],
            'a named cron'   => ['@daily', '@daily'],
            'a nightly cron' => ['30 3 * * *', '30 3 * * *'],
        ];
    }

    /**
     * Each accepted value is read as the schedule it names, or none.
     *
     * @param  ?string  $value
     * @param  ?string  $expected
     * @return void
     */
    #[DataProvider('provideAcceptedValues')]
    public function testReadsACronOrNone(?string $value, ?string $expected): void
    {
        $config = new Repository([]);

        $config->set(self::KEY, $value);

        self::assertSame($expected, ScheduleSetting::read($config, self::KEY, '30 3 * * *'));
    }

    /**
     * Rows of `[value]`: anything that is not a cron expression, `null` or
     * empty.
     *
     * @return iterable<string, array{0: array<int, int>|bool|int|string}>
     */
    public static function provideRefusedValues(): iterable
    {
        yield from [
            'not a cron' => ['every night at org_01'],
            'six fields' => ['* * * * * * *'],
            'an integer' => [5],
            'false'      => [false],
            'a list'     => [[1, 2]],
            'whitespace' => [' '],
        ];
    }

    /**
     * Each refused value fails closed, naming the key and never the value.
     *
     * @param  array<int, int>|bool|int|string  $value
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testAnythingElseIsRefusedNamingTheKey(array|bool|int|string $value): void
    {
        $config = new Repository([]);

        $config->set(self::KEY, $value);

        try {
            ScheduleSetting::read($config, self::KEY, null);

            self::fail('The value was read.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('`audit-log.example.schedule` must be a cron expression, or null or empty to schedule nothing.', $exception->getMessage());
        }
    }
}
