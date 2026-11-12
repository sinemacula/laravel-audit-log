<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;

/**
 * The monitoring settings `audit-log:check --freshness` judges progress by,
 * read and validated on every call.
 *
 * A malformed setting throws an `InvalidArgumentException` naming the key,
 * never the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MonitorSettings
{
    /** @var string Prefix of every monitoring setting's key. */
    private const string PREFIX = 'audit-log.monitor.';

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each setting, in minutes, by its key under the prefix. */
    private const array NUMBERS = [
        'seal_minutes'   => [30, 5, 1440],
        'daily_minutes'  => [1560, 60, 10080],
        'outbox_minutes' => [15, 1, 1440],
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the settings are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * How old the last seal run may grow before sealing is stale, in minutes,
     * from 5 to 1440.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function sealMinutes(): int
    {
        return $this->number('seal_minutes');
    }

    /**
     * How old the last sweep, verification and prune may grow before each is
     * stale, in minutes, from 60 to 10080: a day and two hours by default.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function dailyMinutes(): int
    {
        return $this->number('daily_minutes');
    }

    /**
     * How long the oldest outbox row may wait for a drain before the backlog is
     * stale, in minutes, from 1 to 1440.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function outboxMinutes(): int
    {
        return $this->number('outbox_minutes');
    }

    /**
     * The setting under the key, within its range.
     *
     * @param  key-of<self::NUMBERS>  $setting
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function number(string $setting): int
    {
        [$default, $least, $most] = self::NUMBERS[$setting];

        $key = self::PREFIX . $setting;

        return IntegerSetting::from('`' . $key . '`', $this->config->get($key, $default), $least, $most);
    }
}
