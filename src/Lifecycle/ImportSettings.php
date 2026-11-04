<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;

/**
 * The import settings, read from configuration on every call and validated as
 * they are read: how many lines one chunk of an import writes
 * (`audit-log.import.chunk`), how far ahead of the clock an imported entry may
 * claim to have happened (`audit-log.import.max_skew_seconds`), and the longest
 * line an import reads (`audit-log.import.max_line_bytes`).
 *
 * A missing number takes its default; a number is an integer, or the canonical
 * digit string an environment line gives, within its range. Every malformed
 * value fails closed with an `InvalidArgumentException` naming the key and
 * never the value. How long a running import may stand still before it is
 * called stale is fixed, not configured.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ImportSettings
{
    /** @var int How long a `running` batch may go without moving before it is stale, in seconds: an hour. */
    public const int STALE_SECONDS = 3600;

    /** @var string Prefix of every import setting's key. */
    private const string PREFIX = 'audit-log.import.';

    /** @var array<string, array{0: int, 1: int, 2: int}> Default, least and greatest value of each numeric setting, by its key under the prefix. */
    private const array NUMBERS = [
        'chunk'            => [500, 100, 5000],
        'max_skew_seconds' => [300, 0, 86400],
        'max_line_bytes'   => [1048576, 1024, 16777216],
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
     * The most lines one chunk of an import writes, in one transaction, from
     * 100 to 5000.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function chunk(): int
    {
        return $this->number('chunk');
    }

    /**
     * How far after the clock an imported entry may claim to have happened, in
     * seconds, from 0 to a day.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxSkewSeconds(): int
    {
        return $this->number('max_skew_seconds');
    }

    /**
     * The longest line an import reads, in bytes, from 1 KiB to 16 MiB; a
     * longer one is rejected without being held.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxLineBytes(): int
    {
        return $this->number('max_line_bytes');
    }

    /**
     * Read every import setting, failing on the first malformed one.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        foreach (array_keys(self::NUMBERS) as $setting) {
            $this->number($setting);
        }
    }

    /**
     * The numeric setting under the key, within its range.
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
