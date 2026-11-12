<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Config;

use Illuminate\Contracts\Config\Repository;

/**
 * Reads an integer setting, or the canonical decimal string `env()` returns for
 * one, within its range; anything else fails closed naming the key and the
 * range.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IntegerSetting
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The setting under the key, or the default when it is not set, as an
     * integer from its least to its greatest value.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $key
     * @param  int  $default
     * @param  int  $least
     * @param  int  $most
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public static function read(Repository $config, string $key, int $default, int $least, int $most): int
    {
        return self::from($key, $config->get($key, $default), $least, $most);
    }

    /**
     * The value already read for the key, as an integer from its least to its
     * greatest value.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  int  $least
     * @param  int  $most
     * @return ($least is positive-int ? positive-int : int)
     *
     * @throws \InvalidArgumentException
     */
    public static function from(string $key, mixed $value, int $least, int $most): int
    {
        $integer = self::parse($value);

        if ($integer === null || $integer < $least || $integer > $most) {
            throw new \InvalidArgumentException(sprintf('%s must be an integer from %d to %d.', $key, $least, $most));
        }

        return $integer;
    }

    /**
     * The integer the value names, or `null` when it names none. A string must
     * be exactly the decimal form of its integer, so one that overflows is
     * refused rather than saturated.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return ?int
     */
    public static function parse(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value;
        }

        return is_string($value) && (string) (int) $value === $value ? (int) $value : null;
    }
}
