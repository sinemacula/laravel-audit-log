<?php

declare(strict_types = 1);

namespace Tests\Concerns;

/**
 * Sorts a decoded JSON value's object keys, as MySQL reorders them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait SortsJsonObjectKeys
{
    /**
     * The value with every map's keys sorted, as MySQL reorders JSON object
     * keys.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return mixed
     */
    private static function keysSorted(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }

        if (!array_is_list($value)) {
            ksort($value, SORT_STRING);
        }

        return array_map(self::keysSorted(...), $value);
    }
}
