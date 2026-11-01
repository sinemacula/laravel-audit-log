<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs\Enums;

/**
 * An integer-backed enum the value normaliser writes as its value, kept within
 * the safe integer range.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum StubPriority: int
{
    // A priority backed by an integer
    case HIGH = 1;

    // A priority far beyond the safe integer range
    case HUGE = PHP_INT_MAX;

    // A priority one below the negative bound of the safe integer range
    case BELOW = -9007199254740992;
}
