<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs\Enums;

/**
 * A unit enum, with no backing value, that the value normaliser writes as its
 * name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum StubSuit
{
    // A suit with no backing value
    case HEARTS;
}
