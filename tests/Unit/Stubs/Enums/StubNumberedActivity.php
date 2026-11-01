<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs\Enums;

/**
 * An integer-backed enum, which cannot give an event code because its values
 * are not strings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum StubNumberedActivity: int
{
    // A case whose value is an integer, not a code
    case FIRST = 1;
}
