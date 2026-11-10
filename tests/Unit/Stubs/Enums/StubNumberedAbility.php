<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs\Enums;

/**
 * An integer-backed enum naming an ability, which the Gate checks under its
 * integer value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum StubNumberedAbility: int
{
    // An ability whose value is an integer, not a name
    case PUBLISH = 1;
}
