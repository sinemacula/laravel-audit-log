<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs\Enums;

/**
 * A string-backed enum the value normaliser writes as its value, cleaned.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum StubColour: string
{
    // A colour backed by a string
    case RED = 'red';

    // A colour whose value holds a line feed and a bidi override
    case DIRTY = "a\nb\u{202E}";
}
