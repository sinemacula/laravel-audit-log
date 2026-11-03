<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorDriver;

/**
 * Unit tests for the anchor driver enum: its cases and the values the driver
 * setting names them by.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AnchorDriver::class)]
final class AnchorDriverTest extends TestCase
{
    /**
     * The cases, in order, with their values, so a renamed, reordered or added
     * case fails: no anchor is the string `null`, and the disk anchor is the
     * only other.
     *
     * @return void
     */
    public function testTheStoredValuesArePinned(): void
    {
        self::assertSame([
            'NONE' => 'null',
            'DISK' => 'disk',
        ], array_column(AnchorDriver::cases(), 'value', 'name'));
    }
}
