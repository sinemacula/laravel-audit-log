<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorDriver;

/**
 * Unit tests for the anchor driver enum.
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
     * The cases and their stored values, in order: `null` and `disk`.
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
