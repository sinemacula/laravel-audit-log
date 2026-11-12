<?php

declare(strict_types = 1);

namespace Tests\Unit\Stores\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode;

/**
 * Unit tests for the failure mode enum's cases and values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailureMode::class)]
final class FailureModeTest extends TestCase
{
    /**
     * The cases and their configuration values are pinned, in order.
     *
     * @return void
     */
    public function testTheStoredValuesArePinned(): void
    {
        self::assertSame([
            'REPORT' => 'report',
            'THROW'  => 'throw',
        ], array_column(FailureMode::cases(), 'value', 'name'));
    }
}
