<?php

declare(strict_types = 1);

namespace Tests\Unit\Stores\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode;

/**
 * Unit tests for the failure mode enum: its cases and the values configuration
 * names them by.
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
     * The cases, in order, with the values configuration names them by, so a
     * renamed, reordered or added case fails.
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
