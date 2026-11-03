<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryOutcome;

/**
 * Unit tests for the delivery outcome enum: its cases and their values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliveryOutcome::class)]
final class DeliveryOutcomeTest extends TestCase
{
    /**
     * The cases, in order, with their values, so a renamed, reordered or added
     * case fails.
     *
     * @return void
     */
    public function testTheStoredValuesArePinned(): void
    {
        self::assertSame([
            'COMPLETE'   => 'complete',
            'INCOMPLETE' => 'incomplete',
            'STALE'      => 'stale',
        ], array_column(DeliveryOutcome::cases(), 'value', 'name'));
    }
}
