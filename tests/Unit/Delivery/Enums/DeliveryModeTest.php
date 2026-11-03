<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;

/**
 * Unit tests for the delivery mode enum: its cases and the values configuration
 * names them by.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliveryMode::class)]
final class DeliveryModeTest extends TestCase
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
            'SYNC'   => 'sync',
            'OUTBOX' => 'outbox',
        ], array_column(DeliveryMode::cases(), 'value', 'name'));
    }
}
