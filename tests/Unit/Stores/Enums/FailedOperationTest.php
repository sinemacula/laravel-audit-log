<?php

declare(strict_types = 1);

namespace Tests\Unit\Stores\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;

/**
 * Unit tests for the failed operation enum's cases and values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailedOperation::class)]
final class FailedOperationTest extends TestCase
{
    /**
     * The cases and their values are pinned, in order.
     *
     * @return void
     */
    public function testTheStoredValuesArePinned(): void
    {
        self::assertSame([
            'FINALISE' => 'finalise',
            'STORE'    => 'store',
            'OUTBOX'   => 'outbox',
            'SPILL'    => 'spill',
            'NOTIFY'   => 'notify',
            'DRAIN'    => 'drain',
        ], array_column(FailedOperation::cases(), 'value', 'name'));
    }
}
