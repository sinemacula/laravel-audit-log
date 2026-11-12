<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Querying\Enums\Acknowledgement;

/**
 * Unit tests for the acknowledgement enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Acknowledgement::class)]
final class AcknowledgementTest extends TestCase
{
    /**
     * The cases and their values are pinned, in order.
     *
     * @return void
     */
    public function testTheStoredValues(): void
    {
        self::assertSame([
            'STORED'   => 'stored',
            'ACCEPTED' => 'accepted',
        ], array_column(Acknowledgement::cases(), 'value', 'name'));
    }
}
