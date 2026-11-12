<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;

/**
 * Unit tests for the anchoring status enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AnchorStatus::class)]
final class AnchorStatusTest extends TestCase
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
            'ANCHORED'     => 'anchored',
            'UNANCHORED'   => 'unanchored',
            'UNAVAILABLE'  => 'unavailable',
            'CONTRADICTED' => 'contradicted',
        ], array_column(AnchorStatus::cases(), 'value', 'name'));
    }

    /**
     * Only `anchored` confirms a seal.
     *
     * @return void
     */
    public function testOnlyAnchoredIsConfirmed(): void
    {
        self::assertSame([
            'anchored'     => true,
            'unanchored'   => false,
            'unavailable'  => false,
            'contradicted' => false,
        ], array_combine(
            array_column(AnchorStatus::cases(), 'value'),
            array_map(static fn (AnchorStatus $status): bool => $status->isConfirmed(), AnchorStatus::cases()),
        ));
    }
}
