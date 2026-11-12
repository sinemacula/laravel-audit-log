<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;

/**
 * Unit tests for the basis a hold is placed on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HoldBasis::class)]
final class HoldBasisTest extends TestCase
{
    /**
     * The cases and their values are pinned, in order.
     *
     * @return void
     */
    public function testTheStoredValuesArePinned(): void
    {
        self::assertSame([
            'LEGAL_CLAIM'   => 'legal_claim',
            'REGULATORY'    => 'regulatory',
            'INVESTIGATION' => 'investigation',
            'OTHER'         => 'other',
        ], array_column(HoldBasis::cases(), 'value', 'name'));
    }

    /**
     * Every value fits the 32-character `basis` column and reads back.
     *
     * @return void
     */
    public function testEveryValueFitsItsColumn(): void
    {
        foreach (HoldBasis::cases() as $basis) {
            self::assertLessThanOrEqual(32, strlen($basis->value));
            self::assertSame($basis, HoldBasis::from($basis->value));
        }
    }
}
