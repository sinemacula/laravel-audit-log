<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;

/**
 * Unit tests for the basis a hold is placed on: its cases and the values the
 * journal and the holds projection store.
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
     * The cases, in order, with their values, so a renamed, reordered or added
     * case fails.
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
     * Every value fits the holds table's `basis` column of 32 characters and
     * reads back as its case.
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
