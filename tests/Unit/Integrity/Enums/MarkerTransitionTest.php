<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition;

/**
 * Unit tests for the marker transition enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MarkerTransition::class)]
final class MarkerTransitionTest extends TestCase
{
    /**
     * The cases, in order, with their stored values, so a renamed, reordered or
     * added case fails.
     *
     * @return void
     */
    public function testTheStoredValues(): void
    {
        self::assertSame([
            'ERASED'     => 'erased',
            'REINSTATED' => 'reinstated',
        ], array_column(MarkerTransition::cases(), 'value', 'name'));
    }

    /**
     * Every stored value fits the 16 characters of the marker's `transition`
     * column.
     *
     * @return void
     */
    public function testEveryValueFitsItsColumn(): void
    {
        foreach (MarkerTransition::cases() as $transition) {
            self::assertLessThanOrEqual(16, strlen($transition->value), $transition->name);
        }
    }
}
