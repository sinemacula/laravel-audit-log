<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\RewrapStatus;

/**
 * Unit tests for how a rewrap ended: its cases and the values its record
 * stores.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RewrapStatus::class)]
final class RewrapStatusTest extends TestCase
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
            'COMPLETE' => 'complete',
            'PARTIAL'  => 'partial',
        ], array_column(RewrapStatus::cases(), 'value', 'name'));
    }

    /**
     * Every value reads back as its case.
     *
     * @return void
     */
    public function testEveryValueReadsBackAsItsCase(): void
    {
        foreach (RewrapStatus::cases() as $status) {
            self::assertSame($status, RewrapStatus::from($status->value));
        }
    }
}
