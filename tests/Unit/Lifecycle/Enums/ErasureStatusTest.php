<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;

/**
 * Unit tests for how an erasure that was not refused ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ErasureStatus::class)]
final class ErasureStatusTest extends TestCase
{
    /**
     * The cases and their values are pinned, in order.
     *
     * @return void
     */
    public function testTheStoredValuesArePinned(): void
    {
        self::assertSame([
            'COMPLETE'       => 'complete',
            'PARTIAL'        => 'partial',
            'ALREADY_ERASED' => 'already_erased',
        ], array_column(ErasureStatus::cases(), 'value', 'name'));
    }

    /**
     * Every value reads back as its case.
     *
     * @return void
     */
    public function testEveryValueReadsBackAsItsCase(): void
    {
        foreach (ErasureStatus::cases() as $status) {
            self::assertSame($status, ErasureStatus::from($status->value));
        }
    }
}
