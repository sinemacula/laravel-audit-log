<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;

/**
 * Unit tests for how a prune run ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneStatus::class)]
final class PruneStatusTest extends TestCase
{
    /**
     * The cases and their values are pinned, in order.
     *
     * @return void
     */
    public function testTheStoredValuesArePinned(): void
    {
        self::assertSame([
            'COMPLETE' => 'complete',
            'PARTIAL'  => 'partial',
            'FAILED'   => 'failed',
        ], array_column(PruneStatus::cases(), 'value', 'name'));
    }

    /**
     * Every value reads back as its case.
     *
     * @return void
     */
    public function testEveryValueReadsBackAsItsCase(): void
    {
        foreach (PruneStatus::cases() as $status) {
            self::assertSame($status, PruneStatus::from($status->value));
        }
    }
}
