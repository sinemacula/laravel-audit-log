<?php

declare(strict_types = 1);

namespace Tests\Unit\Records\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;

/**
 * Unit tests for the timing enum: its cases and the values the builder's
 * snapshot carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Timing::class)]
final class TimingTest extends TestCase
{
    /**
     * The cases, in order, with their values, so a renamed, reordered or added
     * case fails.
     *
     * @return void
     */
    public function testTheCasesAndTheirStoredValues(): void
    {
        self::assertSame([
            'AFTER_COMMIT'  => 'after_commit',
            'IMMEDIATE'     => 'immediate',
            'TRANSACTIONAL' => 'transactional',
        ], array_column(Timing::cases(), 'value', 'name'));
    }
}
