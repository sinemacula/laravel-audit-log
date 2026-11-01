<?php

declare(strict_types = 1);

namespace Tests\Unit\Records\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;

/**
 * Unit tests for the outcome enum: its cases and the values a record stores.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Outcome::class)]
final class OutcomeTest extends TestCase
{
    /**
     * The cases, in order, with the values a record stores, so a renamed,
     * reordered or added case fails.
     *
     * @return void
     */
    public function testTheCasesAndTheirStoredValues(): void
    {
        self::assertSame([
            'SUCCESS' => 'success',
            'FAILURE' => 'failure',
            'DENIED'  => 'denied',
        ], array_column(Outcome::cases(), 'value', 'name'));
    }
}
