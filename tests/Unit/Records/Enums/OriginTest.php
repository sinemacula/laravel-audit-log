<?php

declare(strict_types = 1);

namespace Tests\Unit\Records\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;

/**
 * Unit tests for the origin enum: its cases and the values a record stores.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Origin::class)]
final class OriginTest extends TestCase
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
            'HTTP'    => 'http',
            'CONSOLE' => 'console',
            'QUEUE'   => 'queue',
        ], array_column(Origin::cases(), 'value', 'name'));
    }
}
