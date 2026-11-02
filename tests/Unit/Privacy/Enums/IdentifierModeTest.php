<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IdentifierMode;

/**
 * Unit tests for the identifier mode enum: its cases and the values
 * configuration names them by.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierMode::class)]
final class IdentifierModeTest extends TestCase
{
    /**
     * The cases, in order, with the values configuration names them by, so a
     * renamed, reordered or added case fails.
     *
     * @return void
     */
    public function testTheStoredValuesArePinned(): void
    {
        self::assertSame([
            'HASH' => 'hash',
            'DROP' => 'drop',
        ], array_column(IdentifierMode::cases(), 'value', 'name'));
    }
}
