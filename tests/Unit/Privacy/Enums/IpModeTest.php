<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IpMode;

/**
 * Unit tests for the IP mode enum: its cases and the values configuration names
 * them by.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IpMode::class)]
final class IpModeTest extends TestCase
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
            'FULL'     => 'full',
            'TRUNCATE' => 'truncate',
            'HASH'     => 'hash',
            'DROP'     => 'drop',
            'ENCRYPT'  => 'encrypt',
        ], array_column(IpMode::cases(), 'value', 'name'));
    }
}
