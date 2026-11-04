<?php

declare(strict_types = 1);

namespace Tests\Unit\Access\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;

/**
 * Unit tests for the read purpose enum: its cases and the values the record of
 * a read stores.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReadPurpose::class)]
final class ReadPurposeTest extends TestCase
{
    /**
     * The cases, in order, with the values the record of a read stores, so a
     * renamed, reordered or added case fails.
     *
     * @return void
     */
    public function testTheStoredValues(): void
    {
        self::assertSame([
            'READ'   => 'read',
            'COUNT'  => 'count',
            'EXPORT' => 'export',
            'VERIFY' => 'verify',
        ], array_column(ReadPurpose::cases(), 'value', 'name'));
    }
}
