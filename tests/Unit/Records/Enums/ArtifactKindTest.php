<?php

declare(strict_types = 1);

namespace Tests\Unit\Records\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;

/**
 * Unit tests for the artifact kind enum: the values an artifact's row and its
 * record's descriptor store, and which kinds may count no member.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ArtifactKind::class)]
final class ArtifactKindTest extends TestCase
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
            'BULK'       => 'bulk',
            'DISCLOSURE' => 'disclosure',
            'EXPORT'     => 'export',
        ], array_column(ArtifactKind::cases(), 'value', 'name'));
    }

    /**
     * Only a bulk operation needs a member: a disclosure or an export may count
     * none.
     *
     * @return void
     */
    public function testOnlyABulkNeedsAMember(): void
    {
        self::assertSame(
            ['bulk' => false, 'disclosure' => true, 'export' => true],
            array_combine(
                array_column(ArtifactKind::cases(), 'value'),
                array_map(static fn (ArtifactKind $kind): bool => $kind->allowsEmpty(), ArtifactKind::cases()),
            ),
        );
    }
}
