<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;

/**
 * Unit tests for the integrity status enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegrityStatus::class)]
final class IntegrityStatusTest extends TestCase
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
            'VALID'        => 'valid',
            'PRUNED'       => 'pruned',
            'INCOMPLETE'   => 'incomplete',
            'UNVERIFIABLE' => 'unverifiable',
            'TAMPERED'     => 'tampered',
        ], array_column(IntegrityStatus::cases(), 'value', 'name'));
    }

    /**
     * Severity runs from 0 for `valid` to 4 for `tampered`, in case order.
     *
     * @return void
     */
    public function testSeverityOrdersTheStatuses(): void
    {
        self::assertSame([
            'valid'        => 0,
            'pruned'       => 1,
            'incomplete'   => 2,
            'unverifiable' => 3,
            'tampered'     => 4,
        ], array_combine(
            array_column(IntegrityStatus::cases(), 'value'),
            array_map(static fn (IntegrityStatus $status): int => $status->severity(), IntegrityStatus::cases()),
        ));

        foreach (IntegrityStatus::cases() as $failing) {
            foreach (IntegrityStatus::cases() as $passing) {
                if (!$failing->isFailure() || $passing->isFailure()) {
                    continue;
                }

                self::assertGreaterThan($passing->severity(), $failing->severity(), "{$failing->value} over {$passing->value}");
            }
        }
    }

    /**
     * Only `incomplete`, `unverifiable` and `tampered` fail a verification.
     *
     * @return void
     */
    public function testOnlyIncompleteUnverifiableAndTamperedFail(): void
    {
        self::assertSame(
            ['incomplete', 'unverifiable', 'tampered'],
            array_values(array_map(
                static fn (IntegrityStatus $status): string => $status->value,
                array_filter(IntegrityStatus::cases(), static fn (IntegrityStatus $status): bool => $status->isFailure()),
            )),
        );
    }
}
