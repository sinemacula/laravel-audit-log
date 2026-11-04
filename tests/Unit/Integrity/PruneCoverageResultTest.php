<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\PruneCoverageResult;

/**
 * Unit tests for what a seal's prune records say of its members: the findings,
 * the missing members covered and the present members to read again, each kept
 * as given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneCoverageResult::class)]
final class PruneCoverageResultTest extends TestCase
{
    /**
     * The result keeps its findings, its covered ids and its ids to read again
     * as given, in their order, and an empty result keeps none.
     *
     * @return void
     */
    public function testKeepsItsFields(): void
    {
        $findings = [[Finding::PRUNE_RECORD, '01932b4e-9000-7000-8000-000000000001'], [Finding::MISSING_ENTRY, '01932b4e-8a40-7000-8000-000000000002']];
        $result   = new PruneCoverageResult($findings, ['01932b4e-8a40-7000-8000-000000000003', '01932b4e-8a40-7000-8000-000000000001'], ['01932b4e-8a40-7000-8000-000000000004']);

        self::assertSame($findings, $result->findings);
        self::assertSame(['01932b4e-8a40-7000-8000-000000000003', '01932b4e-8a40-7000-8000-000000000001'], $result->covered);
        self::assertSame(['01932b4e-8a40-7000-8000-000000000004'], $result->recheck);

        $empty = new PruneCoverageResult([], [], []);

        self::assertSame([[], [], []], [$empty->findings, $empty->covered, $empty->recheck]);
    }
}
