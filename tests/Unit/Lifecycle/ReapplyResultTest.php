<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\ReapplyResult;

/**
 * Unit tests for what erasing again after a restore reports: it is reconciled
 * exactly when it names the reconciliation's journal row, and its map gives
 * every count, the file's digest and the anchor's head under snake-case keys,
 * naming no owner.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReapplyResult::class)]
final class ReapplyResultTest extends TestCase
{
    /** @var string The operation every result names. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /**
     * A result naming its reconciliation is reconciled, and its map gives
     * everything it holds.
     *
     * @return void
     */
    public function testAReconciledResultNamesItsRowAndTheAnchoredHead(): void
    {
        $result = new ReapplyResult(self::OPERATION, str_repeat('f', 64), 3, 2, 1, 0, 0, 0, true, '01932b4e-9000-7000-8000-0000000000e1', 12, str_repeat('d', 64));

        self::assertTrue($result->reconciled);
        self::assertSame([
            'operation_id'      => self::OPERATION,
            'reconciled'        => true,
            'reconciliation_id' => '01932b4e-9000-7000-8000-0000000000e1',
            'file_sha256'       => str_repeat('f', 64),
            'owners'            => 3,
            'erased'            => 2,
            'already_erased'    => 1,
            'partial'           => 0,
            'refused'           => 0,
            'rejected'          => 0,
            'recorded'          => true,
            'anchored_sequence' => 12,
            'anchored_digest'   => str_repeat('d', 64),
        ], $result->toArray());
    }

    /**
     * A result naming no reconciliation is not reconciled, and names no
     * anchored head, whatever its counts.
     *
     * @return void
     */
    public function testAnUnreconciledResultNamesNoRow(): void
    {
        $result = new ReapplyResult(self::OPERATION, str_repeat('f', 64), 4, 1, 0, 1, 1, 2, false);

        self::assertFalse($result->reconciled);
        self::assertSame([null, null, null], [$result->reconciliationId, $result->anchoredSequence, $result->anchoredDigest]);
        self::assertSame([false, 1, 1, 2, false], [
            $result->toArray()['reconciled'], $result->toArray()['partial'], $result->toArray()['refused'], $result->toArray()['rejected'], $result->toArray()['recorded'],
        ]);
    }
}
