<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\ReinstateResult;

/**
 * Unit tests for what reinstating an owner returns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReinstateResult::class)]
final class ReinstateResultTest extends TestCase
{
    /** @var string The operation that reinstated the owner. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string The reinstatement's journal row id. */
    private const string REINSTATEMENT = '01932b4e-e000-7000-8000-000000000001';

    /** @var string The owner's fingerprint. */
    private const string FINGERPRINT = 'a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1';

    /**
     * A result keeps what it is given, is committed and is not yet recorded.
     *
     * @return void
     */
    public function testKeepsWhatItIsGiven(): void
    {
        $result = new ReinstateResult(self::OPERATION, self::REINSTATEMENT, self::FINGERPRINT, 'k1', 3);

        self::assertSame(self::OPERATION, $result->operationId);
        self::assertSame(self::REINSTATEMENT, $result->reinstatementId);
        self::assertSame(self::FINGERPRINT, $result->fingerprint);
        self::assertSame('k1', $result->fingerprintKey);
        self::assertSame(3, $result->generationFloor);
        self::assertTrue($result->committed);
        self::assertFalse($result->recorded);
    }

    /**
     * Recording is set on a copy, leaving the original unchanged.
     *
     * @return void
     */
    public function testWithRecordedKeepsEveryOtherField(): void
    {
        $result   = new ReinstateResult(self::OPERATION, self::REINSTATEMENT, self::FINGERPRINT, 'k1', 3);
        $recorded = $result->withRecorded(true);

        self::assertTrue($recorded->recorded);
        self::assertFalse($result->recorded);
        self::assertSame([...$result->toArray(), 'recorded' => true], $recorded->toArray());
        self::assertFalse($recorded->withRecorded(false)->recorded);
    }

    /**
     * The array form names each field under its snake-case key, in order.
     *
     * @return void
     */
    public function testTheArrayForm(): void
    {
        self::assertSame([
            'operation_id'      => self::OPERATION,
            'committed'         => true,
            'recorded'          => true,
            'reinstatement_id'  => self::REINSTATEMENT,
            'owner_fingerprint' => self::FINGERPRINT,
            'fingerprint_key'   => 'k1',
            'generation_floor'  => 0,
        ], (new ReinstateResult(self::OPERATION, self::REINSTATEMENT, self::FINGERPRINT, 'k1', 0, true))->toArray());
    }
}
