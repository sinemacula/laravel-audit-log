<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\ReleaseResult;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for what releasing a hold returns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReleaseResult::class)]
final class ReleaseResultTest extends TestCase
{
    /** @var string The operation that released the hold. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string The hold's id. */
    private const string HOLD_ID = '01932b4e-d000-7000-8000-000000000001';

    /**
     * A result keeps what it is given and is always committed.
     *
     * @return void
     */
    public function testKeepsWhatItIsGiven(): void
    {
        $hold   = self::hold();
        $result = new ReleaseResult(self::OPERATION, false, $hold);

        self::assertSame(self::OPERATION, $result->operationId);
        self::assertTrue($result->committed);
        self::assertFalse($result->recorded);
        self::assertSame($hold, $result->hold);
    }

    /**
     * The array form holds the operation, both flags and the released hold.
     *
     * @return void
     */
    public function testTheArrayForm(): void
    {
        $hold = self::hold();

        self::assertSame([
            'operation_id' => self::OPERATION,
            'committed'    => true,
            'recorded'     => true,
            'hold'         => $hold->toArray(),
        ], (new ReleaseResult(self::OPERATION, true, $hold))->toArray());
    }

    /**
     * A hold of every entry, as it was while it was active.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Hold
     */
    private static function hold(): Hold
    {
        return new Hold(
            self::HOLD_ID,
            HoldScope::all(),
            HoldBasis::LEGAL_CLAIM,
            '2027-05-01T00:00:00.000000Z',
            '2026-11-02T09:00:00.000000Z',
            Reference::of('user', '7'),
            'case.review',
            'app:ticket-123',
            self::OPERATION,
            1,
        );
    }
}
