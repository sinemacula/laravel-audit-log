<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\SealBatch;
use SineMacula\Laravel\AuditLog\Integrity\SealCursor;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;

/**
 * Unit tests for what one sealing attempt did.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SealBatch::class)]
final class SealBatchTest extends TestCase
{
    /**
     * An attempt that read nothing has no seal and no position, and is
     * exhausted.
     *
     * @return void
     */
    public function testAnEmptyBatchIsExhausted(): void
    {
        $batch = new SealBatch(null, null, 0, 0, null, 100);

        self::assertNull($batch->seal);
        self::assertNull($batch->digest);
        self::assertSame(0, $batch->read);
        self::assertSame(0, $batch->skipped);
        self::assertNull($batch->last);
        self::assertTrue($batch->exhausted);
    }

    /**
     * An attempt keeps what it wrote and read, and is exhausted only when it
     * read fewer rows than its limit.
     *
     * @return void
     */
    public function testKeepsWhatTheAttemptDid(): void
    {
        $seal = new SealEnvelope(
            logId: 'app-eu-1',
            id: '01932b4e-9000-7000-8000-000000000001',
            sequence: 1,
            previousId: null,
            previousDigest: null,
            memberCount: 2,
            membersDigest: str_repeat('a', 64),
            firstRecordedAt: '2026-10-31T23:34:56.890123Z',
            lastRecordedAt: '2026-10-31T23:35:00.000001Z',
            sealedAt: '2026-10-31T23:40:00.000000Z',
            keyId: 'k2026',
        );

        $last  = SealCursor::after('2026-10-31 23:35:00.000001', '01932b4e-8a40-7000-8000-000000000003');
        $full  = new SealBatch($seal, str_repeat('b', 64), 3, 1, $last, 3);
        $short = new SealBatch($seal, str_repeat('b', 64), 2, 0, $last, 3);

        self::assertSame($seal, $full->seal);
        self::assertSame(str_repeat('b', 64), $full->digest);
        self::assertSame(3, $full->read);
        self::assertSame(1, $full->skipped);
        self::assertSame($last, $full->last);
        self::assertFalse($full->exhausted);
        self::assertTrue($short->exhausted);
    }
}
