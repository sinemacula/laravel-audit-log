<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealResult;

/**
 * Unit tests for the tally of one seal run.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SealResult::class)]
final class SealResultTest extends TestCase
{
    /**
     * A run starts with nothing counted, no sequence and no complete sweep.
     *
     * @return void
     */
    public function testStartsEmpty(): void
    {
        $result = new SealResult;

        self::assertSame(0, $result->seals());
        self::assertSame(0, $result->entries());
        self::assertSame(0, $result->retries());
        self::assertSame(0, $result->skippedEntries());
        self::assertNull($result->firstSequence());
        self::assertNull($result->lastSequence());
        self::assertFalse($result->isSweepComplete());
    }

    /**
     * Each seal added counts once with the entries it holds, and each retry
     * once.
     *
     * @return void
     */
    public function testCountsSealsEntriesAndRetries(): void
    {
        $result = new SealResult;

        $result->added(self::seal(1, 3));
        $result->added(self::seal(2, 5));
        $result->retried();
        $result->retried();
        $result->retried();

        self::assertSame(2, $result->seals());
        self::assertSame(8, $result->entries());
        self::assertSame(3, $result->retries());
        self::assertSame(0, $result->skippedEntries());
    }

    /**
     * The first sequence is the first seal added's, and the last the latest
     * added's.
     *
     * @return void
     */
    public function testKeepsTheFirstAndLastSequence(): void
    {
        $result = new SealResult;

        $result->added(self::seal(4, 1));

        self::assertSame(4, $result->firstSequence());
        self::assertSame(4, $result->lastSequence());

        $result->added(self::seal(5, 1));
        $result->added(self::seal(6, 1));

        self::assertSame(4, $result->firstSequence());
        self::assertSame(6, $result->lastSequence());
    }

    /**
     * A sweep that reached the end of the table is marked so.
     *
     * @return void
     */
    public function testMarksACompleteSweep(): void
    {
        $result = new SealResult;

        $result->completedSweep();

        self::assertTrue($result->isSweepComplete());
        self::assertSame(0, $result->seals());
    }

    /**
     * Skipped entries are summed across the batches that skipped them.
     *
     * @return void
     */
    public function testCountsSkippedEntries(): void
    {
        $result = new SealResult;

        $result->skipped(2);
        $result->skipped(0);
        $result->skipped(3);

        self::assertSame(5, $result->skippedEntries());
        self::assertSame(0, $result->entries());
    }

    /**
     * A seal at the sequence holding the number of members.
     *
     * @param  int  $sequence
     * @param  int  $members
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope
     */
    private static function seal(int $sequence, int $members): SealEnvelope
    {
        return new SealEnvelope(
            logId: 'app-eu-1',
            id: '01932b4e-9000-7000-8000-000000000001',
            sequence: $sequence,
            previousId: null,
            previousDigest: null,
            memberCount: $members,
            membersDigest: str_repeat('a', 64),
            firstRecordedAt: '2026-10-31T23:34:56.890123Z',
            lastRecordedAt: '2026-10-31T23:35:00.000001Z',
            sealedAt: '2026-10-31T23:40:00.000000Z',
            keyId: 'k2026',
        );
    }
}
