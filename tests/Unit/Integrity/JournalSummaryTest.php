<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\JournalSummary;

/**
 * Unit tests for what a verification run read of the lifecycle journal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JournalSummary::class)]
final class JournalSummaryTest extends TestCase
{
    /**
     * The summary keeps the rows, the head's sequence and the sequence the
     * latest seal commits to, as given, `null` for none.
     *
     * @return void
     */
    public function testKeepsItsFields(): void
    {
        $summary = new JournalSummary(12, 11, 9);
        $empty   = new JournalSummary(0, null, null);

        self::assertSame(12, $summary->rowsRead);
        self::assertSame(11, $summary->head);
        self::assertSame(9, $summary->committed);
        self::assertSame(0, $empty->rowsRead);
        self::assertNull($empty->head);
        self::assertNull($empty->committed);
    }

    /**
     * The summary's part of the run's summary names the rows, the head and the
     * commitment, in that order of keys.
     *
     * @return void
     */
    public function testToArray(): void
    {
        self::assertSame(['rows' => 3, 'head' => 3, 'committed' => 2], (new JournalSummary(3, 3, 2))->toArray());
        self::assertSame(['rows' => 0, 'head' => null, 'committed' => null], (new JournalSummary(0, null, null))->toArray());
    }
}
