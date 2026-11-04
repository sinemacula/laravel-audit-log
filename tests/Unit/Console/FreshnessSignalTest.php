<?php

declare(strict_types = 1);

namespace Tests\Unit\Console;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Console\FreshnessSignal;

/**
 * Unit tests for a freshness signal: its line names the signal and its status,
 * with its age and its limit only when it has them, and its fields are the
 * closed list `--json` writes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessSignal::class)]
final class FreshnessSignalTest extends TestCase
{
    /**
     * The statuses are the words the guide documents.
     *
     * @return void
     */
    public function testTheStatusesAreTheDocumentedWords(): void
    {
        self::assertSame(
            ['ok', 'stale', 'failed', 'never_run', 'not_applicable'],
            [FreshnessSignal::OK, FreshnessSignal::STALE, FreshnessSignal::FAILED, FreshnessSignal::NEVER_RUN, FreshnessSignal::NOT_APPLICABLE],
        );
    }

    /**
     * The line names the signal and its status, then its age and its limit in
     * seconds, leaving out whichever it has none of.
     *
     * @return void
     */
    public function testTheLineHoldsWhatTheSignalHas(): void
    {
        self::assertSame('[freshness] sealing: stale (age 1801s, limit 1800s)', (new FreshnessSignal('sealing', FreshnessSignal::STALE, 1801, 1800, true))->line());
        self::assertSame('[freshness] sweep: never_run (limit 93600s)', (new FreshnessSignal('sweep', FreshnessSignal::NEVER_RUN, null, 93600, false))->line());
        self::assertSame('[freshness] anchoring: ok (age 0s)', (new FreshnessSignal('anchoring', FreshnessSignal::OK, 0, null, false))->line());
        self::assertSame('[freshness] outbox: not_applicable', (new FreshnessSignal('outbox', FreshnessSignal::NOT_APPLICABLE, null, null, false))->line());
        $failed = new FreshnessSignal('anchoring', FreshnessSignal::FAILED, null, null, true, 'the anchor failed');

        self::assertSame('[freshness] anchoring: failed (the anchor failed)', $failed->line());
    }

    /**
     * The fields are exactly the signal, its status, its age and its limit,
     * `null` where it has none, and say nothing of whether it is a problem.
     *
     * @return void
     */
    public function testTheFieldsAreTheClosedList(): void
    {
        self::assertSame(
            ['signal' => 'retention', 'status' => 'failed', 'age_seconds' => 60, 'limit_seconds' => 93600],
            (new FreshnessSignal('retention', FreshnessSignal::FAILED, 60, 93600, true, 'a cause'))->toArray(),
        );

        self::assertSame(
            ['signal' => 'outbox', 'status' => 'not_applicable', 'age_seconds' => null, 'limit_seconds' => null],
            (new FreshnessSignal('outbox', FreshnessSignal::NOT_APPLICABLE, null, null, false))->toArray(),
        );
    }
}
