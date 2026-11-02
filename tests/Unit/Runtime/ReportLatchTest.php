<?php

declare(strict_types = 1);

namespace Tests\Unit\Runtime;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;

/**
 * Unit tests for the latch that stops a report causing another report of
 * itself: what runs, what is skipped, and that it lets go afterwards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReportLatch::class)]
final class ReportLatchTest extends TestCase
{
    /**
     * A report with none running runs.
     *
     * @return void
     */
    public function testRunsTheReport(): void
    {
        $runs = 0;

        (new ReportLatch)->once(static function () use (&$runs): void {
            $runs++;
        });

        self::assertSame(1, $runs);
    }

    /**
     * A report made from inside a report is skipped.
     *
     * @return void
     */
    public function testSkipsAReportFromInsideAReport(): void
    {
        $latch = new ReportLatch;
        $runs  = 0;

        $latch->once(static function () use ($latch, &$runs): void {
            $runs++;

            $latch->once(static function () use (&$runs): void {
                $runs++;
            });
        });

        self::assertSame(1, $runs);
    }

    /**
     * A report made after another has finished runs.
     *
     * @return void
     */
    public function testLetsGoOnceTheReportEnds(): void
    {
        $latch = new ReportLatch;
        $runs  = 0;
        $count = static function () use (&$runs): void {
            $runs++;
        };

        $latch->once($count);
        $latch->once($count);

        self::assertSame(2, $runs);
    }

    /**
     * A report that throws lets go of the latch too, so the next failure is
     * still reported.
     *
     * @return void
     */
    public function testLetsGoWhenTheReportThrows(): void
    {
        $latch = new ReportLatch;

        try {
            $latch->once(static function (): void {
                throw new \RuntimeException('The reporter is down.');
            });

            self::fail('Expected the report\'s exception to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The reporter is down.', $exception->getMessage());
        }

        $runs = 0;

        $latch->once(static function () use (&$runs): void {
            $runs++;
        });

        self::assertSame(1, $runs);
    }
}
