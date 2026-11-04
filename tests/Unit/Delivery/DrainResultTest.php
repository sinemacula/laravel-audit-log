<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\DrainResult;

/**
 * Unit tests for a drain's tally: it starts at zero, counts each outcome apart,
 * a row completed as pruned among them, and has failures only once a row
 * failed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DrainResult::class)]
final class DrainResultTest extends TestCase
{
    /**
     * A new tally holds nothing and has no failures.
     *
     * @return void
     */
    public function testStartsAtZero(): void
    {
        $result = new DrainResult;

        self::assertSame([0, 0, 0, 0, 0, 0], self::counts($result));
        self::assertFalse($result->hasFailures());
    }

    /**
     * Each outcome is counted on its own tally, as often as it is added, and on
     * no other.
     *
     * @return void
     */
    public function testCountsEachOutcome(): void
    {
        $result = new DrainResult;

        $result->addDelivered();
        $result->addPruned();
        $result->addPruned();
        $result->addPruned();
        $result->addPruned();
        $result->addPruned();
        $result->addPruned();
        $result->addRetried();
        $result->addRetried();
        $result->addFailed();
        $result->addFailed();
        $result->addFailed();
        $result->addStale();
        $result->addStale();
        $result->addStale();
        $result->addStale();
        $result->addMissed();
        $result->addMissed();
        $result->addMissed();
        $result->addMissed();
        $result->addMissed();

        self::assertSame([1, 6, 2, 3, 4, 5], self::counts($result));
    }

    /**
     * Rows of `[how the outcome is added, whether the tally then has
     * failures]`: only a failed row makes a drain unsuccessful, and a pruned
     * row is complete.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Delivery\DrainResult): void, 1: bool}>
     */
    public static function provideOutcomes(): iterable
    {
        yield from [
            'delivered' => [static function (DrainResult $result): void {
                $result->addDelivered();
            }, false],
            'pruned' => [static function (DrainResult $result): void {
                $result->addPruned();
            }, false],
            'retried' => [static function (DrainResult $result): void {
                $result->addRetried();
            }, false],
            'failed' => [static function (DrainResult $result): void {
                $result->addFailed();
            }, true],
            'stale' => [static function (DrainResult $result): void {
                $result->addStale();
            }, false],
            'missed' => [static function (DrainResult $result): void {
                $result->addMissed();
            }, false],
        ];
    }

    /**
     * A tally has failures only once a row failed.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Delivery\DrainResult): void  $add
     * @param  bool  $failures
     * @return void
     */
    #[DataProvider('provideOutcomes')]
    public function testHasFailuresOnlyWithAFailure(\Closure $add, bool $failures): void
    {
        $result = new DrainResult;

        $add($result);

        self::assertSame($failures, $result->hasFailures());
    }

    /**
     * The tally's counts, in the order the command prints them: delivered,
     * pruned, retried, failed, stale and missed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return list<int>
     */
    private static function counts(DrainResult $result): array
    {
        return [$result->delivered(), $result->pruned(), $result->retried(), $result->failed(), $result->stale(), $result->missed()];
    }
}
