<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode;

/**
 * Unit tests for the failure rule: the rule each timing, fail-closed request
 * and failure mode gives, and the values its cases are named by.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailureRule::class)]
final class FailureRuleTest extends TestCase
{
    /**
     * Rows of `[timing, mode, the rule]`: a record that neither is
     * transactional nor asks to fail closed, under each mode.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Records\Enums\Timing, 1: \SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode, 2: \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideExplicitRecords(): iterable
    {
        yield from [
            'after commit, report mode' => [Timing::AFTER_COMMIT, FailureMode::REPORT, FailureRule::REPORT],
            'after commit, throw mode'  => [Timing::AFTER_COMMIT, FailureMode::THROW, FailureRule::SPILL_AND_THROW],
            'immediate, report mode'    => [Timing::IMMEDIATE, FailureMode::REPORT, FailureRule::REPORT],
            'immediate, throw mode'     => [Timing::IMMEDIATE, FailureMode::THROW, FailureRule::SPILL_AND_THROW],
        ];
    }

    /**
     * A non-transactional record not asking to fail closed is spilled, then
     * reported or thrown by the mode.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  \SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode  $mode
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @return void
     */
    #[DataProvider('provideExplicitRecords')]
    public function testAnExplicitRecordFollowsTheMode(Timing $timing, FailureMode $mode, FailureRule $rule): void
    {
        self::assertSame($rule, FailureRule::for($timing, false, $mode));
    }

    /**
     * A record that asks to fail closed is spilled and thrown under either
     * mode, whether it is written now or after the commit.
     *
     * @return void
     */
    public function testFailClosedSpillsAndThrowsInEitherMode(): void
    {
        foreach ([Timing::AFTER_COMMIT, Timing::IMMEDIATE] as $timing) {
            foreach (FailureMode::cases() as $mode) {
                self::assertSame(FailureRule::SPILL_AND_THROW, FailureRule::for($timing, true, $mode), "{$timing->value} under {$mode->value}");
            }
        }
    }

    /**
     * Rows of `[whether it asks to fail closed, mode]`: every way a
     * transactional record can be asked for.
     *
     * @return iterable<string, array{0: bool, 1: \SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode}>
     */
    public static function provideTransactionalRecords(): iterable
    {
        yield from [
            'report mode'              => [false, FailureMode::REPORT],
            'throw mode'               => [false, FailureMode::THROW],
            'fail closed, report mode' => [true, FailureMode::REPORT],
            'fail closed, throw mode'  => [true, FailureMode::THROW],
        ];
    }

    /**
     * A transactional record is thrown and never spilled, so uncommitted work
     * never becomes a replayable line.
     *
     * @param  bool  $failClosed
     * @param  \SineMacula\Laravel\AuditLog\Stores\Enums\FailureMode  $mode
     * @return void
     */
    #[DataProvider('provideTransactionalRecords')]
    public function testATransactionalRecordNeverSpills(bool $failClosed, FailureMode $mode): void
    {
        self::assertSame(FailureRule::THROW, FailureRule::for(Timing::TRANSACTIONAL, $failClosed, $mode));
    }

    /**
     * The cases, in order, with the values they are named by, so a renamed,
     * reordered or added case fails.
     *
     * @return void
     */
    public function testTheStoredValuesArePinned(): void
    {
        self::assertSame([
            'REPORT'          => 'report',
            'SPILL_AND_THROW' => 'spill_and_throw',
            'THROW'           => 'throw',
        ], array_column(FailureRule::cases(), 'value', 'name'));
    }
}
