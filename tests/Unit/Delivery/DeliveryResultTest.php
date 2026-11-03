<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\DeliveryResult;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryOutcome;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics;

/**
 * Unit tests for the result of delivering one claimed row: each named outcome,
 * and that only an incomplete delivery holds a failure.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliveryResult::class)]
final class DeliveryResultTest extends TestCase
{
    /**
     * An incomplete delivery names its outcome and holds what it failed with.
     *
     * @return void
     */
    public function testAnIncompleteDeliveryHoldsItsFailure(): void
    {
        $failure = new WriteDiagnostics('id', 'code', FailedOperation::DRAIN, 'store', \DomainException::class, null, null, null, null);
        $result  = DeliveryResult::incomplete($failure);

        self::assertSame(DeliveryOutcome::INCOMPLETE, $result->outcome);
        self::assertSame($failure, $result->failure());
    }

    /**
     * Rows of `[result, outcome]`: each delivery that holds no failure.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Delivery\DeliveryResult, 1: \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryOutcome}>
     */
    public static function provideResultsWithoutAFailure(): iterable
    {
        yield from [
            'a complete delivery' => [DeliveryResult::complete(), DeliveryOutcome::COMPLETE],
            'a stale delivery'    => [DeliveryResult::stale(), DeliveryOutcome::STALE],
        ];
    }

    /**
     * Any other delivery names its outcome, and asking it for a failure is a
     * mistake rather than a `null` a caller could misread.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DeliveryResult  $result
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryOutcome  $outcome
     * @return void
     */
    #[DataProvider('provideResultsWithoutAFailure')]
    public function testAnyOtherDeliveryHoldsNoFailure(DeliveryResult $result, DeliveryOutcome $outcome): void
    {
        self::assertSame($outcome, $result->outcome);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Only an incomplete delivery has a failure.');

        $result->failure();
    }
}
