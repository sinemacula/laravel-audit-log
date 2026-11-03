<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\StaleClaimException;

/**
 * Unit tests for the exception that rolls back a delivery's shared transaction
 * once its claim is lost: its message is fixed and it chains nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StaleClaimException::class)]
final class StaleClaimExceptionTest extends TestCase
{
    /**
     * The message is fixed, and the code is zero.
     *
     * @return void
     */
    public function testTheMessageIsFixed(): void
    {
        $exception = new StaleClaimException;

        self::assertSame('The drain no longer owns the outbox row, so the delivery inside its transaction was rolled back.', $exception->getMessage());
        self::assertSame(0, $exception->getCode());
        self::assertInstanceOf(\RuntimeException::class, $exception);
    }

    /**
     * It has no previous exception.
     *
     * @return void
     */
    public function testHasNoPrevious(): void
    {
        self::assertNull((new StaleClaimException)->getPrevious());
    }
}
