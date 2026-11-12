<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneMismatchException;

/**
 * Unit tests for the exception a prune chunk's mismatched delete throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneMismatchException::class)]
final class PruneMismatchExceptionTest extends TestCase
{
    /**
     * The message names the rows affected and the ids named, in that order.
     *
     * @return void
     */
    public function testTheMessageNamesTheTwoCounts(): void
    {
        $exception = PruneMismatchException::of(500, 499);

        self::assertSame('A prune chunk deleted 499 entries where it named 500; the chunk was rolled back.', $exception->getMessage());
        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertNull($exception->getPrevious());
        self::assertSame(0, $exception->getCode());
    }
}
