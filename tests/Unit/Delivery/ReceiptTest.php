<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\Receipt;

/**
 * Unit tests for a destination's receipt: the fields it keeps.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Receipt::class)]
final class ReceiptTest extends TestCase
{
    /**
     * A receipt keeps the destination, the attempts, whether it is delivered
     * and the last error's class as given, `null` included.
     *
     * @return void
     */
    public function testKeepsItsFields(): void
    {
        $failed    = new Receipt('siem.primary', 2, false, \RuntimeException::class);
        $delivered = new Receipt('store', 1, true, null);

        self::assertSame('siem.primary', $failed->destination);
        self::assertSame(2, $failed->attempts);
        self::assertFalse($failed->delivered);
        self::assertSame(\RuntimeException::class, $failed->lastErrorClass);
        self::assertSame('store', $delivered->destination);
        self::assertSame(1, $delivered->attempts);
        self::assertTrue($delivered->delivered);
        self::assertNull($delivered->lastErrorClass);
    }
}
