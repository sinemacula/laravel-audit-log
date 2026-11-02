<?php

declare(strict_types = 1);

namespace Tests\Unit\Runtime\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Runtime\Enums\FrameKind;

/**
 * Unit tests for the kinds of execution frame: their values and the origin each
 * gives a record.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FrameKind::class)]
final class FrameKindTest extends TestCase
{
    /**
     * The kinds and their values are exactly these, in this order.
     *
     * @return void
     */
    public function testTheValues(): void
    {
        self::assertSame(['http', 'command', 'job'], array_map(static fn (FrameKind $kind): string => $kind->value, FrameKind::cases()));
    }

    /**
     * A request's origin is HTTP, a command's console and a job's queue.
     *
     * @return void
     */
    public function testEachKindHasItsOrigin(): void
    {
        self::assertSame(Origin::HTTP, FrameKind::HTTP->origin());
        self::assertSame(Origin::CONSOLE, FrameKind::COMMAND->origin());
        self::assertSame(Origin::QUEUE, FrameKind::JOB->origin());
    }
}
