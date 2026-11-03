<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity\Anchors;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorDriver;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;

/**
 * Unit tests for the null anchor: its name, that it refuses to anchor, that it
 * confirms nothing, and that it can discover nothing and has no head.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NullAnchor::class)]
final class NullAnchorTest extends TestCase
{
    /**
     * The anchor's name is `null`, the value of the driver that configures it,
     * and it is a checkpoint anchor.
     *
     * @return void
     */
    public function testItsNameIsNull(): void
    {
        $anchor = new NullAnchor;

        self::assertInstanceOf(CheckpointAnchor::class, $anchor);
        self::assertSame('null', $anchor->name());
        self::assertSame(AnchorDriver::NONE->value, $anchor->name());
    }

    /**
     * Asking it to anchor is a programming error, since the package never does.
     *
     * @return void
     */
    public function testItAnchorsNothing(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The null anchor anchors nothing; bind a CheckpointAnchor to anchor seals.');

        (new NullAnchor)->anchor(self::summary());
    }

    /**
     * No receipt is ever confirmed, whatever it holds.
     *
     * @return void
     */
    public function testItConfirmsNothing(): void
    {
        $anchor = new NullAnchor;

        self::assertFalse($anchor->confirms(self::summary(), []));
        self::assertFalse($anchor->confirms(self::summary(), ['sequence' => 1, 'digest' => str_repeat('a', 64)]));
    }

    /**
     * It cannot report a head.
     *
     * @return void
     */
    public function testItCannotDiscover(): void
    {
        self::assertFalse((new NullAnchor)->supportsDiscovery());
    }

    /**
     * Its head is none.
     *
     * @return void
     */
    public function testItsHeadIsNone(): void
    {
        self::assertNull((new NullAnchor)->latest());
    }

    /**
     * A summary of a seal.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealSummary
     */
    private static function summary(): SealSummary
    {
        return new SealSummary('app-eu-1', 1, '01932b4e-9000-7000-8000-000000000001', str_repeat('a', 64));
    }
}
