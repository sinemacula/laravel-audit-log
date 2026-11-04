<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureRun;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay;
use Tests\TestCase;

/**
 * Feature tests for what a run of erasures carries from one owner to the next:
 * nothing at first, then the replay the last committed erasure left, and
 * whether the installation was confirmed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ErasureRun::class)]
final class ErasureRunTest extends TestCase
{
    /**
     * A new run holds no replay and has confirmed nothing.
     *
     * @return void
     */
    public function testANewRunCarriesNothing(): void
    {
        $run = new ErasureRun;

        self::assertNull($run->replay());
        self::assertFalse($run->isConfirmed());
    }

    /**
     * The run keeps the replay committed last, replacing the one before, and
     * remembers that it confirmed the installation.
     *
     * @return void
     */
    public function testTheRunKeepsTheLastCommittedReplay(): void
    {
        $run    = new ErasureRun;
        $first  = JournalReplay::start(app(JournalSigner::class), 'log-a');
        $second = JournalReplay::start(app(JournalSigner::class), 'log-a');

        $run->committed($first);

        self::assertSame($first, $run->replay());

        $run->committed($second);
        $run->confirmed();

        self::assertSame($second, $run->replay());
        self::assertTrue($run->isConfirmed());
    }
}
