<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\KeyUseRebuildResult;

/**
 * Unit tests for what a rebuild of the key uses returns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyUseRebuildResult::class)]
final class KeyUseRebuildResultTest extends TestCase
{
    /**
     * A result keeps what it is given.
     *
     * @return void
     */
    public function testKeepsWhatItIsGiven(): void
    {
        $result = new KeyUseRebuildResult(5, 4, 1, 3, true);

        self::assertSame([5, 4, 1, 3], [$result->entries, $result->verified, $result->skipped, $result->added]);
        self::assertTrue($result->dryRun);
    }

    /**
     * The array form names each count under its snake-case key, in order.
     *
     * @return void
     */
    public function testTheArrayForm(): void
    {
        self::assertSame(
            ['entries' => 5, 'verified' => 4, 'skipped' => 1, 'added' => 3, 'dry_run' => false],
            (new KeyUseRebuildResult(5, 4, 1, 3, false))->toArray(),
        );
    }
}
