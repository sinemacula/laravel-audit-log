<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\ErasureBlock;

/**
 * Unit tests for why an erasure keeps a key: the key, its unit and generation
 * as given, its reasons each once and sorted bytewise, at least one of them,
 * the prefixes every reason is built from, and the entry an erasure row lists
 * of a kept key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ErasureBlock::class)]
final class ErasureBlockTest extends TestCase
{
    /** @var string The key every block keeps. */
    private const string KEY_ID = '01932b4e-9000-7000-8000-0000000000c1';

    /** @var string The digest of the key's unit. */
    private const string UNIT = 'a3f1c2d4e5b6a7980a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071';

    /**
     * The key, its unit and its generation are kept as given.
     *
     * @return void
     */
    public function testKeepsTheKeyAsGiven(): void
    {
        $block = new ErasureBlock(self::KEY_ID, self::UNIT, 3, ['unverified']);

        self::assertSame([self::KEY_ID, self::UNIT, 3], [$block->keyId, $block->unit, $block->generation]);
    }

    /**
     * The reasons are kept each once and sorted bytewise, whatever order and
     * repeats they are given in.
     *
     * @return void
     */
    public function testTheReasonsAreDistinctAndSorted(): void
    {
        $block = new ErasureBlock(self::KEY_ID, self::UNIT, 1, ['unverified', 'preserved:billing', 'held:b', 'held:a', 'unverified', 'held:b']);

        self::assertSame(['held:a', 'held:b', 'preserved:billing', 'unverified'], $block->reasons);
    }

    /**
     * A block names at least one reason.
     *
     * @return void
     */
    public function testABlockWithoutAReasonIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An erasure block names at least one reason.');

        new ErasureBlock(self::KEY_ID, self::UNIT, 1, []);
    }

    /**
     * Every reason is built from the prefixes the class names.
     *
     * @return void
     */
    public function testTheReasonsArePinned(): void
    {
        self::assertSame(['unverified', 'held:', 'preserved:'], [ErasureBlock::UNVERIFIED, ErasureBlock::HELD, ErasureBlock::PRESERVED]);
    }

    /**
     * The entry an erasure row lists of the kept key: its id, unit, generation
     * and reasons, in that order.
     *
     * @return void
     */
    public function testTheKeptEntryIsTheBlock(): void
    {
        $block = new ErasureBlock(self::KEY_ID, self::UNIT, 2, ['preserved:billing', 'held:a']);

        self::assertSame([
            'key_id'     => self::KEY_ID,
            'unit'       => self::UNIT,
            'generation' => 2,
            'reasons'    => ['held:a', 'preserved:billing'],
        ], $block->toArray());
    }
}
