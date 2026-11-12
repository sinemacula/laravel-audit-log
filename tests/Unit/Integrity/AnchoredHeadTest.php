<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;

/**
 * Unit tests for the anchored head.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AnchoredHead::class)]
final class AnchoredHeadTest extends TestCase
{
    /** @var string The golden first seal's digest. */
    private const string DIGEST = '329162defc18f3f10f3a8a351a7faa0c0e5e1004d65ea3b432feb0b54d3282c6';

    /**
     * The head keeps the sequence and the digest as given, from the first
     * sequence to the greatest.
     *
     * @return void
     */
    public function testKeepsTheSequenceAndDigest(): void
    {
        $head = new AnchoredHead(1, self::DIGEST);

        self::assertSame(1, $head->sequence);
        self::assertSame(self::DIGEST, $head->digest);
        self::assertSame(PHP_INT_MAX, (new AnchoredHead(PHP_INT_MAX, self::DIGEST))->sequence);
    }

    /**
     * Rows of `[sequence]`: sequences below the first.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideSequencesBelowOne(): iterable
    {
        yield from [
            'zero'      => [0],
            'minus one' => [-1],
            'the least' => [PHP_INT_MIN],
        ];
    }

    /**
     * A sequence below 1 is refused: no seal precedes genesis.
     *
     * @param  int  $sequence
     * @return void
     */
    #[DataProvider('provideSequencesBelowOne')]
    public function testRefusesASequenceBelowOne(int $sequence): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An anchored head\'s sequence must be at least 1.');

        new AnchoredHead($sequence, self::DIGEST);
    }

    /**
     * Rows of `[digest]`: digests that are not 64 lower-case hex.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedDigests(): iterable
    {
        yield from [
            'empty'           => [''],
            'short'           => [substr(self::DIGEST, 1)],
            'long'            => [self::DIGEST . 'a'],
            'upper case'      => [strtoupper(self::DIGEST)],
            'not hex'         => [str_repeat('g', 64)],
            'with a new line' => [self::DIGEST . "\n"],
        ];
    }

    /**
     * A digest that is not 64 lower-case hex is refused.
     *
     * @param  string  $digest
     * @return void
     */
    #[DataProvider('provideMalformedDigests')]
    public function testRefusesAMalformedDigest(string $digest): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An anchored head\'s digest must be 64 lower-case hexadecimal characters.');

        new AnchoredHead(1, $digest);
    }
}
