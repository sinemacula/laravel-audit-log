<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;

/**
 * Unit tests for the range of seals one verification covers: only the whole log
 * is complete, each end defaults to the end of the chain, and a range is
 * validated against the head the run observed, with the messages the verify
 * command prints.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationRange::class)]
final class VerificationRangeTest extends TestCase
{
    /**
     * The whole log gives neither end and is complete.
     *
     * @return void
     */
    public function testTheWholeLogIsComplete(): void
    {
        $range = VerificationRange::whole();

        self::assertNull($range->from);
        self::assertNull($range->to);
        self::assertTrue($range->isComplete());
        self::assertTrue((new VerificationRange)->isComplete());
    }

    /**
     * Rows of `[from, to]`: ranges that give at least one end.
     *
     * @return iterable<string, array{0: ?int, 1: ?int}>
     */
    public static function provideRanges(): iterable
    {
        yield from [
            'a first seal alone' => [2, null],
            'a last seal alone'  => [null, 2],
            'both ends'          => [1, 3],
        ];
    }

    /**
     * A range that gives either end is not complete, even one that happens to
     * cover every seal, so a ranged run never claims the whole log.
     *
     * @param  ?int  $from
     * @param  ?int  $to
     * @return void
     */
    #[DataProvider('provideRanges')]
    public function testARangeIsNotComplete(?int $from, ?int $to): void
    {
        self::assertFalse((new VerificationRange($from, $to))->isComplete());
    }

    /**
     * The whole log runs from the first seal to the head, and an end that is
     * not given defaults to its end of the chain on its own.
     *
     * @return void
     */
    public function testTheBoundsDefaultToTheWholeChain(): void
    {
        self::assertSame([1, 7], VerificationRange::whole()->bounds(7));
        self::assertSame([3, 7], (new VerificationRange(3))->bounds(7));
        self::assertSame([1, 5], (new VerificationRange(null, 5))->bounds(7));
        self::assertSame([2, 5], (new VerificationRange(2, 5))->bounds(7));
    }

    /**
     * A range may end at the head and may hold one seal: neither is refused,
     * which protects against off-by-one mutations of either comparison.
     *
     * @return void
     */
    public function testARangeMayEndAtTheHeadAndHoldOneSeal(): void
    {
        self::assertSame([7, 7], (new VerificationRange(7, 7))->bounds(7));
        self::assertSame([7, 7], (new VerificationRange(7))->bounds(7));
        self::assertSame([1, 1], (new VerificationRange(1, 1))->bounds(1));
    }

    /**
     * A first seal after the last is refused, whatever the head.
     *
     * @return void
     */
    public function testRefusesFromAfterTo(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('--from must not be after --to.');

        (new VerificationRange(4, 3))->bounds(7);
    }

    /**
     * A last seal beyond the head is refused, naming the head, so a seal
     * written after the run began is never asked for.
     *
     * @return void
     */
    public function testRefusesToBeyondTheHead(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('--to is beyond the head of the log, seal 7.');

        (new VerificationRange(1, 8))->bounds(7);
    }

    /**
     * A first seal beyond the head, with no last seal given, is refused naming
     * the head, rather than as a first seal after a last one the caller never
     * gave.
     *
     * @return void
     */
    public function testRefusesFromBeyondTheHead(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('--from is beyond the head of the log, seal 7.');

        (new VerificationRange(8))->bounds(7);
    }

    /**
     * Rows of `[from, to, message]`: ends of a range that are not sequences.
     *
     * @return iterable<string, array{0: ?int, 1: ?int, 2: string}>
     */
    public static function provideEndsThatAreNotSequences(): iterable
    {
        yield from [
            'a first seal of 0'     => [0, null, 'The --from option must be an integer from 1 to 9223372036854775807.'],
            'a negative first seal' => [-1, 3, 'The --from option must be an integer from 1 to 9223372036854775807.'],
            'a last seal of 0'      => [null, 0, 'The --to option must be an integer from 1 to 9223372036854775807.'],
            'a negative last seal'  => [1, -2, 'The --to option must be an integer from 1 to 9223372036854775807.'],
            'both ends of 0'        => [0, 0, 'The --from option must be an integer from 1 to 9223372036854775807.'],
        ];
    }

    /**
     * An end that is not a sequence is refused before anything else, naming the
     * option, even on a log with no seal.
     *
     * @param  ?int  $from
     * @param  ?int  $to
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideEndsThatAreNotSequences')]
    public function testRefusesAnEndThatIsNotASequence(?int $from, ?int $to, string $message): void
    {
        foreach ([7, null] as $head) {
            try {
                (new VerificationRange($from, $to))->bounds($head);

                self::fail('Expected the end to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage());
            }
        }
    }

    /**
     * Any range of a log with no seal is refused, since there is no seal it
     * could name.
     *
     * @param  ?int  $from
     * @param  ?int  $to
     * @return void
     */
    #[DataProvider('provideRanges')]
    public function testRefusesARangeOfAnEmptyLog(?int $from, ?int $to): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The log has no seal to verify in a range.');

        (new VerificationRange($from, $to))->bounds(null);
    }

    /**
     * The whole of a log with no seal is the empty range from 1 to 0: valid,
     * with no segment to check.
     *
     * @return void
     */
    public function testAnEmptyLogHasNoSegments(): void
    {
        [$from, $to] = VerificationRange::whole()->bounds(null);

        self::assertSame([1, 0], [$from, $to]);
        self::assertGreaterThan($to, $from);
    }
}
