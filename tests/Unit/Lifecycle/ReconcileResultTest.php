<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\ReconcileResult;

/**
 * Unit tests for the tally of one reconciliation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReconcileResult::class)]
final class ReconcileResultTest extends TestCase
{
    /**
     * A tally of nothing examined nothing and is complete.
     *
     * @return void
     */
    public function testStartsAtZero(): void
    {
        $result = new ReconcileResult;

        self::assertSame(['examined' => 0, 'recorded' => 0, 'already_recorded' => 0, 'unverifiable' => 0, 'unfinished' => 0, 'failed' => 0], $result->toArray());
        self::assertTrue($result->isComplete());
    }

    /**
     * Each outcome is kept apart, and the operations examined are their sum.
     *
     * @return void
     */
    public function testKeepsEachOutcomeApartAndExaminedIsTheirSum(): void
    {
        $result = new ReconcileResult(recorded: 1, alreadyRecorded: 2, unverifiable: 3, unfinished: 4, failed: 5);

        self::assertSame([1, 2, 3, 4, 5, 15], [$result->recorded, $result->alreadyRecorded, $result->unverifiable, $result->unfinished, $result->failed, $result->examined]);
        self::assertSame(['examined' => 15, 'recorded' => 1, 'already_recorded' => 2, 'unverifiable' => 3, 'unfinished' => 4, 'failed' => 5], $result->toArray());
    }

    /**
     * Rows of `[counts, complete]`: a failure or unverifiable is incomplete.
     *
     * @return iterable<string, array{0: array{0: int, 1: int, 2: int, 3: int, 4: int}, 1: bool}>
     */
    public static function provideCompleteness(): iterable
    {
        yield from [
            'recorded and already recorded' => [[3, 2, 0, 0, 0], true],
            'an unfinished run'             => [[0, 0, 0, 1, 0], true],
            'an unverifiable operation'     => [[0, 0, 1, 0, 0], false],
            'a record that failed'          => [[0, 0, 0, 0, 1], false],
        ];
    }

    /**
     * The tally is complete when nothing failed or was left unverifiable.
     *
     * @param  array{0: int, 1: int, 2: int, 3: int, 4: int}  $counts
     * @param  bool  $complete
     * @return void
     */
    #[DataProvider('provideCompleteness')]
    public function testIsCompleteUnlessSomethingIsStillMissing(array $counts, bool $complete): void
    {
        self::assertSame($complete, (new ReconcileResult(...$counts))->isComplete());
    }

    /**
     * Rows of `[the counts]`: one of them below 0.
     *
     * @return iterable<string, array{0: array{0: int, 1: int, 2: int, 3: int, 4: int}}>
     */
    public static function provideNegativeCounts(): iterable
    {
        yield from [
            'recorded'         => [[-1, 0, 0, 0, 0]],
            'already recorded' => [[0, -1, 0, 0, 0]],
            'unverifiable'     => [[0, 0, -1, 0, 0]],
            'unfinished'       => [[0, 0, 0, -1, 0]],
            'failed'           => [[0, 0, 0, 0, -1]],
        ];
    }

    /**
     * A count below 0 is refused, whichever it is.
     *
     * @param  array{0: int, 1: int, 2: int, 3: int, 4: int}  $counts
     * @return void
     */
    #[DataProvider('provideNegativeCounts')]
    public function testRefusesANegativeCount(array $counts): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A reconciliation\'s counts must each be at least 0.');

        new ReconcileResult(...$counts);
    }
}
