<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLine;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportPlan;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportTally;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;

/**
 * Unit tests for an import's tally.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportTally::class)]
final class ImportTallyTest extends TestCase
{
    /** @var string A digest of a line's assertion. */
    private const string DIGEST = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /**
     * A fresh tally counts nothing, is complete, and lists no conflict.
     *
     * @return void
     */
    public function testAFreshTallyCountsNothing(): void
    {
        $tally = new ImportTally;

        $counts = [$tally->linesRead(), $tally->imported(), $tally->duplicates(), $tally->conflicts(), $tally->rejected(), $tally->dropped(), $tally->pastRetention()];

        self::assertSame([0, 0, 0, 0, 0, 0, 0], $counts);
        self::assertSame([], $tally->rejections());
        self::assertSame([], $tally->conflictIds());
        self::assertTrue($tally->isComplete());
        self::assertSame(['lines_read' => 0, 'imported' => 0, 'duplicates' => 0, 'conflicts' => 0, 'rejected' => 0, 'conflict_ids' => null], $tally->toBatch());
    }

    /**
     * Each count grows, rejections by reason in the order first met.
     *
     * @return void
     */
    public function testEachCountGrows(): void
    {
        $tally = new ImportTally;

        $tally->countRead();
        $tally->countRead();
        $tally->countRead();
        $tally->countRejected(ImportRejection::RESERVED_CODE);
        $tally->countRejected(ImportRejection::MALFORMED_JSON);
        $tally->countRejected(ImportRejection::RESERVED_CODE);
        $tally->countDropped(2);
        $tally->countDropped(0);
        $tally->countDropped(1);
        $tally->countPastRetention();

        self::assertSame(3, $tally->linesRead());
        self::assertSame(3, $tally->rejected());
        self::assertSame(['reserved_code' => 2, 'malformed_json' => 1], $tally->rejections());
        self::assertSame(3, $tally->dropped());
        self::assertSame(1, $tally->pastRetention());
        self::assertFalse($tally->isComplete());
    }

    /**
     * A plan counts new lines, duplicates and conflicts, which are incomplete.
     *
     * @return void
     */
    public function testAPlanCountsItsLines(): void
    {
        $tally = new ImportTally;

        $tally->countPlan(new ImportPlan([self::line(1), self::line(2)], [1 => self::DIGEST, 2 => self::DIGEST], 3, []));

        self::assertSame([2, 3, 0], [$tally->imported(), $tally->duplicates(), $tally->conflicts()]);
        self::assertTrue($tally->isComplete());

        $tally->countPlan(new ImportPlan([], [], 0, [7 => 'rec-7', 5 => 'rec-5']));

        self::assertSame([2, 3, 2], [$tally->imported(), $tally->duplicates(), $tally->conflicts()]);
        self::assertSame(['rec-5', 'rec-7'], $tally->conflictIds());
        self::assertFalse($tally->isComplete());
    }

    /**
     * The conflict list names the first hundred ids; every one is counted.
     *
     * @return void
     */
    public function testTheConflictListIsBoundedAtAHundred(): void
    {
        $tally = new ImportTally;

        $tally->countPlan(new ImportPlan([], [], 0, self::conflicts(1, 60)));
        $tally->countPlan(new ImportPlan([], [], 0, self::conflicts(61, 60)));
        $tally->countPlan(new ImportPlan([], [], 0, self::conflicts(121, 5)));

        self::assertSame(125, $tally->conflicts());
        self::assertCount(ImportTally::MAX_CONFLICT_IDS, $tally->conflictIds());
        self::assertSame('rec-1', $tally->conflictIds()[0]);
        self::assertSame('rec-100', $tally->conflictIds()[99]);
        self::assertSame(100, ImportTally::MAX_CONFLICT_IDS);
    }

    /**
     * The conflict list stops early before it outgrows MySQL's `text` type.
     *
     * @return void
     */
    public function testTheConflictListIsBoundedByItsBytes(): void
    {
        $tally = new ImportTally;
        $ids   = [];

        for ($number = 1; $number <= 100; $number++) {
            $ids[$number] = sprintf('%03d', $number) . str_repeat("\u{1F600}", 188);
        }

        $tally->countPlan(new ImportPlan([], [], 0, $ids));
        $tally->countPlan(new ImportPlan([], [], 0, [101 => 'rec-101']));

        $listed = $tally->conflictIds();
        $stored = $tally->toBatch()['conflict_ids'];

        self::assertSame(101, $tally->conflicts());
        self::assertSame(array_slice(array_values($ids), 0, count($listed)), $listed);
        self::assertLessThan(100, count($listed));
        self::assertIsString($stored);
        self::assertLessThanOrEqual(ImportTally::MAX_CONFLICT_ID_BYTES, strlen($stored));
        self::assertGreaterThan(ImportTally::MAX_CONFLICT_ID_BYTES - 800, strlen($stored));
        self::assertNotContains('rec-101', $listed);
        self::assertSame(60000, ImportTally::MAX_CONFLICT_ID_BYTES);
    }

    /**
     * The past-retention count, once given up, reads `null` and counts no more.
     *
     * @return void
     */
    public function testThePastRetentionCountCanBeGivenUp(): void
    {
        $tally = new ImportTally;

        $tally->countPastRetention();

        self::assertTrue($tally->countsPastRetention());
        self::assertSame(1, $tally->pastRetention());

        $tally->givePastRetentionUp();
        $tally->countPastRetention();

        self::assertFalse($tally->countsPastRetention());
        self::assertNull($tally->pastRetention());
    }

    /**
     * A copy with a plan counted leaves the tally it was made from as it was.
     *
     * @return void
     */
    public function testWithLeavesTheTallyAsItIs(): void
    {
        $tally = new ImportTally;

        $tally->countRead();

        $next = $tally->with(new ImportPlan([self::line(1)], [1 => self::DIGEST], 1, [3 => 'rec-3']));

        self::assertSame([0, 0, 0], [$tally->imported(), $tally->duplicates(), $tally->conflicts()]);
        self::assertSame([1, 1, 1, 1], [$next->linesRead(), $next->imported(), $next->duplicates(), $next->conflicts()]);
        self::assertSame(['rec-3'], $next->conflictIds());
        self::assertSame([], $tally->conflictIds());
    }

    /**
     * The batch row holds the counts and the conflicting ids as canonical JSON.
     *
     * @return void
     */
    public function testTheBatchHoldsTheCountsAndACanonicalList(): void
    {
        $tally = new ImportTally;

        $tally->countRead();
        $tally->countRead();
        $tally->countRejected(ImportRejection::OVERSIZED_LINE);
        $tally->countPlan(new ImportPlan([], [], 0, [2 => 'rec/2 "x"']));

        self::assertSame([
            'lines_read'   => 2,
            'imported'     => 0,
            'duplicates'   => 0,
            'conflicts'    => 1,
            'rejected'     => 1,
            'conflict_ids' => '["rec/2 \"x\""]',
        ], $tally->toBatch());
    }

    /**
     * Fewer dropped values than none are refused.
     *
     * @return void
     */
    public function testRefusesFewerDroppedThanNone(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The values removed from a line cannot be fewer than none.');

        (new ImportTally)->countDropped(-1);
    }

    /**
     * Conflicts of the count given from the line given, each id `rec-<number>`.
     *
     * @param  int  $from
     * @param  int  $count
     * @return array<int, string>
     */
    private static function conflicts(int $from, int $count): array
    {
        $conflicts = [];

        for ($number = $from; $number < $from + $count; $number++) {
            $conflicts[$number] = 'rec-' . $number;
        }

        return $conflicts;
    }

    /**
     * A line of the number given.
     *
     * @param  int  $number
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     */
    private static function line(int $number): ImportLine
    {
        return new ImportLine(
            $number,
            'crm-eu',
            null,
            'rec-' . $number,
            'invoice.approved',
            '2026-10-01T09:00:00.000000Z',
            Outcome::SUCCESS,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
        );
    }
}
