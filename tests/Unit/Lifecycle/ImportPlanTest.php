<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLine;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportPlan;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;

/**
 * Unit tests for a chunk's import plan: the new lines it keeps with their
 * digests, its duplicates, its conflicts listed in file order, and the plan
 * left once its new lines are conflicts instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportPlan::class)]
final class ImportPlanTest extends TestCase
{
    /** @var string A digest of a line's assertion. */
    private const string DIGEST = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /** @var string Another digest. */
    private const string OTHER_DIGEST = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    /**
     * The plan keeps its new lines in order, each line's digest by its number,
     * its duplicates and its conflicts.
     *
     * @return void
     */
    public function testKeepsItsLines(): void
    {
        $first  = self::line(1, 'rec-1');
        $second = self::line(3, 'rec-3');
        $plan   = new ImportPlan([$first, $second], [1 => self::DIGEST, 3 => self::OTHER_DIGEST], 2, [2 => 'rec-2']);

        self::assertSame([$first, $second], $plan->lines);
        self::assertSame(self::DIGEST, $plan->digestOf($first));
        self::assertSame(self::OTHER_DIGEST, $plan->digestOf($second));
        self::assertSame(2, $plan->duplicates);
        self::assertSame(1, $plan->conflicts());
        self::assertSame(['rec-2'], $plan->conflictIds());
    }

    /**
     * The conflicts are listed in file order, whatever order they were found
     * in.
     *
     * @return void
     */
    public function testConflictsAreListedInFileOrder(): void
    {
        $plan = new ImportPlan([], [], 0, [9 => 'rec-9', 2 => 'rec-2', 5 => 'rec-5']);

        self::assertSame(['rec-2', 'rec-5', 'rec-9'], $plan->conflictIds());
        self::assertSame(3, $plan->conflicts());
    }

    /**
     * Once its new lines are conflicts, the plan inserts nothing, keeps its
     * duplicates, and lists every conflict in file order, the former new lines
     * among them.
     *
     * @return void
     */
    public function testItsNewLinesBecomeConflicts(): void
    {
        $plan = new ImportPlan([self::line(1, 'rec-1'), self::line(4, 'rec-4')], [1 => self::DIGEST, 4 => self::DIGEST], 1, [2 => 'rec-2']);
        $left = $plan->withNewLinesAsConflicts();

        self::assertSame([], $left->lines);
        self::assertSame([], $left->digests);
        self::assertSame(1, $left->duplicates);
        self::assertSame(['rec-1', 'rec-2', 'rec-4'], $left->conflictIds());
        self::assertSame(3, $left->conflicts());
        self::assertCount(2, $plan->lines);
    }

    /**
     * A new line without its digest is refused.
     *
     * @return void
     */
    public function testRefusesANewLineWithoutItsDigest(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Every new line of an import plan has its digest.');

        new ImportPlan([self::line(1, 'rec-1')], [2 => self::DIGEST], 0, []);
    }

    /**
     * Fewer duplicates than none are refused.
     *
     * @return void
     */
    public function testRefusesNegativeDuplicates(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An import plan\'s duplicates cannot be fewer than none.');

        new ImportPlan([], [], -1, []);
    }

    /**
     * Only a new line has a digest in the plan.
     *
     * @return void
     */
    public function testALineThatIsNotNewHasNoDigest(): void
    {
        $plan = new ImportPlan([], [], 1, []);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Only a new line of an import plan has a digest in it.');

        $plan->digestOf(self::line(1, 'rec-1'));
    }

    /**
     * A line of the number and source record id given.
     *
     * @param  int  $number
     * @param  string  $recordId
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     */
    private static function line(int $number, string $recordId): ImportLine
    {
        return new ImportLine(
            $number,
            'crm-eu',
            null,
            $recordId,
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
