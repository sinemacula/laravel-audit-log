<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\PruneStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneResult;

/**
 * Unit tests for what a prune run did: its counts per category bounded at the
 * fifty largest with the rest under `_other`, its skipped seals bounded at a
 * hundred, whether its record was written, and the map it renders.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneResult::class)]
final class PruneResultTest extends TestCase
{
    /** @var string The run every result is of. */
    private const string RUN = '01932b4e-c000-7000-8000-000000000001';

    /**
     * Sixty categories, each deleting a different count, keep the fifty largest
     * by name, the largest first, and the ten smallest summed under `_other`.
     *
     * @return void
     */
    public function testTheCategoriesAreBoundedAtFifty(): void
    {
        $categories = [];

        for ($index = 1; $index <= 60; $index++) {
            $categories[sprintf('category_%02d', $index)] = $index;
        }

        $result   = self::completeResult($categories);
        $expected = [];

        for ($index = 60; $index > 10; $index--) {
            $expected[sprintf('category_%02d', $index)] = $index;
        }

        $expected['_other'] = array_sum(range(1, 10));

        self::assertSame($expected, $result->categories);
        self::assertCount(51, $result->categories);
    }

    /**
     * Categories deleting the same count are ordered bytewise, so which of them
     * is kept by name never depends on the order they were counted in.
     *
     * @return void
     */
    public function testATieIsOrderedBytewise(): void
    {
        $categories = ['zeta' => 1];

        for ($index = 1; $index <= 50; $index++) {
            $categories[sprintf('alpha_%02d', $index)] = 1;
        }

        $bounded = PruneResult::bounded($categories);

        self::assertSame('alpha_01', array_key_first($bounded));
        self::assertSame(1, $bounded['alpha_50']);
        self::assertArrayNotHasKey('zeta', $bounded);
        self::assertSame(1, $bounded['_other']);
        self::assertSame($bounded, PruneResult::bounded(array_reverse($categories, true)));
    }

    /**
     * No more than fifty categories are kept as they are, the largest first,
     * with no `_other`; one given is kept, and an already bounded map bounds to
     * itself.
     *
     * @return void
     */
    public function testFewCategoriesNeedNoOther(): void
    {
        self::assertSame(['security' => 3, 'finance' => 2], PruneResult::bounded(['finance' => 2, 'security' => 3]));
        self::assertSame([], PruneResult::bounded([]));
        self::assertSame(['finance' => 2, '_other' => 0], PruneResult::bounded(['_other' => 0, 'finance' => 2]));

        $categories = [];

        for ($index = 1; $index <= 70; $index++) {
            $categories[sprintf('category_%02d', $index)] = $index;
        }

        $bounded = PruneResult::bounded($categories);

        self::assertSame($bounded, PruneResult::bounded($bounded));
        self::assertSame(array_sum(range(1, 20)), $bounded['_other']);
    }

    /**
     * At most a hundred skipped seals are named, the first skipped.
     *
     * @return void
     */
    public function testTheSkippedSealIdsAreBoundedAtAHundred(): void
    {
        $ids = array_map(static fn (int $index): string => sprintf('01932b4e-a000-7000-8000-%012d', $index), range(1, 150));

        $result = new PruneResult(self::RUN, true, false, PruneStatus::PARTIAL, null, 'config:0123456789abcdef', 0, 0, 0, 0, 150, 3, 0, [], 0, $ids);

        self::assertSame(array_slice($ids, 0, 100), $result->skippedSealIds);
        self::assertSame(150, $result->skippedSeals);
    }

    /**
     * Whether the record was written is `false` until it is set, and setting it
     * keeps everything else.
     *
     * @return void
     */
    public function testWithRecordedKeepsEverythingElse(): void
    {
        $result   = self::completeResult(['finance' => 4]);
        $recorded = $result->withRecorded(true);

        self::assertFalse($result->recorded);
        self::assertTrue($recorded->recorded);
        self::assertSame([...$result->toArray(), 'recorded' => true], $recorded->toArray());
        self::assertFalse($recorded->withRecorded(false)->recorded);
    }

    /**
     * The map renders every field under its snake-case key, in order, the
     * status as its value.
     *
     * @return void
     */
    public function testTheMapRendersEveryField(): void
    {
        $pair   = ['category' => 'finance', 'tenant_type' => null, 'tenant_id' => null, 'cutoff' => '2026-10-01T00:00:00.000000Z', 'eligible' => 2];
        $plan   = ['pairs' => [$pair], 'seals' => [1 => 2]];
        $result = new PruneResult(self::RUN, false, true, PruneStatus::COMPLETE, null, 'config:0123456789abcdef', 0, 0, 1, 0, 0, 1, 0, [], 0, [], $plan);

        self::assertSame([
            'operation_id'     => self::RUN,
            'committed'        => false,
            'recorded'         => false,
            'dry_run'          => true,
            'status'           => 'complete',
            'failure'          => null,
            'policy_version'   => 'config:0123456789abcdef',
            'deleted'          => 0,
            'seals'            => 0,
            'held'             => 1,
            'pending_delivery' => 0,
            'skipped_seals'    => 0,
            'skipped_seal_ids' => [],
            'cursor'           => 1,
            'remaining'        => 0,
            'categories'       => [],
            'tenants_affected' => 0,
            'plan'             => $plan,
        ], $result->toArray());
    }

    /**
     * A failed result keeps why it failed, and every count as given.
     *
     * @return void
     */
    public function testAFailedResultKeepsItsReasonAndCounts(): void
    {
        $skipped = ['01932b4e-a000-7000-8000-000000000009'];
        $result  = new PruneResult(self::RUN, true, false, PruneStatus::FAILED, 'journal_broken', null, 5, 2, 1, 3, 1, 4, 6, ['finance' => 5], 2, $skipped);

        self::assertSame([PruneStatus::FAILED, 'journal_broken', null, null], [$result->status, $result->failure, $result->policyVersion, $result->plan]);
        self::assertSame([5, 2, 1, 3, 1], [$result->deleted, $result->seals, $result->held, $result->pendingDelivery, $result->skippedSeals]);
        self::assertSame([4, 6, 2], [$result->cursor, $result->remaining, $result->tenantsAffected]);
        self::assertSame(['01932b4e-a000-7000-8000-000000000009'], $result->skippedSealIds);
        self::assertTrue($result->committed);
        self::assertFalse($result->dryRun);
    }

    /**
     * A complete run's result with the categories given.
     *
     * @param  array<string, int>  $categories
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\PruneResult
     */
    private static function completeResult(array $categories): PruneResult
    {
        return new PruneResult(self::RUN, true, false, PruneStatus::COMPLETE, null, 'config:0123456789abcdef', array_sum($categories), 1, 0, 0, 0, 1, 0, $categories, 1, []);
    }
}
