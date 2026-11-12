<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecision;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for one decision of a prune.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RetentionDecision::class)]
final class RetentionDecisionTest extends TestCase
{
    /** @var string The cut-off of the decisions below. */
    private const string CUTOFF = '2026-10-05T00:00:00.000000Z';

    /**
     * The decision keeps the pair, the days and the cut-off as given.
     *
     * @return void
     */
    public function testKeepsWhatItIsGiven(): void
    {
        $tenant   = Reference::of('team', 7);
        $decision = new RetentionDecision('security', $tenant, 30, 7, self::CUTOFF);

        self::assertSame('security', $decision->category);
        self::assertSame($tenant, $decision->tenant);
        self::assertSame(30, $decision->retainDays);
        self::assertSame(7, $decision->preserveDays);
        self::assertSame(self::CUTOFF, $decision->cutoff);
    }

    /**
     * Only an instant strictly before the cut-off is admitted, bytewise.
     *
     * @return void
     */
    public function testAdmitsAnInstantStrictlyBeforeTheCutoff(): void
    {
        $decision = new RetentionDecision('general', null, 30, null, self::CUTOFF);

        self::assertTrue($decision->admits('2026-10-04T23:59:59.999999Z'));
        self::assertTrue($decision->admits('1970-01-01T00:00:00.000000Z'));
        self::assertFalse($decision->admits(self::CUTOFF));
        self::assertFalse($decision->admits('2026-10-05T00:00:00.000001Z'));
        self::assertFalse($decision->admits('2026-11-04T12:00:00.000000Z'));
    }

    /**
     * A decision with no cut-off admits nothing, not even the empty instant.
     *
     * @return void
     */
    public function testNoCutoffAdmitsNothing(): void
    {
        $decision = new RetentionDecision('general', null, null, PHP_INT_MAX, null);

        self::assertFalse($decision->admits('0001-01-01T00:00:00.000000Z'));
        self::assertFalse($decision->admits(''));
    }

    /**
     * The journal list is the pair, the days kept and preserved, the cut-off.
     *
     * @return void
     */
    public function testToArrayIsTheJournalsList(): void
    {
        self::assertSame(
            ['security', 'team', '7', 30, PHP_INT_MAX, self::CUTOFF],
            (new RetentionDecision('security', Reference::of('team', 7), 30, PHP_INT_MAX, self::CUTOFF))->toArray(),
        );

        self::assertSame(['general', null, null, null, null, null], (new RetentionDecision('general', null, null, null, null))->toArray());
    }
}
