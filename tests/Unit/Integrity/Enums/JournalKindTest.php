<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;

/**
 * Unit tests for the journal kind enum: its cases and their stored values, the
 * label each signs under, the kinds that carry an authority, and the kinds
 * whose payloads the pruner replays.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JournalKind::class)]
final class JournalKindTest extends TestCase
{
    /**
     * The cases, in order, with the values the journal stores, so a renamed,
     * reordered or added case fails.
     *
     * @return void
     */
    public function testTheStoredValues(): void
    {
        self::assertSame([
            'POLICY'          => 'policy',
            'PRUNE_RUN'       => 'prune_run',
            'PRUNE'           => 'prune',
            'HOLD'            => 'hold',
            'RELEASE'         => 'release',
            'IMPORT_STARTED'  => 'import_started',
            'IMPORT_FINISHED' => 'import_finished',
        ], array_combine(
            array_map(static fn (JournalKind $kind): string => $kind->name, JournalKind::cases()),
            array_map(static fn (JournalKind $kind): string => $kind->value, JournalKind::cases()),
        ));
    }

    /**
     * Each kind signs under a label naming it, version 1 and a new line, so no
     * two kinds share one.
     *
     * @return void
     */
    public function testEachLabelNamesItsKind(): void
    {
        $labels = array_map(static fn (JournalKind $kind): string => $kind->label(), JournalKind::cases());

        self::assertSame("audit-log:lifecycle:policy:v1\n", JournalKind::POLICY->label());
        self::assertSame("audit-log:lifecycle:import_finished:v1\n", JournalKind::IMPORT_FINISHED->label());

        foreach (JournalKind::cases() as $kind) {
            self::assertSame('audit-log:lifecycle:' . $kind->value . ":v1\n", $kind->label(), $kind->name);
        }

        self::assertCount(count(JournalKind::cases()), array_unique($labels));
    }

    /**
     * A hold, a release, and an import's start and finish carry the authority
     * that asked for them; a policy, a prune run and a prune chunk carry none.
     *
     * @return void
     */
    public function testWhichKindsCarryAnAuthority(): void
    {
        $carrying = array_values(array_filter(JournalKind::cases(), static fn (JournalKind $kind): bool => $kind->carriesAuthority()));

        self::assertSame([JournalKind::HOLD, JournalKind::RELEASE, JournalKind::IMPORT_STARTED, JournalKind::IMPORT_FINISHED], $carrying);
    }

    /**
     * Only a policy's, a hold's and a release's payloads are read when the
     * pruner replays the journal.
     *
     * @return void
     */
    public function testOnlyPoliciesHoldsAndReleasesAreReplayedFromTheirPayloads(): void
    {
        $replayed = array_values(array_filter(JournalKind::cases(), static fn (JournalKind $kind): bool => $kind->readsPayloadToReplay()));

        self::assertSame([JournalKind::POLICY, JournalKind::HOLD, JournalKind::RELEASE], $replayed);
    }
}
