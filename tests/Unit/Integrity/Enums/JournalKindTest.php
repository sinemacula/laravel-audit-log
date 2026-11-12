<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;

/**
 * Unit tests for the journal kind enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JournalKind::class)]
final class JournalKindTest extends TestCase
{
    /** @var list<\SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind> The kinds an owner's keys journal. */
    private const array PRIVACY_KINDS = [JournalKind::ERASURE, JournalKind::REINSTATE, JournalKind::REWRAP, JournalKind::RESTORE_RECONCILED];

    /**
     * The cases, in order, with the values the journal stores, so a renamed,
     * reordered or added case fails.
     *
     * @return void
     */
    public function testTheStoredValues(): void
    {
        self::assertSame([
            'POLICY'             => 'policy',
            'PRUNE_RUN'          => 'prune_run',
            'PRUNE'              => 'prune',
            'HOLD'               => 'hold',
            'RELEASE'            => 'release',
            'IMPORT_STARTED'     => 'import_started',
            'IMPORT_FINISHED'    => 'import_finished',
            'ERASURE'            => 'erasure',
            'REINSTATE'          => 'reinstate',
            'REWRAP'             => 'rewrap',
            'RESTORE_RECONCILED' => 'restore_reconciled',
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
     * Each privacy kind signs under its own label, so one never verifies as
     * another.
     *
     * @return void
     */
    public function testEachKindSignsUnderItsOwnLabel(): void
    {
        self::assertSame([
            'erasure'            => "audit-log:lifecycle:erasure:v1\n",
            'reinstate'          => "audit-log:lifecycle:reinstate:v1\n",
            'rewrap'             => "audit-log:lifecycle:rewrap:v1\n",
            'restore_reconciled' => "audit-log:lifecycle:restore_reconciled:v1\n",
        ], array_combine(
            array_map(static fn (JournalKind $kind): string => $kind->value, self::PRIVACY_KINDS),
            array_map(static fn (JournalKind $kind): string => $kind->label(), self::PRIVACY_KINDS),
        ));

        foreach (JournalKind::cases() as $other) {
            foreach (self::PRIVACY_KINDS as $kind) {
                self::assertSame($other === $kind, $other->label() === $kind->label(), $kind->value . ' and ' . $other->value);
            }
        }
    }

    /**
     * Holds, releases, imports and privacy kinds carry an authority; policies
     * and prune rows do not.
     *
     * @return void
     */
    public function testWhichKindsCarryAnAuthority(): void
    {
        $carrying = array_values(array_filter(JournalKind::cases(), static fn (JournalKind $kind): bool => $kind->carriesAuthority()));

        self::assertSame([
            JournalKind::HOLD, JournalKind::RELEASE, JournalKind::IMPORT_STARTED, JournalKind::IMPORT_FINISHED, JournalKind::ERASURE,
            JournalKind::REINSTATE, JournalKind::REWRAP, JournalKind::RESTORE_RECONCILED,
        ], $carrying);
    }

    /**
     * An erasure, a reinstatement, a rewrap batch and a reconciled restore are
     * each asked for by an operator, so each carries the authority that asked.
     *
     * @return void
     */
    public function testThePrivacyKindsCarryAnAuthority(): void
    {
        foreach (self::PRIVACY_KINDS as $kind) {
            self::assertTrue($kind->carriesAuthority(), $kind->value);
        }
    }

    /**
     * The pruner never replays a privacy kind's payload.
     *
     * @return void
     */
    public function testNoPrivacyKindIsReplayedForItsPayload(): void
    {
        foreach (self::PRIVACY_KINDS as $kind) {
            self::assertFalse($kind->readsPayloadToReplay(), $kind->value);
        }
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
