<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;

/**
 * Unit tests for the finding enum: its cases and their values in order of
 * precedence, and the integrity status each gives.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Finding::class)]
final class FindingTest extends TestCase
{
    /**
     * The cases, in order of precedence, with their values, so a renamed,
     * reordered or added case fails: the order decides which of several
     * findings of one status a segment reports.
     *
     * @return void
     */
    public function testTheValuesArePinnedInPrecedenceOrder(): void
    {
        self::assertSame([
            'SEAL_MALFORMED'       => 'seal_malformed',
            'SEAL_VERSION'         => 'seal_version',
            'SEAL_KEY'             => 'seal_key',
            'LOG_MISMATCH'         => 'log_mismatch',
            'SEAL_DIGEST'          => 'seal_digest',
            'SEAL_SIGNATURE'       => 'seal_signature',
            'GENESIS'              => 'genesis',
            'SEQUENCE_GAP'         => 'sequence_gap',
            'CHAIN_BROKEN'         => 'chain_broken',
            'MEMBER_COUNT'         => 'member_count',
            'MEMBERS_DIGEST'       => 'members_digest',
            'ANCHOR_CONTRADICTION' => 'anchor_contradiction',
            'ANCHOR_CONFLICT'      => 'anchor_conflict',
            'MISSING_TAIL'         => 'missing_tail',
            'ORPHAN_MEMBER'        => 'orphan_member',
            'PRUNE_RECORD'         => 'prune_record',
            'MEMBER_HMAC'          => 'member_hmac',
            'ENTRY_HMAC'           => 'entry_hmac',
            'MANIFEST_MISSING'     => 'manifest_missing',
            'MANIFEST_MISMATCH'    => 'manifest_mismatch',
            'MANIFEST_SWAPPED'     => 'manifest_swapped',
            'MANIFEST_WRONG_KIND'  => 'manifest_wrong_kind',
            'MANIFEST_MALFORMED'   => 'manifest_malformed',
            'MANIFEST_TAMPERED'    => 'manifest_tampered',
            'PRUNE_KEY'            => 'prune_key',
            'ENTRY_MALFORMED'      => 'entry_malformed',
            'ENTRY_KEY'            => 'entry_key',
            'MANIFEST_UNREADABLE'  => 'manifest_unreadable',
            'MISSING_ENTRY'        => 'missing_entry',
            'OVERDUE_UNSEALED'     => 'overdue_unsealed',
            'FUTURE_UNSEALED'      => 'future_unsealed',
        ], array_column(Finding::cases(), 'value', 'name'));
    }

    /**
     * Each finding gives its status: a seal or entry that cannot be read or
     * whose key is unknown, or an artifact that cannot be decrypted, is
     * `unverifiable`, a missing entry, or an unsealed one overdue or far ahead
     * of the clock, is `incomplete`, and every other finding, an artifact that
     * is missing, mismatched, swapped, of the wrong kind, malformed or tampered
     * among them, shows the log was altered. The whole map is compared at once,
     * so a finding moved to another status fails.
     *
     * @return void
     */
    public function testEachFindingMapsToItsStatus(): void
    {
        self::assertSame([
            'seal_malformed'       => 'unverifiable',
            'seal_version'         => 'unverifiable',
            'seal_key'             => 'unverifiable',
            'log_mismatch'         => 'unverifiable',
            'seal_digest'          => 'tampered',
            'seal_signature'       => 'tampered',
            'genesis'              => 'tampered',
            'sequence_gap'         => 'tampered',
            'chain_broken'         => 'tampered',
            'member_count'         => 'tampered',
            'members_digest'       => 'tampered',
            'anchor_contradiction' => 'tampered',
            'anchor_conflict'      => 'tampered',
            'missing_tail'         => 'tampered',
            'orphan_member'        => 'tampered',
            'prune_record'         => 'tampered',
            'member_hmac'          => 'tampered',
            'entry_hmac'           => 'tampered',
            'manifest_missing'     => 'tampered',
            'manifest_mismatch'    => 'tampered',
            'manifest_swapped'     => 'tampered',
            'manifest_wrong_kind'  => 'tampered',
            'manifest_malformed'   => 'tampered',
            'manifest_tampered'    => 'tampered',
            'prune_key'            => 'unverifiable',
            'entry_malformed'      => 'unverifiable',
            'entry_key'            => 'unverifiable',
            'manifest_unreadable'  => 'unverifiable',
            'missing_entry'        => 'incomplete',
            'overdue_unsealed'     => 'incomplete',
            'future_unsealed'      => 'incomplete',
        ], array_combine(
            array_column(Finding::cases(), 'value'),
            array_map(static fn (Finding $finding): string => $finding->status()->value, Finding::cases()),
        ));
    }

    /**
     * No finding gives a status that passes: a finding is always a reason a
     * verification fails.
     *
     * @return void
     */
    public function testEveryFindingFails(): void
    {
        foreach (Finding::cases() as $finding) {
            self::assertTrue($finding->status()->isFailure(), $finding->value);
            self::assertNotSame(IntegrityStatus::PRUNED, $finding->status(), $finding->value);
        }
    }
}
