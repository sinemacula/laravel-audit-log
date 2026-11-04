<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;

/**
 * Unit tests for the finding enum: its cases and their values in order of
 * precedence, the integrity status each gives, the journal's and the key
 * store's findings among them, and the order within each status.
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
            'SEAL_MALFORMED'             => 'seal_malformed',
            'SEAL_VERSION'               => 'seal_version',
            'SEAL_KEY'                   => 'seal_key',
            'LOG_MISMATCH'               => 'log_mismatch',
            'SEAL_DIGEST'                => 'seal_digest',
            'SEAL_SIGNATURE'             => 'seal_signature',
            'GENESIS'                    => 'genesis',
            'SEQUENCE_GAP'               => 'sequence_gap',
            'CHAIN_BROKEN'               => 'chain_broken',
            'MEMBER_COUNT'               => 'member_count',
            'MEMBERS_DIGEST'             => 'members_digest',
            'ANCHOR_CONTRADICTION'       => 'anchor_contradiction',
            'ANCHOR_CONFLICT'            => 'anchor_conflict',
            'MISSING_TAIL'               => 'missing_tail',
            'ORPHAN_MEMBER'              => 'orphan_member',
            'PRUNE_RECORD'               => 'prune_record',
            'MEMBER_HMAC'                => 'member_hmac',
            'ENTRY_HMAC'                 => 'entry_hmac',
            'MANIFEST_MISSING'           => 'manifest_missing',
            'MANIFEST_MISMATCH'          => 'manifest_mismatch',
            'MANIFEST_SWAPPED'           => 'manifest_swapped',
            'MANIFEST_WRONG_KIND'        => 'manifest_wrong_kind',
            'MANIFEST_MALFORMED'         => 'manifest_malformed',
            'MANIFEST_TAMPERED'          => 'manifest_tampered',
            'JOURNAL_GAP'                => 'journal_gap',
            'JOURNAL_SIGNATURE'          => 'journal_signature',
            'JOURNAL_COMMITMENT'         => 'journal_commitment',
            'JOURNAL_TRANSITION'         => 'journal_transition',
            'KEY_USE_MISSING'            => 'key_use_missing',
            'KEY_MISSING'                => 'key_missing',
            'KEY_SUBSTITUTED'            => 'key_substituted',
            'KEY_DESTROYED_UNJOURNALLED' => 'key_destroyed_unjournalled',
            'KEY_RESTORED'               => 'key_restored',
            'PRUNE_KEY'                  => 'prune_key',
            'ENTRY_MALFORMED'            => 'entry_malformed',
            'ENTRY_KEY'                  => 'entry_key',
            'MANIFEST_UNREADABLE'        => 'manifest_unreadable',
            'JOURNAL_KEY'                => 'journal_key',
            'JOURNAL_MALFORMED'          => 'journal_malformed',
            'KEY_UNVERIFIABLE'           => 'key_unverifiable',
            'MISSING_ENTRY'              => 'missing_entry',
            'OVERDUE_UNSEALED'           => 'overdue_unsealed',
            'FUTURE_UNSEALED'            => 'future_unsealed',
            'RESURRECTED'                => 'resurrected',
        ], array_column(Finding::cases(), 'value', 'name'));
    }

    /**
     * Each finding gives its status: a seal, entry, journal row or key row that
     * cannot be read or whose key is unknown, or an artifact that cannot be
     * decrypted, is `unverifiable`, a missing entry, an unsealed one overdue or
     * far ahead of the clock, or a pruned one present again, is `incomplete`,
     * and every other finding, an artifact that is missing, mismatched,
     * swapped, of the wrong kind, malformed or tampered, a journal that is
     * gapped, forged, uncommitted or out of its transitions, and a key use or a
     * key that is missing, substituted, destroyed unjournalled or restored
     * among them, shows the log was altered. The whole map is compared at once,
     * so a finding moved to another status fails.
     *
     * @return void
     */
    public function testEachFindingMapsToItsStatus(): void
    {
        self::assertSame([
            'seal_malformed'             => 'unverifiable',
            'seal_version'               => 'unverifiable',
            'seal_key'                   => 'unverifiable',
            'log_mismatch'               => 'unverifiable',
            'seal_digest'                => 'tampered',
            'seal_signature'             => 'tampered',
            'genesis'                    => 'tampered',
            'sequence_gap'               => 'tampered',
            'chain_broken'               => 'tampered',
            'member_count'               => 'tampered',
            'members_digest'             => 'tampered',
            'anchor_contradiction'       => 'tampered',
            'anchor_conflict'            => 'tampered',
            'missing_tail'               => 'tampered',
            'orphan_member'              => 'tampered',
            'prune_record'               => 'tampered',
            'member_hmac'                => 'tampered',
            'entry_hmac'                 => 'tampered',
            'manifest_missing'           => 'tampered',
            'manifest_mismatch'          => 'tampered',
            'manifest_swapped'           => 'tampered',
            'manifest_wrong_kind'        => 'tampered',
            'manifest_malformed'         => 'tampered',
            'manifest_tampered'          => 'tampered',
            'journal_gap'                => 'tampered',
            'journal_signature'          => 'tampered',
            'journal_commitment'         => 'tampered',
            'journal_transition'         => 'tampered',
            'key_use_missing'            => 'tampered',
            'key_missing'                => 'tampered',
            'key_substituted'            => 'tampered',
            'key_destroyed_unjournalled' => 'tampered',
            'key_restored'               => 'tampered',
            'prune_key'                  => 'unverifiable',
            'entry_malformed'            => 'unverifiable',
            'entry_key'                  => 'unverifiable',
            'manifest_unreadable'        => 'unverifiable',
            'journal_key'                => 'unverifiable',
            'journal_malformed'          => 'unverifiable',
            'key_unverifiable'           => 'unverifiable',
            'missing_entry'              => 'incomplete',
            'overdue_unsealed'           => 'incomplete',
            'future_unsealed'            => 'incomplete',
            'resurrected'                => 'incomplete',
        ], array_combine(
            array_column(Finding::cases(), 'value'),
            array_map(static fn (Finding $finding): string => $finding->status()->value, Finding::cases()),
        ));
    }

    /**
     * Rows of `[finding, the status it gives]`: the journal's findings and a
     * pruned member present again.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus}>
     */
    public static function provideLifecycleFindings(): iterable
    {
        yield from [
            'a gap in the journal'         => [Finding::JOURNAL_GAP, IntegrityStatus::TAMPERED],
            'a journal row\'s signature'   => [Finding::JOURNAL_SIGNATURE, IntegrityStatus::TAMPERED],
            'a seal\'s journal commitment' => [Finding::JOURNAL_COMMITMENT, IntegrityStatus::TAMPERED],
            'a journal transition'         => [Finding::JOURNAL_TRANSITION, IntegrityStatus::TAMPERED],
            'a journal row\'s unknown key' => [Finding::JOURNAL_KEY, IntegrityStatus::UNVERIFIABLE],
            'a malformed journal row'      => [Finding::JOURNAL_MALFORMED, IntegrityStatus::UNVERIFIABLE],
            'a resurrected member'         => [Finding::RESURRECTED, IntegrityStatus::INCOMPLETE],
        ];
    }

    /**
     * Each new finding gives its status, and is read back from its value.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus  $status
     * @return void
     */
    #[DataProvider('provideLifecycleFindings')]
    public function testEachLifecycleFindingGivesItsStatus(Finding $finding, IntegrityStatus $status): void
    {
        self::assertSame($status, $finding->status());
        self::assertSame($finding, Finding::from($finding->value));
    }

    /**
     * Rows of `[finding, the status it gives]`: the key store's findings, each
     * showing the log was altered but a key row signed or wrapped under a key
     * that is not held.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus}>
     */
    public static function provideKeyFindings(): iterable
    {
        yield from [
            'an envelope with no key use'   => [Finding::KEY_USE_MISSING, IntegrityStatus::TAMPERED],
            'a key use with no key row'     => [Finding::KEY_MISSING, IntegrityStatus::TAMPERED],
            'a substituted key row'         => [Finding::KEY_SUBSTITUTED, IntegrityStatus::TAMPERED],
            'an unjournalled destruction'   => [Finding::KEY_DESTROYED_UNJOURNALLED, IntegrityStatus::TAMPERED],
            'a restored key'                => [Finding::KEY_RESTORED, IntegrityStatus::TAMPERED],
            'a key under an unknown secret' => [Finding::KEY_UNVERIFIABLE, IntegrityStatus::UNVERIFIABLE],
        ];
    }

    /**
     * Each key finding gives its status, and is read back from its value.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus  $status
     * @return void
     */
    #[DataProvider('provideKeyFindings')]
    public function testEveryKeyFindingHasItsStatus(Finding $finding, IntegrityStatus $status): void
    {
        self::assertSame($status, $finding->status());
        self::assertSame($finding, Finding::from($finding->value));
    }

    /**
     * Within each status the findings keep their order of precedence, each
     * added group after every finding its status already had: the journal's
     * findings and the resurrected member, then the key store's, so none of
     * them outranks an earlier finding when a segment fails several checks of
     * one status.
     *
     * @return void
     */
    public function testTheOrderWithinEachStatus(): void
    {
        $byStatus = [];

        foreach (Finding::cases() as $finding) {
            $byStatus[$finding->status()->value][] = $finding->value;
        }

        self::assertSame([
            'unverifiable' => [
                'seal_malformed', 'seal_version', 'seal_key', 'log_mismatch', 'prune_key', 'entry_malformed', 'entry_key', 'manifest_unreadable',
                'journal_key', 'journal_malformed', 'key_unverifiable',
            ],
            'tampered' => [
                'seal_digest', 'seal_signature', 'genesis', 'sequence_gap', 'chain_broken', 'member_count', 'members_digest', 'anchor_contradiction',
                'anchor_conflict', 'missing_tail', 'orphan_member', 'prune_record', 'member_hmac', 'entry_hmac', 'manifest_missing',
                'manifest_mismatch', 'manifest_swapped', 'manifest_wrong_kind', 'manifest_malformed', 'manifest_tampered', 'journal_gap',
                'journal_signature', 'journal_commitment', 'journal_transition', 'key_use_missing', 'key_missing', 'key_substituted',
                'key_destroyed_unjournalled', 'key_restored',
            ],
            'incomplete' => ['missing_entry', 'overdue_unsealed', 'future_unsealed', 'resurrected'],
        ], $byStatus);
    }

    /**
     * The key store's findings are the last of their statuses: every other
     * tampered finding precedes the five that show a key or a key use was
     * altered, and every other unverifiable one precedes a key whose secret is
     * not held, so a key finding never hides a finding of the log itself.
     *
     * @return void
     */
    public function testTheKeyFindingsFollowEveryOtherFindingOfTheirStatus(): void
    {
        $order = array_column(Finding::cases(), 'value');
        $tails = [
            'tampered'     => ['key_use_missing', 'key_missing', 'key_substituted', 'key_destroyed_unjournalled', 'key_restored'],
            'unverifiable' => ['key_unverifiable'],
        ];

        foreach ($tails as $status => $tail) {

            $ofStatus = array_values(array_filter($order, static fn (string $value): bool => Finding::from($value)->status()->value === $status));

            self::assertSame($tail, array_slice($ofStatus, -count($tail)), $status);
            self::assertSame([], array_values(array_filter(array_slice($ofStatus, 0, -count($tail)), static fn (string $value): bool => str_starts_with($value, 'key_'))), $status);
        }
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
