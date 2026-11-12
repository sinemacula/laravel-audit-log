<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\JournalSummary;
use SineMacula\Laravel\AuditLog\Integrity\KeyStoreSummary;
use SineMacula\Laravel\AuditLog\Integrity\RunFinding;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\VerificationSummary;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use Symfony\Component\Console\Formatter\OutputFormatter;

/**
 * The lines `audit-log:verify` prints as text.
 *
 * An id or class an altered table may hold is sanitised and escaped, so nothing
 * in it is read as a style.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class VerifyLines
{
    /** @var string How an id the line has none of is written. */
    public const string NONE = 'none';

    /**
     * Disallow instantiation.
     */
    private function __construct() {}

    /**
     * The line of a verified seal: its sequence, id, statuses and members,
     * whether it awaits anchoring, and any finding with its first id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SegmentReport  $report
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function segmentLine(SegmentReport $report): string
    {
        $line = sprintf(
            'seal %d %s integrity=%s anchoring=%s members=%d',
            $report->sequence,
            self::id($report->sealId),
            $report->integrity->value,
            $report->anchoring->value,
            $report->members,
        );

        if ($report->awaitingAnchor) {
            $line .= ' awaiting-anchor';
        }

        if ($report->finding === null) {
            return $line;
        }

        return $line . sprintf(' finding=%s first=%s', $report->finding->value, self::id($report->firstBadId));
    }

    /**
     * The line of a finding of the run as a whole: the check, the status it
     * gives, how many times it was found and the first id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RunFinding  $finding
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function findingLine(RunFinding $finding): string
    {
        return sprintf('finding %s integrity=%s count=%d first=%s', $finding->finding->value, $finding->status()->value, $finding->count, self::id($finding->firstBadId));
    }

    /**
     * The id as a line shows it, sanitised and escaped since an altered table
     * may hold anything, or `none` when there is no id.
     *
     * @param  ?string  $id
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function id(?string $id): string
    {
        return $id === null || $id === '' ? self::NONE : OutputFormatter::escape(TextSanitizer::clean($id));
    }

    /**
     * The line of the seals in each integrity status.
     *
     * @param  array<string, int>  $integrity
     * @return string
     */
    public static function integrityLine(array $integrity): string
    {
        return sprintf(
            'Integrity: %d valid, %d pruned, %d incomplete, %d unverifiable, %d tampered.',
            $integrity[IntegrityStatus::VALID->value],
            $integrity[IntegrityStatus::PRUNED->value],
            $integrity[IntegrityStatus::INCOMPLETE->value],
            $integrity[IntegrityStatus::UNVERIFIABLE->value],
            $integrity[IntegrityStatus::TAMPERED->value],
        );
    }

    /**
     * The line of the seals in each anchoring status, with those unanchored
     * only while they await their first anchoring.
     *
     * @param  array<string, int>  $anchoring
     * @param  int  $awaiting
     * @return string
     */
    public static function anchoringLine(array $anchoring, int $awaiting): string
    {
        return sprintf(
            'Anchoring: %d anchored, %d unanchored (%d awaiting their first anchoring), %d unavailable, %d contradicted.',
            $anchoring[AnchorStatus::ANCHORED->value],
            $anchoring[AnchorStatus::UNANCHORED->value],
            $awaiting,
            $anchoring[AnchorStatus::UNAVAILABLE->value],
            $anchoring[AnchorStatus::CONTRADICTED->value],
        );
    }

    /**
     * The line of the lifecycle journal: the rows read, the sequence of the
     * chain's head, and the sequence the latest seal commits to.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSummary  $journal
     * @return string
     */
    public static function journalLine(JournalSummary $journal): string
    {
        return sprintf(
            'Journal: %d rows to sequence %s; the latest seal commits to %s.',
            $journal->rowsRead,
            $journal->head      ?? self::NONE,
            $journal->committed ?? self::NONE,
        );
    }

    /**
     * The line of the owners' key store: keys verified, erased and findings, or
     * that it was skipped for a field encrypter that is not the package's.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\KeyStoreSummary  $keys
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function keysLine(KeyStoreSummary $keys): string
    {
        if ($keys->skipped) {
            return sprintf('Keys: skipped; the bound field encrypter %s does not use the package\'s key store.', self::id($keys->encrypter));
        }

        return sprintf('Keys: %d verified, %d erased, %d findings.', $keys->keys, $keys->erased, $keys->findings);
    }

    /**
     * The seals the run checked and the head it observed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary  $summary
     * @return string
     */
    public static function coverage(VerificationSummary $summary): string
    {
        if ($summary->head === null) {
            return 'Checked no seals: the log has none;';
        }

        return sprintf('Checked seals %d to %d of head %d;', $summary->from, $summary->to, $summary->head);
    }

    /**
     * What the run learnt of the anchor's head.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary  $summary
     * @return string
     */
    public static function anchorClause(VerificationSummary $summary): string
    {
        return match (true) {
            !$summary->anchorConfigured                     => 'no anchor is configured.',
            !$summary->discovers                            => 'the anchor cannot report its head.',
            $summary->remote === AnchorStatus::UNAVAILABLE  => 'the anchor is unavailable.',
            $summary->remoteHead !== null                   => sprintf('the anchor\'s head is %d.', $summary->remoteHead),
            $summary->remote === AnchorStatus::CONTRADICTED => 'the anchor holds another digest for a seal.',
            default                                         => 'the anchor holds no seal.',
        };
    }
}
