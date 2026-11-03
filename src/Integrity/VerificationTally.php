<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;

/**
 * The counts of one verification run, kept as it streams so no report is held:
 * the segments in each integrity and each anchoring status, every status listed
 * from zero in enum order, the segments awaiting their first anchoring, the
 * findings of the run as a whole, and the unsealed entries, pending and
 * overdue.
 *
 * Of every failing segment and run finding, it keeps the first failure: the one
 * of the most severe status, and of those the earliest it was given, with the
 * id it was found at.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class VerificationTally
{
    /** @var array<string, int> The segments in each integrity status, by its value, in enum order. */
    private array $integrity;

    /** @var array<string, int> The segments in each anchoring status, by its value, in enum order. */
    private array $anchoring;

    /** @var int The segments unanchored only because they were sealed within the anchoring grace. */
    private int $awaiting = 0;

    /** @var list<\SineMacula\Laravel\AuditLog\Integrity\RunFinding> The findings of the run as a whole, in the order found. */
    private array $findings = [];

    /** @var int Unsealed entries younger than the allowed age. */
    private int $pending = 0;

    /** @var int Unsealed entries older than the allowed age. */
    private int $overdue = 0;

    /** @var ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding The first failure's finding, or `null` while nothing has failed. */
    private ?Finding $firstFinding = null;

    /** @var ?string The id the first failure was found at, or `null` when there is none to name. */
    private ?string $firstBadId = null;

    /** @var int The severity of the first failure's status, or 0 while nothing has failed. */
    private int $severity = 0;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->integrity = array_fill_keys(array_map(static fn (IntegrityStatus $status): string => $status->value, IntegrityStatus::cases()), 0);
        $this->anchoring = array_fill_keys(array_map(static fn (AnchorStatus $status): string => $status->value, AnchorStatus::cases()), 0);
    }

    /**
     * Count a segment's report, and keep its finding when it is the first
     * failure.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SegmentReport  $report
     * @return void
     */
    public function add(SegmentReport $report): void
    {
        $this->integrity[$report->integrity->value]++;
        $this->anchoring[$report->anchoring->value]++;

        if ($report->awaitingAnchor) {
            $this->awaiting++;
        }

        $this->consider($report->integrity, $report->finding, $report->firstBadId);
    }

    /**
     * Keep a finding of the run as a whole, and its finding when it is the
     * first failure.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RunFinding  $finding
     * @return void
     */
    public function addFinding(RunFinding $finding): void
    {
        $this->findings[] = $finding;

        $this->consider($finding->status(), $finding->finding, $finding->firstBadId);
    }

    /**
     * Keep the counts of the entries no seal holds: those younger than the
     * allowed age, pending, and those older, overdue.
     *
     * @param  int  $pending
     * @param  int  $overdue
     * @return void
     */
    public function unsealed(int $pending, int $overdue): void
    {
        $this->pending = $pending;
        $this->overdue = $overdue;
    }

    /**
     * The segments in each integrity status, by its value, every status listed
     * in enum order.
     *
     * @return array<string, int>
     */
    public function integrity(): array
    {
        return $this->integrity;
    }

    /**
     * The segments in each anchoring status, by its value, every status listed
     * in enum order.
     *
     * @return array<string, int>
     */
    public function anchoring(): array
    {
        return $this->anchoring;
    }

    /**
     * The segments counted.
     *
     * @return int
     */
    public function segments(): int
    {
        return array_sum($this->integrity);
    }

    /**
     * The segments unanchored only because they were sealed within the
     * anchoring grace.
     *
     * @return int
     */
    public function awaiting(): int
    {
        return $this->awaiting;
    }

    /**
     * The findings of the run as a whole, in the order found.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\RunFinding>
     */
    public function findings(): array
    {
        return $this->findings;
    }

    /**
     * Unsealed entries younger than the allowed age.
     *
     * @return int
     */
    public function pending(): int
    {
        return $this->pending;
    }

    /**
     * Unsealed entries older than the allowed age.
     *
     * @return int
     */
    public function overdue(): int
    {
        return $this->overdue;
    }

    /**
     * The first failure's finding, or `null` when nothing failed.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    public function firstFinding(): ?Finding
    {
        return $this->firstFinding;
    }

    /**
     * The id the first failure was found at, or `null` when nothing failed or
     * it was found at no id.
     *
     * @return ?string
     */
    public function firstBadId(): ?string
    {
        return $this->firstBadId;
    }

    /**
     * Keep the finding as the first failure when its status fails and is more
     * severe than the failure kept so far.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus  $status
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $finding
     * @param  ?string  $id
     * @return void
     */
    private function consider(IntegrityStatus $status, ?Finding $finding, ?string $id): void
    {
        if ($finding === null || !$status->isFailure() || $status->severity() <= $this->severity) {
            return;
        }

        $this->firstFinding = $finding;
        $this->firstBadId   = $id;
        $this->severity     = $status->severity();
    }
}
