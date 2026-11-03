<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;

/**
 * What one verification run established: the exact range of seals it checked
 * and the head it observed, the anchor's head and how it compared, whether the
 * run covered the whole log, the segments in each integrity and anchoring
 * status, the findings of the run as a whole, the unsealed entries, and the
 * first failure.
 *
 * A run fails on any integrity failure, of a segment or of the run. A strict
 * run with an anchor configured also fails on any segment short of `anchored`,
 * except one awaiting its first anchoring, on any `unavailable` or
 * `contradicted` segment, on an anchor that cannot report its head, and on an
 * anchor's head that is not `anchored`; an anchor that holds no seal is excused
 * only while every seal from the first is still awaiting its first anchoring.
 * With no anchor configured, `strict` changes nothing, and `unanchored` is
 * informational.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class VerificationSummary
{
    /**
     * Constructor.
     *
     * @param  int  $from
     * @param  int  $to
     * @param  ?int  $head
     * @param  ?int  $remoteHead
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus  $remote
     * @param  bool  $complete
     * @param  bool  $anchorConfigured
     * @param  bool  $discovers
     * @param  array<string, int>  $integrity
     * @param  array<string, int>  $anchoring
     * @param  int  $awaiting
     * @param  list<\SineMacula\Laravel\AuditLog\Integrity\RunFinding>  $findings
     * @param  int  $pending
     * @param  int  $overdue
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding  $firstFinding
     * @param  ?string  $firstBadId
     */
    public function __construct(

        /** The sequence of the first seal checked. */
        public int $from,

        /** The sequence of the last seal checked; before `from` when there was none to check. */
        public int $to,

        /** The sequence of the local head the run observed, or `null` when the log had no seal. */
        public ?int $head,

        /** The sequence of the anchor's head, or `null` when it holds none or was not asked. */
        public ?int $remoteHead,

        /** How the anchor's head compared with the local log, or `null` with no anchor configured. */
        public ?AnchorStatus $remote,

        /** Whether the run covered the whole log. */
        public bool $complete,

        /** Whether an anchor other than the null anchor is configured. */
        public bool $anchorConfigured,

        /** Whether the configured anchor can report its head. */
        public bool $discovers,

        /** The segments in each integrity status, by its value, every status listed in enum order. */
        public array $integrity,

        /** The segments in each anchoring status, by its value, every status listed in enum order. */
        public array $anchoring,

        /** The segments unanchored only because they were sealed within the anchoring grace. */
        public int $awaiting,

        /** The findings of the run as a whole, in the order found. */
        public array $findings,

        /** Unsealed entries younger than the allowed age. */
        public int $pending,

        /** Unsealed entries older than the allowed age. */
        public int $overdue,

        /** The first failure's finding, or `null` when nothing failed. */
        public ?Finding $firstFinding,

        /** The id the first failure was found at, or `null` when there is none to name. */
        public ?string $firstBadId,
    ) {}

    /**
     * The summary of a run from its counts, the range it checked, the heads it
     * observed and what it knows of the anchor.
     *
     * @param  array{0: int, 1: int}  $bounds
     * @param  ?int  $head
     * @param  ?int  $remoteHead
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus  $remote
     * @param  bool  $complete
     * @param  bool  $discovers
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @return self
     */
    public static function of(array $bounds, ?int $head, ?int $remoteHead, ?AnchorStatus $remote, bool $complete, bool $discovers, VerificationTally $tally): self
    {
        return new self(
            $bounds[0],
            $bounds[1],
            $head,
            $remoteHead,
            $remote,
            $complete,
            $remote !== null,
            $discovers,
            $tally->integrity(),
            $tally->anchoring(),
            $tally->awaiting(),
            $tally->findings(),
            $tally->pending(),
            $tally->overdue(),
            $tally->firstFinding(),
            $tally->firstBadId(),
        );
    }

    /**
     * Whether the run fails: on any integrity failure, and when strict, with an
     * anchor configured, on anything short of what the anchor confirms.
     *
     * @param  bool  $strict
     * @return bool
     */
    public function fails(bool $strict): bool
    {
        if ($this->hasIntegrityFailure()) {
            return true;
        }

        return $strict && $this->anchorConfigured && $this->fallsShortOfAnchored();
    }

    /**
     * The summary as the last line of output: the range checked and the heads
     * observed, how the anchor compared, the counts, the first failure, and
     * whether the run passed.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  bool  $strict
     * @return array{type: 'summary', from: int, to: int, head: ?int, remote_head: ?int, remote: ?string, complete: bool, strict: bool, integrity: array<string, int>, anchoring: array<string, int>, awaiting_anchor: int, pending: int, overdue: int, first_finding: ?string, first_bad_id: ?string, passed: bool}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function toArray(bool $strict): array
    {
        return [
            'type'            => 'summary',
            'from'            => $this->from,
            'to'              => $this->to,
            'head'            => $this->head,
            'remote_head'     => $this->remoteHead,
            'remote'          => $this->remote?->value,
            'complete'        => $this->complete,
            'strict'          => $strict,
            'integrity'       => $this->integrity,
            'anchoring'       => $this->anchoring,
            'awaiting_anchor' => $this->awaiting,
            'pending'         => $this->pending,
            'overdue'         => $this->overdue,
            'first_finding'   => $this->firstFinding?->value,
            'first_bad_id'    => $this->firstBadId,
            'passed'          => !$this->fails($strict),
        ];
    }

    /**
     * The event that tells listeners the run failed, from the command given:
     * the counts in every status, the first failure, the heads observed and
     * whether the run covered the whole log.
     *
     * @param  string  $command
     * @return \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed
     */
    public function toEvent(string $command): IntegrityCheckFailed
    {
        $finding = $this->firstFinding?->value;

        return new IntegrityCheckFailed($command, $this->integrity, $this->anchoring, $finding, $this->firstBadId, $this->head, $this->remoteHead, $this->complete);
    }

    /**
     * Whether a segment or a finding of the run has a status that fails.
     *
     * @return bool
     */
    private function hasIntegrityFailure(): bool
    {
        foreach (IntegrityStatus::cases() as $status) {
            if ($status->isFailure() && $this->integrity[$status->value] > 0) {
                return true;
            }
        }

        // Every finding gives a status that fails
        return $this->findings !== [];
    }

    /**
     * Whether the run falls short of what a strict run requires of the anchor:
     * a segment unanchored and not awaiting its first anchoring, one
     * unavailable or contradicted, an anchor that cannot report its head, or an
     * anchor's head that is not accepted.
     *
     * @return bool
     */
    private function fallsShortOfAnchored(): bool
    {
        $unexcused = max(0, $this->anchoring[AnchorStatus::UNANCHORED->value] - $this->awaiting);
        $short     = $unexcused + $this->anchoring[AnchorStatus::UNAVAILABLE->value] + $this->anchoring[AnchorStatus::CONTRADICTED->value];

        return $short > 0 || !$this->discovers || !$this->isRemoteAccepted();
    }

    /**
     * Whether the anchor's head is accepted by a strict run: it is `anchored`,
     * or the anchor holds no seal while every seal from the first awaits its
     * first anchoring.
     *
     * @return bool
     */
    private function isRemoteAccepted(): bool
    {
        if ($this->remote === AnchorStatus::ANCHORED) {
            return true;
        }

        $segments = array_sum($this->integrity);
        $empty    = $this->remote === AnchorStatus::UNANCHORED && $this->remoteHead === null;
        $awaiting = $this->from   === 1                        && $segments > 0 && $this->awaiting === $segments;

        return $empty && $awaiting;
    }
}
