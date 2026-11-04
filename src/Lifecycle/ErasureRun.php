<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * What a run of erasures, one owner after another, carries from each erasure to
 * the next: whether the installation was confirmed, which a run does once, and
 * the journal replay the last committed erasure left.
 *
 * The first erasure of a run verifies the whole journal; every later one
 * advances the replay it is given from that head, so a run of many owners reads
 * each journal row once rather than once per owner. A replay is kept only once
 * its erasure's transaction has committed, so a refused or failed erasure
 * leaves the replay the run held before it, whose head is still the journal's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ErasureRun
{
    /** @var ?\SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay The replay the last committed erasure left, or `null` before the first. */
    private ?JournalReplay $replay = null;

    /** @var bool Whether the installation was confirmed for the run. */
    private bool $confirmed = false;

    /**
     * The replay the last committed erasure of the run left, or `null` when
     * none has committed yet.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay
     */
    public function replay(): ?JournalReplay
    {
        return $this->replay;
    }

    /**
     * Keep the replay a committed erasure left, for the next to advance.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @return void
     */
    public function committed(JournalReplay $replay): void
    {
        $this->replay = $replay;
    }

    /**
     * Whether the installation was confirmed for the run.
     *
     * @return bool
     */
    public function isConfirmed(): bool
    {
        return $this->confirmed;
    }

    /**
     * Note that the installation was confirmed for the run.
     *
     * @return void
     */
    public function confirmed(): void
    {
        $this->confirmed = true;
    }
}
