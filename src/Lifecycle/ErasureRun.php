<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * What a run of erasures carries from one to the next, so the installation is
 * confirmed once and each journal row is read once rather than per owner.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ErasureRun
{
    /** @var ?\SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay The last committed erasure's replay. */
    private ?JournalReplay $replay = null;

    /** @var bool Whether the installation was confirmed for the run. */
    private bool $confirmed = false;

    /**
     * The last committed erasure's replay, or `null` before the first.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay
     */
    public function replay(): ?JournalReplay
    {
        return $this->replay;
    }

    /**
     * Keep a committed erasure's replay for the next to advance.
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
