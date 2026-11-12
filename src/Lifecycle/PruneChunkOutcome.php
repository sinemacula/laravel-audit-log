<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * What one prune chunk did under the lock, with the replay it ended with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PruneChunkOutcome
{
    /**
     * Constructor.
     *
     * @param  list<string>  $deleted
     * @param  int  $held
     * @param  int  $pendingDelivery
     * @param  int  $ineligible
     * @param  bool  $sealFailed
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     */
    public function __construct(

        /** The ids of the entries the chunk deleted, in member order, which its prune record covers. */
        public array $deleted,

        /** How many eligible entries an active hold kept. */
        public int $held,

        /** How many eligible entries an outbox row or an undelivered receipt kept. */
        public int $pendingDelivery,

        /** How many verified entries were no longer eligible when read under the lock. */
        public int $ineligible,

        /** Whether a candidate failed verification, so nothing was deleted and the seal is skipped. */
        public bool $sealFailed,

        /** The replay the chunk ended with: advanced under the lock, and holding its prune row when it wrote one. */
        public JournalReplay $replay,
    ) {}

    /**
     * The outcome of a chunk with a candidate that failed verification.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @return self
     */
    public static function skippingTheSeal(JournalReplay $replay): self
    {
        return new self([], 0, 0, 0, true, $replay);
    }
}
