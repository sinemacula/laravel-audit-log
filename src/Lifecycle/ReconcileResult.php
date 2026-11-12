<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;

/**
 * The tally of one reconciliation: each operation examined counted under
 * exactly one outcome, never by id or value.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, int>
 */
final readonly class ReconcileResult implements Arrayable
{
    /** @var int The operations examined: the sum of the five outcomes. */
    public int $examined;

    /**
     * Constructor.
     *
     * @param  int  $recorded
     * @param  int  $alreadyRecorded
     * @param  int  $unverifiable
     * @param  int  $unfinished
     * @param  int  $failed
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The operations whose missing record was written again. */
        public int $recorded = 0,

        /** The operations an entry already records. */
        public int $alreadyRecorded = 0,

        /** The operations whose journal rows do not verify, which are never recorded. */
        public int $unverifiable = 0,

        /** The prune runs that started and have not finished, which have nothing to record yet. */
        public int $unfinished = 0,

        /** The operations whose missing record could not be written. */
        public int $failed = 0,
    ) {
        if (min($recorded, $alreadyRecorded, $unverifiable, $unfinished, $failed) < 0) {
            throw new \InvalidArgumentException('A reconciliation\'s counts must each be at least 0.');
        }

        $this->examined = $recorded + $alreadyRecorded + $unverifiable + $unfinished + $failed;
    }

    /**
     * Whether nothing is left missing; an unfinished prune run has nothing to
     * record yet.
     *
     * @return bool
     */
    public function isComplete(): bool
    {
        return $this->failed === 0 && $this->unverifiable === 0;
    }

    /**
     * The tally as the command prints it.
     *
     * @return array{examined: int, recorded: int, already_recorded: int, unverifiable: int, unfinished: int, failed: int}
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'examined'         => $this->examined,
            'recorded'         => $this->recorded,
            'already_recorded' => $this->alreadyRecorded,
            'unverifiable'     => $this->unverifiable,
            'unfinished'       => $this->unfinished,
            'failed'           => $this->failed,
        ];
    }
}
