<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * What one verification run read of the lifecycle journal: its rows, its head
 * and the sequence the latest seal commits to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class JournalSummary
{
    /**
     * Constructor.
     *
     * @param  int  $rowsRead
     * @param  ?int  $head
     * @param  ?int  $committed
     */
    public function __construct(

        /** The journal rows the run read, malformed ones included. */
        public int $rowsRead,

        /** The sequence of the chain's head, its last good row, or `null` when there is none. */
        public ?int $head,

        /** The sequence the latest seal commits to, or `null` when there is no seal or it commits to none. */
        public ?int $committed,
    ) {}

    /**
     * The summary as the journal's part of the run's summary.
     *
     * @return array{rows: int, head: ?int, committed: ?int}
     */
    public function toArray(): array
    {
        return [
            'rows'      => $this->rowsRead,
            'head'      => $this->head,
            'committed' => $this->committed,
        ];
    }
}
