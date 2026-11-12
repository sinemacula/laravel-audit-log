<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Events;

use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;

/**
 * Dispatched when sealing or verification finds the log altered, incomplete or
 * unverifiable, or a verification stops before it can say.
 *
 * It carries ids, counts and codes only. Both maps list every status by its
 * value, zero-filled and in the same order, so sealing and verification give
 * one shape.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IntegrityCheckFailed implements AuditLogEvent
{
    /**
     * Constructor.
     *
     * @param  string  $command
     * @param  array<string, int>  $integrity
     * @param  array<string, int>  $anchoring
     * @param  ?string  $finding
     * @param  ?string  $firstBadId
     * @param  ?int  $head
     * @param  ?int  $remoteHead
     * @param  bool  $complete
     */
    public function __construct(

        /** The command that ran: `seal` or `verify`. */
        public string $command,

        /** How many segments were found in each integrity status, by its value, every status listed; a seal run's one failing condition counts once. */
        public array $integrity,

        /** How many segments were found in each anchoring status, by its value, every status listed. */
        public array $anchoring,

        /** The value of the first finding, or `null` when the run stopped before it found one. */
        public ?string $finding,

        /** The id of the first seal or entry the finding was found at, or `null` when there is none to name. */
        public ?string $firstBadId,

        /** The sequence of the local head the run observed, or `null` when the log had no seal. */
        public ?int $head,

        /** The sequence of the anchor's head, or `null` when it was not discovered or the anchor holds none. */
        public ?int $remoteHead,

        /** Whether the run covered the whole log. */
        public bool $complete,
    ) {}
}
