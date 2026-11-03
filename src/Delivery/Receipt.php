<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

/**
 * What the deliveries table holds for one destination of one record: the
 * destination, the attempts made to reach it, whether it has the record, and
 * the class of the last error it raised, if any. It holds nothing of the record
 * itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Receipt
{
    /**
     * Constructor.
     *
     * @param  string  $destination
     * @param  int  $attempts
     * @param  bool  $delivered
     * @param  ?string  $lastErrorClass
     */
    public function __construct(

        /** The destination's id: a stack's name for it, or `store` for a single store. */
        public string $destination,

        /** The attempts made to reach the destination, each counted before its call. */
        public int $attempts,

        /** Whether the destination has the record. */
        public bool $delivered,

        /** The class of the last error the destination raised, or `null` when there is none. */
        public ?string $lastErrorClass,
    ) {}
}
