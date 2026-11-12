<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

/**
 * A drain's claim on one outbox row; its token fences every later change, so a
 * claim that lost the row changes nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OutboxClaim
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $token
     * @param  string  $payload
     * @param  int  $attempts
     */
    public function __construct(

        /** The row's id, which is its record's id. */
        public string $id,

        /** The token every later change to the row requires. */
        #[\SensitiveParameter]
        public string $token,

        /** The record's envelope, encrypted. */
        #[\SensitiveParameter]
        public string $payload,

        /** The attempts counted on the row, this claim's included. */
        public int $attempts,
    ) {}
}
