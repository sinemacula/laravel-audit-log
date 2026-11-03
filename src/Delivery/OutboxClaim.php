<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

/**
 * A drain's claim on one outbox row: the row's id, the token that fences every
 * later change to it, the encrypted payload it holds and the attempts counted
 * on it, this one included.
 *
 * The token is unique to the claim, so once the lease has passed and another
 * drain has claimed the row, nothing this claim asks for changes it. The token
 * and the payload are hidden from every stack frame.
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

        /** The id of the claimed row, which is the id of the record it holds. */
        public string $id,

        /** The token the claim wrote to the row, which every later change requires. */
        #[\SensitiveParameter]
        public string $token,

        /** The row's payload: the record's envelope, encrypted. */
        #[\SensitiveParameter]
        public string $payload,

        /** The attempts counted on the row, this claim's included. */
        public int $attempts,
    ) {}
}
