<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * Thrown when a row names an integrity key the ring does not hold, so its
 * signature can be neither confirmed nor denied: the row is unverifiable, never
 * reported as tampered, until the key is configured again.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnknownKeyException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $message
     * @param  string  $keyId
     */
    public function __construct(

        // What is wrong.
        string $message,

        /** The id of the key the ring does not hold. */
        public readonly string $keyId,
    ) {
        parent::__construct($message);
    }

    /**
     * The exception for a key id the ring does not hold.
     *
     * @param  string  $keyId
     * @return self
     */
    public static function forKey(string $keyId): self
    {
        return new self(sprintf('The integrity key [%s] is not in the key ring; its rows cannot be verified until it is configured again.', $keyId), $keyId);
    }
}
