<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

/**
 * Thrown when a key row names a wrapping key the ring does not hold; its fields
 * read as unreadable until that key is configured again.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnknownWrappingKeyException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  string  $keyId
     */
    public function __construct(

        /** The id of the wrapping key the ring does not hold; never a secret. */
        public readonly string $keyId,
    ) {
        parent::__construct(sprintf('The wrapping key [%s] is not in the wrapping ring; the keys it wrapped cannot be unwrapped until it is configured again.', $keyId));
    }

    /**
     * The exception for a wrapping key id the ring does not hold.
     *
     * @param  string  $keyId
     * @return self
     */
    public static function forKey(string $keyId): self
    {
        return new self($keyId);
    }
}
