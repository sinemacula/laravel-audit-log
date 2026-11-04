<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

/**
 * Thrown when a key row names a wrapping key the ring does not hold, so its
 * data key can be neither unwrapped nor its wrapping confirmed: the fields
 * sealed under it read as unreadable, and verification reports the key as
 * unverifiable, never as substituted, until the wrapping key is configured
 * again. The message names the key's id and nothing else.
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
