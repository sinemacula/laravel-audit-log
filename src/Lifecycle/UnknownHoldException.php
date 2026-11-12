<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * Thrown when a release names a hold the verified journal does not hold active;
 * nothing is written.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnknownHoldException extends \RuntimeException
{
    /**
     * The hold is not active.
     *
     * @param  string  $holdId
     * @return self
     */
    public static function for(string $holdId): self
    {
        return new self(sprintf('The hold `%s` is not active; only an active hold is released.', $holdId));
    }
}
