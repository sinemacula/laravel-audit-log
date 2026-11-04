<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * Thrown when a release names a hold the verified journal does not hold active:
 * one never placed, or one already released. The release is refused and nothing
 * is written; whether a hold is active is decided from the journal's chain,
 * never from the holds projection.
 *
 * Its message names the hold id, an opaque UUID the package minted, and no
 * other value; the package never gives it another exception.
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
