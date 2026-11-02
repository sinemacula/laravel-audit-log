<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Models;

/**
 * Thrown when code tries to write an audit entry through the model: an entry is
 * evidence, written once by the store and never changed or removed through
 * Eloquent.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ImmutableEntryException extends \LogicException
{
    /**
     * The exception for a write through the named model method.
     *
     * @param  string  $method
     * @return self
     */
    public static function refusing(string $method): self
    {
        return new self(sprintf('Audit entries are append-only: `%s()` cannot write an entry; the store writes entries, and the database\'s grants keep them unchanged.', $method));
    }
}
