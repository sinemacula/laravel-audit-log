<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

/**
 * Thrown when a page cursor is refused, with the same message whatever the
 * cause so a caller learns nothing of why, not even whether a key exists.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidCursorException extends \InvalidArgumentException
{
    /**
     * The refusal of a cursor, whatever the cause.
     *
     * @return self
     */
    public static function refused(): self
    {
        return new self('The cursor was refused.');
    }
}
