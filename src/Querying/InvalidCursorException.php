<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

/**
 * Thrown when a cursor given to a read of the trail is refused: malformed,
 * signed under a key the ring does not hold, tampered with, or issued for
 * another viewer, purpose, scope, set of filters or page size.
 *
 * Its message is the same whatever the cause, so a refusal tells a caller
 * nothing of why: neither which part failed nor whether a key exists. It never
 * carries another exception.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidCursorException extends \InvalidArgumentException
{
    /** @var string The one message, whatever the cause. */
    private const string MESSAGE = 'The cursor was refused.';

    /**
     * The refusal of a cursor, whatever the cause.
     *
     * @return self
     */
    public static function refused(): self
    {
        return new self(self::MESSAGE);
    }
}
