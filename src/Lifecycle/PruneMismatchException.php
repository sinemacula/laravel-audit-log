<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * Thrown when a prune delete affected another number of rows than it named; the
 * chunk rolls back and is retried once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PruneMismatchException extends \RuntimeException
{
    /** @var string The message, by the ids a delete named and the rows it affected. */
    private const string MESSAGE = 'A prune chunk deleted %2$d entries where it named %1$d; the chunk was rolled back.';

    /**
     * The exception for a delete that named and affected the counts given.
     *
     * @param  int  $named
     * @param  int  $affected
     * @return self
     */
    public static function of(int $named, int $affected): self
    {
        return new self(sprintf(self::MESSAGE, $named, $affected));
    }
}
