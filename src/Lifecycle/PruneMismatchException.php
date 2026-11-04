<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * Thrown inside a prune chunk's transaction when a delete of entries affected
 * another number of rows than the ids it named, which rolls the whole chunk
 * back: something deleted or restored an entry between the chunk's read and its
 * delete, so a record of what it deleted could not be trusted. The pruner
 * retries the chunk once from a fresh read, then skips the seal for the run.
 *
 * It names only the two counts, never an id.
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
     * The exception for a delete that named the ids given and affected the rows
     * given.
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
