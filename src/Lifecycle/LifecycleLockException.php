<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * Thrown when a lifecycle operation cannot take the lifecycle lock as the
 * protocol needs it: the lock's one row is missing, so its update would lock
 * nothing, or the maintenance connection's transactions do not run at `read
 * committed`, so a read after the lock could miss a row committed while it
 * waited. The operation is rolled back and never retried.
 *
 * Its message names no statement and no value of a row, and the package never
 * gives it another exception.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class LifecycleLockException extends \RuntimeException
{
    /**
     * The lock's one row is missing.
     *
     * @return self
     */
    public static function missing(): self
    {
        return new self('The lifecycle lock row is missing; run the migrations, which seed it.');
    }

    /**
     * The maintenance connection's transactions run at another isolation level
     * than `read committed`.
     *
     * @param  string  $level
     * @return self
     */
    public static function isolation(string $level): self
    {
        return new self(sprintf('The maintenance connection\'s transactions are `%s`; a lifecycle operation needs `read committed`.', $level));
    }
}
