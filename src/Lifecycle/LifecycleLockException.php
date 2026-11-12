<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * Thrown when the lifecycle lock row is missing or the maintenance connection
 * is not at `read committed`; never retried.
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
     * The maintenance connection's transactions are not at `read committed`.
     *
     * @param  string  $level
     * @return self
     */
    public static function isolation(string $level): self
    {
        return new self(sprintf('The maintenance connection\'s transactions are `%s`; a lifecycle operation needs `read committed`.', $level));
    }
}
