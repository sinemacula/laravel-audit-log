<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * Thrown when every attempt at a lifecycle operation was lost to concurrent
 * ones; nothing was committed, so it may be retried.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class LifecycleContentionException extends \RuntimeException
{
    /** @var string The message, by the number of attempts it names. */
    private const string MESSAGE = 'A lifecycle operation lost to concurrent operations %d times and was abandoned; nothing it attempted was committed.';

    /**
     * The exception for an operation whose every attempt was lost.
     *
     * @param  int  $attempts
     * @return self
     */
    public static function after(int $attempts): self
    {
        return new self(sprintf(self::MESSAGE, $attempts));
    }
}
