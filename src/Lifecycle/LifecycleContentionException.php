<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * Thrown when every attempt at a lifecycle operation was lost to concurrent
 * operations: each met a deadlock, a serialisation failure, a lock wait timeout
 * or a locked database, and was rolled back whole, so nothing it attempted was
 * committed and the operation may be asked for again.
 *
 * Its message names the number of attempts alone, and the package never gives
 * it another exception, so nothing it holds can reach a row.
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
