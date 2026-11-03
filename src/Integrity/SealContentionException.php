<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * Thrown when every attempt at one seal was lost to concurrent writers: each
 * met a duplicate seal or member, a deadlock, a serialisation failure, a lock
 * wait timeout or a locked database, and was rolled back whole. Nothing of the
 * attempts remains, and the next run tries again.
 *
 * Its message names the number of attempts alone, and the package never gives
 * it another exception, so nothing it holds can reach an entry.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SealContentionException extends \RuntimeException
{
    /** @var string The message, by the number of attempts it names. */
    private const string MESSAGE = 'Sealing gave up after %d attempts lost to concurrent writers; the next run tries again.';

    /**
     * The exception for a seal whose every attempt was lost.
     *
     * @param  int  $attempts
     * @return self
     */
    public static function after(int $attempts): self
    {
        return new self(sprintf(self::MESSAGE, $attempts));
    }
}
