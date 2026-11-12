<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * Thrown when every attempt at one seal was lost to concurrent writers and
 * rolled back; the next run tries again.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SealContentionException extends \RuntimeException
{
    /** @var string The message format, taking the number of attempts. */
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
