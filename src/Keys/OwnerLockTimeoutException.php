<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

/**
 * Thrown when an owner's lock was not granted within its wait; whatever waited
 * rolled back, and the message names the wait alone, never the owner.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class OwnerLockTimeoutException extends \RuntimeException
{
    /** @var string The message, by the wait it names, in seconds. */
    private const string MESSAGE = 'An owner\'s lock was not granted within %d seconds; nothing that waited for it was committed.';

    /**
     * The exception for a lock not granted within the wait, in seconds.
     *
     * @param  int  $seconds
     * @return self
     */
    public static function after(int $seconds): self
    {
        return new self(sprintf(self::MESSAGE, $seconds));
    }
}
