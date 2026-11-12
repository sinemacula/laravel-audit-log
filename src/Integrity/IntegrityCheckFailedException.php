<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;

/**
 * Reported beside every `IntegrityCheckFailed` event, so a failed seal or
 * verification reaches exception reporting even with no listener. An id is
 * named only when it is a lower-case UUID, so an altered table cannot put a
 * control character in a log.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class IntegrityCheckFailedException extends \RuntimeException
{
    /** @var string The message of a failed check. */
    private const string FAILED = 'The audit log\'s integrity check failed (%s): %d tampered, %d incomplete, %d unverifiable;'
        . ' %d unanchored, %d unavailable, %d contradicted; first finding %s at %s; head %s.';

    /** @var string The message of a run that stopped. */
    private const string STOPPED = 'The audit log\'s %s run stopped with %s; its integrity was not established.';

    /** @var string How a part the event does not hold is written. */
    private const string NONE = 'none';

    /**
     * The exception for the failure the event describes.
     *
     * @param  \SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed  $event
     * @return self
     */
    public static function of(IntegrityCheckFailed $event): self
    {
        return new self(sprintf(
            self::FAILED,
            $event->command,
            $event->integrity['tampered']      ?? 0,
            $event->integrity['incomplete']    ?? 0,
            $event->integrity['unverifiable']  ?? 0,
            $event->anchoring['unanchored']    ?? 0,
            $event->anchoring['unavailable']   ?? 0,
            $event->anchoring['contradicted']  ?? 0,
            $event->finding                    ?? self::NONE,
            self::nameable($event->firstBadId) ?? self::NONE,
            $event->head                       ?? self::NONE,
        ));
    }

    /**
     * The exception for a run of the command that stopped with a failure of the
     * class before its integrity was established.
     *
     * @param  string  $command
     * @param  string  $class
     * @return self
     */
    public static function stopped(string $command, string $class): self
    {
        return new self(sprintf(self::STOPPED, $command, $class));
    }

    /**
     * The id when it is a lower-case UUID, and `null` otherwise.
     *
     * @param  ?string  $id
     * @return ?string
     */
    private static function nameable(?string $id): ?string
    {
        return $id !== null && preg_match(SealEnvelope::UUID_PATTERN, $id) === 1 ? $id : null;
    }
}
