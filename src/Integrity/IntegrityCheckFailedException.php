<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Events\IntegrityCheckFailed;

/**
 * Reported beside every `IntegrityCheckFailed` event, so a failure of sealing
 * or verification reaches the application's exception reporting even when no
 * listener is registered and nobody reads the run's output.
 *
 * Its message is built from the event alone: the command, the segments in each
 * failing integrity status and each anchoring status short of anchored, the
 * first finding and the id it was found at, and the head the run observed, so a
 * strict failure on anchoring alone still says why. The id is named only when
 * it is a lower-case UUID, the only form the package writes, so an id read from
 * an altered table can never put a line break or a control character in a log.
 * A run that stopped before it could say is named by the class of what stopped
 * it. It never carries another exception and holds no value of an entry.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class IntegrityCheckFailedException extends \RuntimeException
{
    /** @var string The message of a failed check, by the command, the counts, the finding, its id and the head. */
    private const string FAILED = 'The audit log\'s integrity check failed (%s): %d tampered, %d incomplete, %d unverifiable;'
        . ' %d unanchored, %d unavailable, %d contradicted; first finding %s at %s; head %s.';

    /** @var string The message of a run that stopped, by the command and the class. */
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
