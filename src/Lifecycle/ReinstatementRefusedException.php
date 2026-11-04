<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * Thrown when a reinstatement names an owner whose latest marker, read under
 * the lifecycle and owner locks, does not record an erasure: an owner never
 * erased, and one already reinstated. The reinstatement is refused and nothing
 * is written.
 *
 * It carries the reason, `not_erased`, which the activity record of the refusal
 * names, and its message names neither the owner nor anything that could link
 * it to one; the package never gives it another exception.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ReinstatementRefusedException extends \RuntimeException
{
    /** @var string Why an owner whose latest marker records no erasure is refused. */
    public const string NOT_ERASED = 'not_erased';

    /**
     * Constructor.
     *
     * @param  string  $reason
     * @param  string  $message
     */
    private function __construct(

        /** Why the reinstatement was refused: `not_erased`. */
        public readonly string $reason,

        // What the refusal says, naming no owner.
        string $message,
    ) {
        parent::__construct($message);
    }

    /**
     * The owner's latest marker records no erasure, so there is nothing to
     * reinstate.
     *
     * @return self
     */
    public static function notErased(): self
    {
        return new self(self::NOT_ERASED, 'The owner is not erased; only an owner whose latest marker records an erasure is reinstated.');
    }
}
