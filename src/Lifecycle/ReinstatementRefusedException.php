<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

/**
 * Thrown when a reinstatement names an owner whose latest marker records no
 * erasure; nothing is written.
 *
 * Its message names nothing that could link it to the owner.
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

        // Passed to the parent, not kept
        string $message,
    ) {
        parent::__construct($message);
    }

    /**
     * The owner's latest marker records no erasure.
     *
     * @return self
     */
    public static function notErased(): self
    {
        return new self(self::NOT_ERASED, 'The owner is not erased; only an owner whose latest marker records an erasure is reinstated.');
    }
}
