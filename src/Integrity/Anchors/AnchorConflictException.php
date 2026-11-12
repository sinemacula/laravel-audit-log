<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Anchors;

/**
 * Thrown when an anchor already holds another digest for a seal's sequence, so
 * the log or the anchor was altered. Its message names only the sequence.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AnchorConflictException extends \RuntimeException
{
    /** @var string The message format, taking the sequence. */
    private const string MESSAGE = 'The anchor already holds another digest for seal %d; the local log or the anchor has been altered.';

    /**
     * Constructor.
     *
     * @param  int  $sequence
     */
    private function __construct(

        /** The sequence the anchor holds another digest for. */
        public readonly int $sequence,
    ) {
        parent::__construct(sprintf(self::MESSAGE, $sequence));
    }

    /**
     * The exception for a sequence the anchor holds another digest for.
     *
     * @param  int  $sequence
     * @return self
     */
    public static function forSequence(int $sequence): self
    {
        return new self($sequence);
    }
}
