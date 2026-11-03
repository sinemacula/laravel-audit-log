<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * Reported when a seal run stops before it ends, in sealing or in anchoring, so
 * a scheduled run whose output nobody reads still raises it.
 *
 * Its message names the class of what stopped the run alone, and it never
 * carries another exception, so no message, statement or binding of the
 * failure, and nothing of an entry, can reach a reporter.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SealFailedException extends \RuntimeException
{
    /** @var string The message, by the class it names. */
    private const string MESSAGE = 'Sealing stopped with %s.';

    /**
     * The exception for a run stopped by a failure of the class.
     *
     * @param  string  $class
     * @return self
     */
    public static function stoppedBy(string $class): self
    {
        return new self(sprintf(self::MESSAGE, $class));
    }
}
