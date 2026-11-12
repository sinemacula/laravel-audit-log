<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

/**
 * Reported when a seal run stops early, so a scheduled run nobody watches still
 * raises it. Its message names only the failure's class, never SQL or an entry.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SealFailedException extends \RuntimeException
{
    /**
     * The exception for a run stopped by a failure of the class.
     *
     * @param  string  $class
     * @return self
     */
    public static function stoppedBy(string $class): self
    {
        return new self(sprintf('Sealing stopped with %s.', $class));
    }
}
