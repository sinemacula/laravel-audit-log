<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Definitions\Enums;

/**
 * How a field rule handles the value at its path before a record is stored.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FieldHandling: string
{
    // The value is kept as captured
    case RETAIN = 'retain';

    // The value is stored as `[REDACTED]`
    case REDACT = 'redact';

    // The value is stored as a keyed, fingerprinted hash
    case PSEUDONYMISE = 'pseudonymise';

    // The value is stored encrypted under its owner's key
    case ENCRYPT = 'encrypt';

    // The value is not stored
    case DROP = 'drop';

    /**
     * Whether a rule with this handling decides its whole branch, so a rule
     * beneath it could never apply.
     *
     * @return bool
     */
    public function isTerminal(): bool
    {
        return match ($this) {
            self::RETAIN => false,
            default      => true,
        };
    }
}
