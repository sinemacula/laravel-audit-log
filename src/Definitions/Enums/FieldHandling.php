<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Definitions\Enums;

/**
 * How an event definition's field rule handles the value at its path before a
 * record is stored: kept as captured, redacted, pseudonymised, encrypted for an
 * owner, or dropped.
 *
 * Every handling but `retain` is terminal (`isTerminal()`): it decides the
 * whole branch beneath its path, so a rule beneath a terminal rule could never
 * apply and a definition refuses one. Applying a handling to a payload is the
 * redaction pipeline's work, not this enum's.
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

    // The value is stored as an envelope under its owner's key, never in
    // plaintext
    case ENCRYPT = 'encrypt';

    // The value is not stored
    case DROP = 'drop';

    /**
     * Whether a rule with this handling decides its whole branch: every
     * handling but `retain` replaces or removes the value at its path, so a
     * rule beneath it could never apply.
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
