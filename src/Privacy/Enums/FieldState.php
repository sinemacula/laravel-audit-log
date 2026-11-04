<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy\Enums;

/**
 * Why an encrypted fragment of an entry is shown as a marker rather than as its
 * value: it is still sealed under its owner's key, its owner's keys have been
 * destroyed, or it could not be read at all.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FieldState: string
{
    // Sealed under its owner's key, which the field reader does not open
    case ENCRYPTED = 'encrypted';

    // Sealed under keys its owner's erasure destroyed, so it can never be read
    case ERASED = 'erased';

    // Malformed, or its field reader failed
    case UNREADABLE = 'unreadable';

    /**
     * The marker an entry shows in the fragment's place: `[ENCRYPTED]`,
     * `[ERASED]` or `[UNREADABLE]`.
     *
     * @return string
     */
    public function marker(): string
    {
        return match ($this) {
            self::ENCRYPTED  => '[ENCRYPTED]',
            self::ERASED     => '[ERASED]',
            self::UNREADABLE => '[UNREADABLE]',
        };
    }
}
