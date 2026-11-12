<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Enums;

/**
 * Where an owner's key stands, as its row stores it. An erased key never holds
 * a key again: a reinstated owner is given a new generation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum KeyState: string
{
    // The key is wrapped, and encrypts and decrypts
    case LIVE = 'live';

    // The key is wrapped, and only decrypts what it encrypted before
    case SUPERSEDED = 'superseded';

    // The key was destroyed by an erasure, and holds no wrapped key
    case ERASED = 'erased';

    /**
     * Whether a key in the state still holds its wrapped key.
     *
     * @return bool
     */
    public function holdsAKey(): bool
    {
        return match ($this) {
            self::LIVE,
            self::SUPERSEDED => true,
            default          => false,
        };
    }

    /**
     * Whether a key in the state encrypts a new field.
     *
     * @return bool
     */
    public function encrypts(): bool
    {
        return $this === self::LIVE;
    }
}
