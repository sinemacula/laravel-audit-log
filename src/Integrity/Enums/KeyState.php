<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity\Enums;

/**
 * Where an owner's key stands, as its row stores it: it encrypts and decrypts,
 * it only decrypts what it encrypted before it was superseded, or it was erased
 * and holds no key at all.
 *
 * A key moves from `live` to `superseded` when its generation is rotated, and
 * from either to `erased` when its owner is erased. An erased key never holds a
 * key again: a reinstated owner is given a new generation, never an old one
 * back.
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
     * Whether a key in the state still holds its wrapped key: a live and a
     * superseded one do, and an erased one never does.
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
     * Whether a key in the state encrypts a new field: only a live one does.
     *
     * @return bool
     */
    public function encrypts(): bool
    {
        return $this === self::LIVE;
    }
}
