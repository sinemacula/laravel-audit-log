<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records\Enums;

/**
 * What an artifact holds, as its row and its record's signed descriptor store
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum ArtifactKind: string
{
    // The subjects a bulk operation affected, each once
    case BULK = 'bulk';

    // What a read of the trail disclosed: its filters, scope and entries
    case DISCLOSURE = 'disclosure';

    // The manifest of an export of the trail
    case EXPORT = 'export';

    /**
     * Whether an artifact of the kind may count no member.
     *
     * @return bool
     */
    public function allowsEmpty(): bool
    {
        return match ($this) {
            self::BULK => false,
            default    => true,
        };
    }
}
