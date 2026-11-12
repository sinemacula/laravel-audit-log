<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture\Enums;

/**
 * What became of a watched model, the last segment of its record's code. A
 * restore is told from an update, so no Eloquent restore event is listened to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum ModelEvent: string
{
    // The model was inserted
    case CREATED = 'created';

    // The model was saved with changes
    case UPDATED = 'updated';

    // The model was deleted, or soft-deleted
    case DELETED = 'deleted';

    // A soft-deleted model was restored
    case RESTORED = 'restored';

    // A model was deleted for good, past its soft delete
    case FORCE_DELETED = 'force_deleted';

    /**
     * The code of this change for a model watched under the segment.
     *
     * @param  string  $as
     * @return string
     */
    public function codeFor(string $as): string
    {
        return $as . '.' . $this->value;
    }

    /**
     * The Eloquent event this change is listened for by, or `null` for a
     * restore.
     *
     * @return ?string
     */
    public function eloquentEvent(): ?string
    {
        return match ($this) {
            self::CREATED       => 'created',
            self::UPDATED       => 'updated',
            self::DELETED       => 'deleted',
            self::FORCE_DELETED => 'forceDeleted',
            self::RESTORED      => null,
        };
    }
}
