<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture\Enums;

/**
 * What became of a watched model, as the last segment of the code its record is
 * stored under: the model's own segment, then the change.
 *
 * Four of the changes are Eloquent events the watch listens to. A restore is
 * none of them: it is told from the update that clears a soft-deleted model's
 * deleted-at column, so the restore event is never listened to.
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
     * The code a change of the model watched as the segment is stored under:
     * the segment, a dot, then this change.
     *
     * @param  string  $as
     * @return string
     */
    public function codeFor(string $as): string
    {
        return $as . '.' . $this->value;
    }

    /**
     * The Eloquent event the change is listened for by, as the model events
     * name it, or `null` for a restore, which is told from an update.
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
