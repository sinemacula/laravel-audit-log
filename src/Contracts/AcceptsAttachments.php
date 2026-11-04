<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

/**
 * Attachment store contract: an audit store that says whether it keeps a
 * record's attachment, a bulk operation's subjects, a read's disclosure or an
 * export's manifest, with the record's entry.
 *
 * A store that keeps attachments stores each with its entry atomically: both
 * are kept or neither is, so an entry never points at an artifact that is not
 * there. Every read of the trail, a page, a count, an export or the
 * verification of an export, is recorded with a `disclosure` or an `export`
 * attachment, so the store the trail is read through must keep them. A store
 * that does not implement this contract, or says `false`, is never handed an
 * attachment: a bulk operation is refused while it is bound, and in sync mode
 * every read of the trail is refused with `AuditReadRefusedException` before
 * anything is queried, so an artifact is never silently lost. An implementation
 * must answer from its own configuration, never from the record, and must keep
 * no state between calls.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AcceptsAttachments extends AuditStore
{
    /**
     * Whether the store keeps a record's attachment with its entry, both or
     * neither.
     *
     * @return bool
     */
    public function acceptsAttachments(): bool;
}
