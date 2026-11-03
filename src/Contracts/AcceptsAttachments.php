<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

/**
 * Attachment store contract: an audit store that says whether it keeps a
 * record's attachment, the manifest of the subjects a bulk operation touched,
 * with the record's entry.
 *
 * A store that keeps attachments stores each with its entry atomically: both
 * are kept or neither is, so an entry never points at a manifest that is not
 * there. A store that does not implement this contract, or says `false`, is
 * never handed an attachment, and a bulk operation is refused while it is
 * bound, so a manifest is never silently lost. An implementation must answer
 * from its own configuration, never from the record, and must keep no state
 * between calls.
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
