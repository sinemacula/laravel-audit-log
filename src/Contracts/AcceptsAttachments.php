<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

/**
 * Attachment store contract: whether a store keeps a record's attachment, such
 * as a bulk operation's subjects, a read's disclosure or an export's manifest,
 * with its entry.
 *
 * An implementation keeps each attachment and its entry atomically, answers
 * from its own configuration, and keeps no state between calls.
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
