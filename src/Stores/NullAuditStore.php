<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * An audit store that keeps nothing, for turning the log off in one
 * environment; never durable, so a fail-closed record needs the outbox.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NullAuditStore implements AcceptsAttachments, DurableAuditStore
{
    /**
     * Succeed without writing the record anywhere.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return void
     */
    #[\Override]
    public function store(#[\SensitiveParameter] FinalisedRecord $record): void
    {
        // A null store keeps nothing, by design
    }

    /**
     * Whether a return is durable: never, since nothing is kept.
     *
     * @return bool
     */
    #[\Override]
    public function isDurable(): bool
    {
        return false;
    }

    /**
     * Whether a write joins a transaction on the connection: never.
     *
     * @param  string  $connection
     * @return bool
     */
    #[\Override]
    public function participatesIn(string $connection): bool
    {
        return false;
    }

    /**
     * Whether the store keeps attachments: yes, since it loses every record
     * alike.
     *
     * @return bool
     */
    #[\Override]
    public function acceptsAttachments(): bool
    {
        return true;
    }
}
