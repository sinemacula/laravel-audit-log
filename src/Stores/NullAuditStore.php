<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * An audit store that keeps nothing: every call succeeds and writes nowhere.
 *
 * It is for an application that turns the audit log off in one environment
 * while its code goes on recording. It is never durable and joins no
 * transaction, so a fail-closed or a transactional record bound to it is
 * refused unless the outbox acknowledges for it, rather than being told it was
 * kept.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NullAuditStore implements DurableAuditStore
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
     * Whether a return is a durable acknowledgement: never, since nothing is
     * kept.
     *
     * @return bool
     */
    #[\Override]
    public function isDurable(): bool
    {
        return false;
    }

    /**
     * Whether a write joins a transaction on the connection: never, since there
     * is no write.
     *
     * @param  string  $connection
     * @return bool
     */
    #[\Override]
    public function participatesIn(string $connection): bool
    {
        return false;
    }
}
