<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

/**
 * Durable audit store contract: what a return from `store()` means, so delivery
 * can refuse a guarantee it cannot give.
 *
 * A fail-closed record needs a durable store and a transactional one a store
 * participating on its connection, unless the outbox acknowledges for them. An
 * implementation answers from its own configuration and keeps no state.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface DurableAuditStore extends AuditStore
{
    /**
     * Whether a return from `store()` is a durable acknowledgement that the
     * record is kept.
     *
     * @return bool
     */
    public function isDurable(): bool;

    /**
     * Whether a write commits and rolls back with a transaction open on the
     * connection, named as `config/database.php` names it.
     *
     * @param  string  $connection
     * @return bool
     */
    public function participatesIn(string $connection): bool;
}
