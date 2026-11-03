<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Contracts;

/**
 * Durable audit store contract: an audit store that says what a return from
 * `store()` means, so the delivery can tell a guarantee it may give from one it
 * must refuse.
 *
 * Durability means that a return is a durable acknowledgement: the record is
 * kept once `store()` returns, and a process that dies a moment later loses
 * nothing. Participation means that the write commits and rolls back with a
 * transaction open on the connection named, so the record exists exactly when
 * the business change it describes does. The two are separate: a durable remote
 * store cannot be atomic with local data, and a store that joins a transaction
 * is durable only once that transaction commits. A fail-closed record needs a
 * durable store, and a transactional record a store that participates on its
 * connection, unless the outbox acknowledges for them. A store without this
 * contract counts as neither. An implementation must answer from its own
 * configuration, never from the record, and must keep no state between calls.
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
