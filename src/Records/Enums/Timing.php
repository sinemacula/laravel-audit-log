<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records\Enums;

/**
 * When a record is written relative to the database transaction around it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum Timing: string
{
    // Deferred to the transaction's outermost commit, dropped on its rollback
    case AFTER_COMMIT = 'after_commit';

    // Written now, in a savepoint if the storage connection has a transaction
    case IMMEDIATE = 'immediate';

    // Written inside the open transaction on the connection, atomic with it
    case TRANSACTIONAL = 'transactional';

    // Deferred to the outermost transaction's commit or rollback
    case AFTER_TRANSACTION = 'after_transaction';
}
