<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;

/**
 * Selects the transaction an after-commit record waits for: its work runs at
 * once when none applies, otherwise when the selected transaction's outermost
 * commit completes, and never when that transaction is rolled back, a rollback
 * to a savepoint included.
 *
 * With no connection named it selects the innermost pending transaction on any
 * connection; with one, that connection's innermost, and a transaction on
 * another connection neither delays nor cancels the work. A transaction the
 * testing manager wraps a test in is never selected, because that manager
 * leaves it out of the transactions callbacks apply to, and a connection's
 * transaction level is never what decides, because that manager runs callbacks
 * at level 1 where Laravel's own runs them at 0. What waits on the selected
 * transaction is the commit queue's to hold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AfterCommit
{
    /**
     * Constructor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(): mixed  $transactions
     */
    public function __construct(

        /** Returns the current transactions manager, if any, when called. */
        #[\SensitiveParameter]
        private \Closure $transactions,
    ) {}

    /**
     * The transaction work on the connection would wait for: that connection's
     * innermost pending transaction, the innermost on any connection with no
     * name, and `null` with no manager or none to select.
     *
     * The manager is resolved on every call, as Laravel's event dispatcher
     * does, so a manager swapped in later (by the testing transaction traits,
     * which ignore their own wrapping transaction) is the one consulted.
     *
     * @param  ?string  $connection
     * @return ?\Illuminate\Database\DatabaseTransactionRecord
     */
    public function selected(?string $connection): ?DatabaseTransactionRecord
    {
        $manager = ($this->transactions)();

        if (!$manager instanceof DatabaseTransactionsManager) {
            return null;
        }

        $selects = static fn (DatabaseTransactionRecord $transaction): bool => $connection === null || $transaction->connection === $connection;

        return $manager->callbackApplicableTransactions()->last($selects);
    }
}
