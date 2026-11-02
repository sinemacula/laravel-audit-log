<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;

/**
 * Defers work until a transaction commits: at once when no transaction applies,
 * otherwise when the selected transaction's outermost commit completes, and
 * never when that transaction is rolled back, a rollback to a savepoint
 * included.
 *
 * With no connection named it selects the innermost pending transaction on any
 * connection; with one, that connection's innermost, and a transaction on
 * another connection neither delays nor cancels the work. A transaction the
 * testing manager wraps a test in is never selected, because that manager
 * leaves it out of the transactions callbacks apply to. An exception from the
 * work reaches whoever runs it: the caller, or the code that commits.
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
        private \Closure $transactions,
    ) {}

    /**
     * Run the callback once the selected transaction commits, or now when there
     * is none.
     *
     * The manager is resolved on every call, as Laravel's event dispatcher
     * does, so a manager swapped in later (by the testing transaction traits,
     * which ignore their own wrapping transaction) is the one consulted. The
     * callback is attached to the selected record itself, so a rollback of that
     * transaction drops it whichever connection is transacting.
     *
     * @param  ?string  $connection
     * @param  \Closure(): void  $callback
     * @return void
     */
    public function run(?string $connection, \Closure $callback): void
    {
        $manager = ($this->transactions)();
        $selects = static fn (DatabaseTransactionRecord $transaction): bool => $connection === null || $transaction->connection === $connection;
        $pending = $manager instanceof DatabaseTransactionsManager ? $manager->callbackApplicableTransactions()->last($selects) : null;

        if ($pending === null) {

            $callback();

            return;
        }

        $pending->addCallback($callback);
    }
}
