<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;

/**
 * Selects the transaction an after-commit record waits for, never the one the
 * testing manager wraps a test in, which runs callbacks at level 1, not 0.
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
     * The innermost pending transaction on the connection, or on any when none
     * is named; the manager is resolved per call, so a swapped one is used.
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
