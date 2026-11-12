<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Database\Events\TransactionRolledBack;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;

/**
 * Runs audit work at commit, so one record's failure, or a commit that is
 * really a rollback, cannot cost another record.
 *
 * Laravel stops running commit callbacks at the first that throws, so each
 * outermost transaction gets one flush that all its audit work runs inside.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CommitQueue
{
    /** @var string The one driver whose commit of an aborted transaction reports success. */
    private const string ABORTING_DRIVER = 'pgsql';

    /** @var \WeakMap<\Illuminate\Database\DatabaseTransactionRecord, \SineMacula\Laravel\AuditLog\Delivery\CommitFlush> The flush of each outermost transaction used, dropped with it. */
    private \WeakMap $flushes;

    /** @var list<array{connection: string, level: int, work: \Closure(): void}> Work whose transaction rolled back, run once the rollback finishes. */
    private array $rolledBack = [];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Where the current transactions manager is read from. */
        private readonly Container $container,
    ) {
        $this->flushes = new \WeakMap;
    }

    /**
     * Register the outermost transaction's flush now, so later audit work runs
     * ahead of application callbacks registered after this.
     *
     * @param  \Illuminate\Database\DatabaseTransactionRecord  $transaction
     * @return void
     */
    public function reserve(DatabaseTransactionRecord $transaction): void
    {
        $this->flushOf($this->outermostOf($transaction));
    }

    /**
     * Run the work once the transaction and every one around it commit, never
     * on a rollback; the abandon step runs if the commit proves a rollback.
     *
     * @param  \Illuminate\Database\DatabaseTransactionRecord  $transaction
     * @param  \Closure(): void  $work
     * @param  ?\Closure(\Throwable): void  $abandon
     * @return void
     */
    public function defer(DatabaseTransactionRecord $transaction, #[\SensitiveParameter] \Closure $work, #[\SensitiveParameter] ?\Closure $abandon = null): void
    {
        $outermost = $this->outermostOf($transaction);
        $flush     = $this->flushOf($outermost);

        $flush->expect();

        if ($transaction === $outermost) {
            $flush->add($work, $abandon);

            return;
        }

        $transaction->addCallback(static function () use ($flush, $work, $abandon): void {
            $flush->add($work, $abandon);
        });
    }

    /**
     * Run the commit step when the outermost transaction commits, and the
     * rollback step after Laravel's rollback event, since the manager still
     * lists the transactions while rollback callbacks run.
     *
     * @param  \Illuminate\Database\DatabaseTransactionRecord  $transaction
     * @param  \Closure(): void  $onCommit
     * @param  \Closure(): void  $onRollback
     * @return void
     */
    public function deferToEnd(DatabaseTransactionRecord $transaction, #[\SensitiveParameter] \Closure $onCommit, #[\SensitiveParameter] \Closure $onRollback): void
    {
        $outermost = $this->outermostOf($transaction);
        $flush     = $this->flushOf($outermost);

        $flush->expect();
        $flush->add($onCommit, $onRollback);

        $outermost->addCallbackForRollback(function () use ($outermost, $onRollback): void {
            $this->rolledBack[] = ['connection' => $outermost->connection, 'level' => $outermost->level - 1, 'work' => $onRollback];
        });
    }

    /**
     * Once a rollback has finished, run the work waiting on every transaction
     * it ended on that connection.
     *
     * @param  \Illuminate\Database\Events\TransactionRolledBack  $event
     * @return void
     */
    public function release(#[\SensitiveParameter] TransactionRolledBack $event): void
    {
        $name    = $event->connection->getName();
        $level   = $event->connection->transactionLevel();
        $ready   = [];
        $waiting = [];

        foreach ($this->rolledBack as $entry) {
            if ($entry['connection'] === $name && $level <= $entry['level']) {
                $ready[] = $entry['work'];

                continue;
            }

            $waiting[] = $entry;
        }

        $this->rolledBack = $waiting;

        foreach ($ready as $work) {
            $work();
        }
    }

    /**
     * PostgreSQL commits an aborted transaction as a rollback yet reports
     * success, so before an outermost commit with work waiting, ask with
     * `select 1` and doom the flush on SQLSTATE `25P02`.
     *
     * @param  \Illuminate\Database\Events\TransactionCommitting  $event
     * @return void
     */
    public function probe(#[\SensitiveParameter] TransactionCommitting $event): void
    {
        $connection = $event->connection;
        $flush      = $this->waitingFlushOf($connection);

        if ($flush === null || $connection->getDriverName() !== self::ABORTING_DRIVER) {
            return;
        }

        try {
            $connection->scalar('select 1', [], false);
        } catch (\Throwable $exception) {
            if ((new FailureClassifier)->isAbortedHost($exception)) {
                $flush->doom($exception);
            }
        }
    }

    /**
     * The flush waiting on the connection's open transaction, or `null`.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return ?\SineMacula\Laravel\AuditLog\Delivery\CommitFlush
     */
    private function waitingFlushOf(Connection $connection): ?CommitFlush
    {
        $manager = $this->manager();

        if ($manager === null) {
            return null;
        }

        foreach ($manager->callbackApplicableTransactions() as $transaction) {
            $flush = $this->flushes[$transaction] ?? null;

            if ($flush !== null && $transaction->connection === $connection->getName() && $flush->isExpecting()) {
                return $flush;
            }
        }

        return null;
    }

    /**
     * The outermost transaction's flush, registered as its commit callback on
     * first use.
     *
     * @param  \Illuminate\Database\DatabaseTransactionRecord  $outermost
     * @return \SineMacula\Laravel\AuditLog\Delivery\CommitFlush
     */
    private function flushOf(DatabaseTransactionRecord $outermost): CommitFlush
    {
        if (isset($this->flushes[$outermost])) {
            return $this->flushes[$outermost];
        }

        $flush = new CommitFlush($this->container);

        $outermost->addCallback($flush->run(...));

        return $this->flushes[$outermost] = $flush;
    }

    /**
     * The outermost transaction whose commit callbacks run, skipping a testing
     * wrapper.
     *
     * @param  \Illuminate\Database\DatabaseTransactionRecord  $transaction
     * @return \Illuminate\Database\DatabaseTransactionRecord
     */
    private function outermostOf(DatabaseTransactionRecord $transaction): DatabaseTransactionRecord
    {
        $applicable = $this->manager()?->callbackApplicableTransactions();
        $outermost  = $transaction;

        while ($outermost->parent !== null && $applicable?->contains($outermost->parent) === true) {
            $outermost = $outermost->parent;
        }

        return $outermost;
    }

    /**
     * The current transactions manager, read each call since the testing traits
     * swap one in later.
     *
     * @return ?\Illuminate\Database\DatabaseTransactionsManager
     */
    private function manager(): ?DatabaseTransactionsManager
    {
        return $this->container->bound('db.transactions') ? $this->container->make('db.transactions') : null;
    }
}
