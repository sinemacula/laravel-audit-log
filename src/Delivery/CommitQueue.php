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
 * Holds what the audit log must do once a transaction commits, so a record's
 * failure, or a commit that is really a rollback, cannot cost another record.
 *
 * Laravel runs commit callbacks in a plain loop, so one that throws stops every
 * callback behind it. So an outermost transaction gets one flush, registered
 * the first time the audit log uses that transaction, and every deferred write
 * and bound spill of the transaction and of those nested in it runs inside it:
 * one record's failure stops no other, and an application callback registered
 * after that first use cannot stop them. A nested transaction's work joins the
 * flush only when that transaction commits, so its rollback still drops the
 * work. An application callback that throws and was registered before the first
 * use, or on a nested transaction, still stops the flush, because nothing can
 * reach ahead of it.
 *
 * PostgreSQL ends an aborted transaction with a rollback while reporting the
 * commit a success, so Laravel then runs the commit callbacks for work that was
 * undone. So just before an outermost commit on PostgreSQL with work waiting on
 * it, one statement, `select 1`, asks whether the transaction is still alive.
 * When it answers SQLSTATE `25P02` the flush writes nothing, and only reports.
 * With no work waiting, no statement is added, and no other engine has this
 * state.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CommitQueue
{
    /** @var string The driver of the one engine whose commit of an aborted transaction reports a success. */
    private const string ABORTING_DRIVER = 'pgsql';

    /** @var \WeakMap<\Illuminate\Database\DatabaseTransactionRecord, \SineMacula\Laravel\AuditLog\Delivery\CommitFlush> The flush of each outermost transaction the audit log has used; it goes with its transaction. */
    private \WeakMap $flushes;

    /** @var list<array{connection: string, level: int, work: \Closure(): void}> Work whose transaction rolled back, run once that rollback has finished. */
    private array $rolledBack = [];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the current transactions manager is read from. */
        private readonly Container $container,
    ) {
        $this->flushes = new \WeakMap;
    }

    /**
     * Hold the flush's place among the commit callbacks of the transaction's
     * outermost, so whatever is deferred later runs ahead of any application
     * callback registered from here on.
     *
     * @param  \Illuminate\Database\DatabaseTransactionRecord  $transaction
     * @return void
     */
    public function reserve(DatabaseTransactionRecord $transaction): void
    {
        $this->flushOf($this->outermostOf($transaction));
    }

    /**
     * Run the work when the transaction, and every one around it on its
     * connection, has committed, and never when one of them rolls back; if the
     * commit proves to be a rollback, the abandon step runs instead, when there
     * is one.
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
     * Run one of the steps when the transaction's outermost ends: the commit
     * step when it commits, and the rollback step when it rolls back or its
     * commit proves to be a rollback. A rollback inside it changes nothing. The
     * rollback step waits for Laravel's rollback event, since the manager still
     * lists the rolled-back transactions while its callbacks run; a rollback
     * without that event leaves it for the next one on the connection.
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
     * Just before an outermost commit, ask a PostgreSQL connection with work
     * waiting whether its transaction was already aborted, and doom the flush
     * if so. Any other failure of the question is the commit's to raise.
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
     * The flush with work waiting on the connection's open transaction, or
     * `null` when there is none.
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
     * The flush of the outermost transaction, registered as its commit callback
     * on first use.
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
     * The outermost transaction around this one whose commit callbacks run: a
     * transaction the testing manager wraps a test in does not count.
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
     * The current transactions manager, read on every call, because the testing
     * transaction traits swap one in later; `null` when there is none.
     *
     * @return ?\Illuminate\Database\DatabaseTransactionsManager
     */
    private function manager(): ?DatabaseTransactionsManager
    {
        return $this->container->bound('db.transactions') ? $this->container->make('db.transactions') : null;
    }
}
