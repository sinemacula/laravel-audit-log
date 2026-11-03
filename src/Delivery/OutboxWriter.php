<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\DatabaseTransactionRecord;
use SineMacula\Laravel\AuditLog\Database\AfterCommit;
use SineMacula\Laravel\AuditLog\Database\OpenTransactions;
use SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;

/**
 * Writes a captured record to the outbox, finalised once and encrypted as a
 * string, for a drain to deliver: never to a store, and with no
 * `AuditRecorded`, since the drain dispatches that.
 *
 * An after-commit record whose selected transaction is on the outbox connection
 * is inserted now, inside that transaction, so the row exists exactly when the
 * transaction commits and the gap between a commit and its write is closed. One
 * whose selected transaction is on another connection is inserted when that
 * transaction commits, in the commit queue so its failure stops no other
 * record, and is never inserted when it rolls back or when its commit proves to
 * be a rollback; the gap between that commit and the insert remains. Every
 * other record is inserted now. The selection is the one `AfterCommit` makes,
 * so a testing wrapper is never selected, and it holds only while the outbox
 * connection really has a transaction open: a host transaction on another
 * instance of that connection, as one name with a read or write selector gives,
 * cannot hold the row.
 *
 * A failed insert leaves a healthy transaction as it was, and follows the
 * record's failure rule: the diagnostics go out at once, and an after-commit
 * record's spill never precedes a commit it depends on. While a transaction
 * selected on the outbox connection holds the insert, the spill waits for that
 * transaction's commit and goes with its rollback, so a replay never brings
 * back a record of work that was undone. An immediate record's spill is written
 * at once, because its host may already have failed. Finalising and inserting
 * here moves their failures ahead of the host's commit.
 *
 * Whatever finalising and encrypting need is resolved inside the attempt, so a
 * malformed ring or a missing application key follows the failure rule rather
 * than escaping from a constructor. An outbox connection that cannot be
 * resolved holds no transaction, and its insert fails and follows the rule in
 * the same way.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OutboxWriter
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Outbox  $outbox
     */
    public function __construct(

        /** The container of the capture the write belongs to. */
        private Container $container,

        /** The outbox the record is inserted in. */
        private Outbox $outbox,
    ) {}

    /**
     * Write the record as its timing and the selected transaction say: inside
     * that transaction when it is on the outbox connection, at its commit when
     * it is on another, and now otherwise.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $transaction
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    public function write(#[\SensitiveParameter] AuditRecord $record, Timing $timing, ?string $transaction, FailureRule $rule): void
    {
        $afterCommit = $timing === Timing::AFTER_COMMIT;
        $selected    = $afterCommit ? $this->transactions()->selected($transaction) : null;

        if ($selected === null) {

            $this->insert($record, $rule, $afterCommit);

            return;
        }

        $queue = $this->container->make(CommitQueue::class);

        if ($this->holdsTheInsert($selected)) {

            // A spill this or a later record binds runs ahead of any
            // application callback registered from here on
            $queue->reserve($selected);

            $this->insert($record, $rule, true);

            return;
        }

        $sealed = new \SensitiveParameterValue($record);

        $queue->defer(
            $selected,
            function () use ($sealed, $rule): void {
                $this->insertSealed($sealed, $rule);
            },
            function (#[\SensitiveParameter] \Throwable $aborted) use ($sealed): void {
                $this->abandonSealed($sealed, $aborted);
            },
        );
    }

    /**
     * Insert the record a commit callback holds sealed. The commit's own frames
     * hold the transaction and the callbacks bound to it, so a failure's trace
     * would otherwise reach the record through them.
     *
     * @param  \SensitiveParameterValue  $sealed
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function insertSealed(\SensitiveParameterValue $sealed, FailureRule $rule): void
    {
        /** @var \SineMacula\Laravel\AuditLog\Records\AuditRecord $record */
        $record = $sealed->getValue();

        $this->insert($record, $rule, true);
    }

    /**
     * Report the record a commit callback holds sealed, whose commit proved to
     * be a rollback, so it is not inserted.
     *
     * @param  \SensitiveParameterValue  $sealed
     * @param  \Throwable  $aborted
     * @return void
     */
    private function abandonSealed(\SensitiveParameterValue $sealed, #[\SensitiveParameter] \Throwable $aborted): void
    {
        /** @var \SineMacula\Laravel\AuditLog\Records\AuditRecord $record */
        $record = $sealed->getValue();

        (new FailureHandler($this->container))->abandon($record, $aborted, FailedOperation::OUTBOX, get_debug_type($this->outbox));
    }

    /**
     * Finalise the record once and insert its encrypted envelope, and hand any
     * failure to the failure handler under the rule.
     *
     * Whether a transaction is open on the outbox connection, every connection
     * with one open, and which one an after-commit record's spill is bound to,
     * are read now and before the attempt: Laravel forgets an open transaction
     * when its connection is lost, and a transaction open when a deferred
     * insert runs holds its row, so it must hold its spill too.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  bool  $afterCommit
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function insert(#[\SensitiveParameter] AuditRecord $record, FailureRule $rule, bool $afterCommit): void
    {
        $connection  = $this->connectionName();
        $hostOpen    = $this->isTransacting();
        $open        = (new OpenTransactions($this->container->make(ConnectionResolverInterface::class)))->names();
        $commitBound = $afterCommit && $hostOpen ? $this->transactions()->selected($connection) : null;
        $finalised   = null;

        try {
            $finalised = $this->container->make(RecordFinaliser::class)->finalise($record);

            $this->enqueue($finalised);
        } catch (\Throwable $failure) {
            $operation = $finalised === null ? FailedOperation::FINALISE : FailedOperation::OUTBOX;
            $failed    = new FailedWrite($record, $finalised, $failure, $operation, get_debug_type($this->outbox), $connection, $hostOpen, $open);

            (new FailureHandler($this->container))->handle($failed, $rule, $commitBound);
        }
    }

    /**
     * Encode the finalised record as its envelope, encrypt it as a string and
     * insert it under the record's id, inside the write guard.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $finalised
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException
     */
    private function enqueue(#[\SensitiveParameter] FinalisedRecord $finalised): void
    {
        $envelope = $this->container->make(EnvelopeCodec::class)->encode($finalised);
        $payload  = $this->container->make(StringEncrypter::class)->encryptString($envelope);
        $id       = $finalised->record->id;

        $this->container->make(WriteGuard::class)->during(function () use ($id, $payload): void {
            $this->outbox->insert($id, $payload);
        });
    }

    /**
     * Whether an insert now would be inside the selected transaction: it is on
     * the outbox connection, by the connection's own name, and that connection
     * has a transaction open. A selector gives a second instance under the same
     * name, whose transaction the outbox's own instance cannot join.
     *
     * @param  \Illuminate\Database\DatabaseTransactionRecord  $selected
     * @return bool
     */
    private function holdsTheInsert(DatabaseTransactionRecord $selected): bool
    {
        return $selected->connection === $this->connectionName() && $this->isTransacting();
    }

    /**
     * The outbox connection's name, or `null` when it cannot be resolved, which
     * the insert then fails on and follows the rule.
     *
     * @return ?string
     */
    private function connectionName(): ?string
    {
        try {
            return $this->outbox->connectionName();
        } catch (\Throwable) {
            // The insert fails on the same setting, inside its attempt, so the
            // failure follows the rule rather than escaping from here
            return null;
        }
    }

    /**
     * Whether a transaction is open on the outbox connection, and `false` when
     * it cannot be resolved.
     *
     * @return bool
     */
    private function isTransacting(): bool
    {
        try {
            return $this->outbox->isInTransaction();
        } catch (\Throwable) {
            // The insert fails on the same setting, inside its attempt, so the
            // failure follows the rule rather than escaping from here
            return false;
        }
    }

    /**
     * The adapter that selects a transaction from the current manager.
     *
     * @return \SineMacula\Laravel\AuditLog\Database\AfterCommit
     */
    private function transactions(): AfterCommit
    {
        $container = $this->container;

        return new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null);
    }
}
