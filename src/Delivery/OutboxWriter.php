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
 * Writes a captured record to the outbox, finalised once and encrypted, for a
 * drain to deliver; the drain dispatches `AuditRecorded`.
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
     * Insert the record inside the selected transaction when it is on the
     * outbox connection, at its commit when it is on another, and now
     * otherwise. A package write is acknowledged once the insert returns.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $transaction
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\PackageWrite  $package
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    public function write(
        #[\SensitiveParameter] AuditRecord $record,
        Timing $timing,
        ?string $transaction,
        FailureRule $rule,
        #[\SensitiveParameter] ?CaptureSignal $capture = null,
        #[\SensitiveParameter] ?PackageWrite $package = null,
    ): void {
        if ($timing === Timing::AFTER_TRANSACTION) {

            $this->insertAfterTransaction($record, $rule, $capture);

            return;
        }

        $afterCommit = $timing === Timing::AFTER_COMMIT;
        $selected    = $afterCommit ? $this->transactions()->selected($transaction) : null;

        if ($selected === null) {

            $this->insert($record, $rule, $afterCommit, $capture, $package);

            return;
        }

        $queue = $this->container->make(CommitQueue::class);

        if ($this->holdsTheInsert($selected)) {

            // Spills bound from here run ahead of later application callbacks
            $queue->reserve($selected);

            $this->insert($record, $rule, true, $capture);

            return;
        }

        $sealed = new \SensitiveParameterValue($record);

        $capture?->defer();

        $queue->defer(
            $selected,
            function () use ($sealed, $rule, $capture): void {
                $this->insertSealed($sealed, $rule, $capture);
            },
            function (#[\SensitiveParameter] \Throwable $aborted) use ($sealed): void {
                $this->abandonSealed($sealed, $aborted);
            },
        );
    }

    /**
     * Insert the record once the outermost transaction holding the insert ends,
     * under its rule on commit and contained on rollback, or now when none
     * holds it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function insertAfterTransaction(#[\SensitiveParameter] AuditRecord $record, FailureRule $rule, #[\SensitiveParameter] ?CaptureSignal $capture): void
    {
        $connection = $this->connectionName();
        $selected   = $connection === null ? null : $this->transactions()->selected($connection);

        if ($selected === null || !$this->holdsTheInsert($selected)) {

            $this->insert($record, $rule, false, $capture);

            return;
        }

        $sealed = new \SensitiveParameterValue($record);

        $capture?->defer();

        $this->container->make(CommitQueue::class)->deferToEnd(
            $selected,
            function () use ($sealed, $rule, $capture): void {
                $this->insertSealed($sealed, $rule, $capture);
            },
            function () use ($sealed, $capture): void {
                $this->insertRolledBack($sealed, $capture);
            },
        );
    }

    /**
     * Insert a sealed record past a rollback under `REPORT`, letting nothing
     * out, so the host's own exception is not masked.
     *
     * @param  \SensitiveParameterValue  $sealed
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @return void
     */
    private function insertRolledBack(\SensitiveParameterValue $sealed, #[\SensitiveParameter] ?CaptureSignal $capture): void
    {
        /** @var \SineMacula\Laravel\AuditLog\Records\AuditRecord $record */
        $record = $sealed->getValue();
        $store  = get_debug_type($this->outbox);

        try {
            $this->insert($record, FailureRule::REPORT, false, $capture);
        } catch (\Throwable $failure) {
            $handler = new FailureHandler($this->container);

            $capture === null
                ? $handler->abandon($record, $failure, FailedOperation::OUTBOX, $store)
                : $handler->contain($record, $failure, FailedOperation::OUTBOX, $store, $capture);
        }
    }

    /**
     * Insert the record a commit callback holds sealed, so a failure's trace
     * cannot reach it through the commit's frames. A capture's failure is
     * contained, letting nothing out into the commit.
     *
     * @param  \SensitiveParameterValue  $sealed
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function insertSealed(\SensitiveParameterValue $sealed, FailureRule $rule, #[\SensitiveParameter] ?CaptureSignal $capture): void
    {
        /** @var \SineMacula\Laravel\AuditLog\Records\AuditRecord $record */
        $record = $sealed->getValue();

        if ($capture === null) {

            $this->insert($record, $rule, true);

            return;
        }

        try {
            $this->insert($record, $rule, true, $capture);
        } catch (\Throwable $failure) {
            (new FailureHandler($this->container))->contain($record, $failure, FailedOperation::OUTBOX, get_debug_type($this->outbox), $capture);
        }
    }

    /**
     * Report a sealed record whose commit proved a rollback, so it is not
     * inserted.
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
     * Finalise the record once and insert its encrypted envelope, or hand the
     * failure to the failure handler. A package write is acknowledged once the
     * insert returns, which is a committed row since a read refuses an open
     * outbox transaction.
     *
     * Open transactions are read before the attempt, because Laravel forgets an
     * open transaction when its connection is lost.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  bool  $afterCommit
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\PackageWrite  $package
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function insert(
        #[\SensitiveParameter] AuditRecord $record,
        FailureRule $rule,
        bool $afterCommit,
        #[\SensitiveParameter] ?CaptureSignal $capture = null,
        #[\SensitiveParameter] ?PackageWrite $package = null,
    ): void {
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

            (new FailureHandler($this->container))->handle($failed, $rule, $commitBound, $capture);

            return;
        }

        $package?->acknowledge($finalised);
    }

    /**
     * Encode, encrypt and insert the finalised record under its id, inside the
     * write guard.
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
     * Whether an insert now would join the selected transaction: same
     * connection name with a transaction open, since a selector's second
     * instance cannot join it.
     *
     * @param  \Illuminate\Database\DatabaseTransactionRecord  $selected
     * @return bool
     */
    private function holdsTheInsert(DatabaseTransactionRecord $selected): bool
    {
        return $selected->connection === $this->connectionName() && $this->isTransacting();
    }

    /**
     * The outbox connection's name, or `null` when it cannot be resolved.
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
     * Whether a transaction is open on the outbox connection; `false` when it
     * cannot be resolved.
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
