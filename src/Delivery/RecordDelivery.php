<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\DatabaseTransactionRecord;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\AfterCommit;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\OpenTransactions;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\FailureSettings;

/**
 * Delivers one captured record according to its timing and the delivery mode:
 * in sync mode it finalises the record once, stores it, then dispatches
 * `AuditRecorded`, and in outbox mode it hands the record to the outbox writer,
 * whose row a drain delivers later.
 *
 * It is made from the current container for each capture, and a deferred write
 * holds it only until its transaction ends, so it keeps no request's objects
 * beyond that. The finaliser and the store are resolved when the write happens,
 * so a record is stamped when it is written, and a store bound after the record
 * was captured is the one used. The failure and delivery modes are read once
 * before anything is deferred, so a malformed one is a refusal at the capture
 * and never an exception out of a commit callback.
 *
 * A failed write follows the failure policy: the failure handler spills,
 * reports and dispatches `AuditWriteFailed`, and throws what the record's
 * failure rule requires, to whoever runs the write, which is the code that
 * commits when it was deferred. It never notifies. A deferred write waits in
 * the commit queue, so its failure stops no other record waiting on that
 * commit, and it writes nothing when that commit proves to be a rollback. An
 * after-commit record's spill never precedes a commit it depends on, so a write
 * running while a transaction is open on the storage connection binds its spill
 * to that transaction. The notification sits outside the write: a listener's
 * failure is reported and goes no further, so it neither causes another write
 * nor stops a later after-commit callback, unless it ended a transaction open
 * on the connection it happened on.
 *
 * A record made while another is being written, or its failure handled, is not
 * written, since it would fail or be refused the same way: a fail-closed or a
 * transactional record is refused, because returning would break its guarantee,
 * and any other is reported once and returned unwritten.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordDelivery
{
    /** @var string Why a fail-closed or a transactional record made inside the write guard is refused. */
    private const string STRICT_RECORD_IN_A_WRITE = 'A fail-closed or transactional record was made while an audit record was being written or its failure handled,'
        . ' so its guarantee cannot be met.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     */
    public function __construct(

        /** The container of the capture the delivery belongs to. */
        private ContainerContract $container,

        /** Resolves connection names, without opening a connection. */
        private ConnectionResolverInterface $connections,
    ) {}

    /**
     * Refuse what cannot be honoured, before anything is consumed: a malformed
     * failure or delivery mode, a fail-closed or transactional record made
     * inside the write guard, a transactional record with no transaction to
     * join, a store that cannot give a strict record its guarantee when the
     * outbox is not acknowledging for it, and an after-commit record naming a
     * connection that does not exist.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $connection
     * @param  bool  $failClosed
     * @return void
     *
     * @throws \LogicException
     */
    public function check(Timing $timing, ?string $connection, bool $failClosed = false): void
    {
        $this->container->make(FailureSettings::class)->mode();

        $mode = $this->container->make(DeliverySettings::class)->mode();

        if (($failClosed || $timing === Timing::TRANSACTIONAL) && $this->container->make(WriteGuard::class)->isActive()) {
            throw new \LogicException(self::STRICT_RECORD_IN_A_WRITE);
        }

        if ($timing === Timing::TRANSACTIONAL) {
            $mode === DeliveryMode::OUTBOX ? $this->checkOutboxTransactional($connection) : $this->checkTransactional($connection);
        }

        if ($mode === DeliveryMode::SYNC) {
            $this->checkCapabilities($timing, $failClosed);
        }

        if ($timing !== Timing::AFTER_COMMIT || $connection === null) {
            return;
        }

        $this->connections->connection($connection);
    }

    /**
     * Deliver the record by the delivery mode: an after-commit record once the
     * selected transaction commits, or now when there is none, and any other
     * now, with a failure following the record's rule. A connection named with
     * a read or write selector is the connection it selects. Inside the write
     * guard a strict record is refused, and any other is left unwritten.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $connection
     * @param  bool  $failClosed
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    public function deliver(#[\SensitiveParameter] AuditRecord $record, Timing $timing, ?string $connection, bool $failClosed = false): void
    {
        $guard = $this->container->make(WriteGuard::class);

        if ($guard->isActive()) {

            $this->refuse($guard, $record, $failClosed || $timing === Timing::TRANSACTIONAL);

            return;
        }

        $rule = FailureRule::for($timing, $failClosed, $this->container->make(FailureSettings::class)->mode());

        if ($this->container->make(DeliverySettings::class)->mode() === DeliveryMode::OUTBOX) {

            (new OutboxWriter($this->container, $this->container->make(Outbox::class)))->write($record, $timing, $this->transactionNameOf($connection), $rule);

            return;
        }

        if ($timing !== Timing::AFTER_COMMIT) {

            $this->write($record, $rule, false);

            return;
        }

        $this->writeAfterCommit($record, $rule, $this->transactions()->selected($this->transactionNameOf($connection)));
    }

    /**
     * Write the record when the selected transaction commits, unless that
     * commit proves to be a rollback, and now when there is none.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  ?\Illuminate\Database\DatabaseTransactionRecord  $selected
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function writeAfterCommit(#[\SensitiveParameter] AuditRecord $record, FailureRule $rule, ?DatabaseTransactionRecord $selected): void
    {
        if ($selected === null) {

            $this->write($record, $rule, true);

            return;
        }

        $sealed = new \SensitiveParameterValue($record);

        $this->container->make(CommitQueue::class)->defer(
            $selected,
            function () use ($sealed, $rule): void {
                $this->writeSealed($sealed, $rule);
            },
            function (#[\SensitiveParameter] \Throwable $aborted) use ($sealed): void {
                $this->abandonSealed($sealed, $aborted);
            },
        );
    }

    /**
     * The name a transaction on the named connection is known by. A selector
     * such as `reporting::write` is a valid connection name, but a transaction
     * records the connection's own name, so comparing the selector would match
     * no transaction and write at once.
     *
     * @param  ?string  $connection
     * @return ?string
     */
    private function transactionNameOf(?string $connection): ?string
    {
        if ($connection === null) {
            return null;
        }

        $resolved = $this->connections->connection($connection);

        return ($resolved instanceof Connection ? $resolved->getName() : null) ?? $connection;
    }

    /**
     * Refuse a transactional record, in sync mode, that does not name the
     * storage connection, since another connection needs the outbox, or that
     * has no transaction open on it. The transaction may be a test's wrapping
     * one.
     *
     * @param  ?string  $connection
     * @return void
     *
     * @throws \LogicException
     */
    private function checkTransactional(?string $connection): void
    {
        $storage = StorageConnection::resolvedName();

        if ($connection !== null && $connection !== $storage) {
            $message = 'A transactional record is written on the storage connection [%s], not [%s];'
                . ' another connection needs the outbox.';

            throw new \LogicException(sprintf($message, $storage, $connection));
        }

        if (!$this->isTransacting($storage)) {
            throw new \LogicException(sprintf('A transactional record needs a transaction open on the storage connection [%s].', $storage));
        }
    }

    /**
     * Refuse a transactional record, in outbox mode, that does not name the
     * outbox connection, or that has no transaction open on it.
     *
     * @param  ?string  $connection
     * @return void
     *
     * @throws \LogicException
     */
    private function checkOutboxTransactional(?string $connection): void
    {
        $outbox = DeliveryTables::resolvedOutboxConnection();

        if ($connection !== null && $connection !== $outbox) {
            throw new \LogicException(sprintf('A transactional record is written on the outbox connection [%s], not [%s].', $outbox, $connection));
        }

        if (!$this->isTransacting($outbox)) {
            throw new \LogicException(sprintf('A transactional record needs a transaction open on the outbox connection [%s].', $outbox));
        }
    }

    /**
     * Whether the named connection is a database connection with a transaction
     * open.
     *
     * @param  string  $connection
     * @return bool
     */
    private function isTransacting(string $connection): bool
    {
        $resolved = $this->connections->connection($connection);

        return $resolved instanceof Connection && $resolved->transactionLevel() > 0;
    }

    /**
     * Refuse, in sync mode, a fail-closed record whose store does not say a
     * return is durable, and a transactional record whose store does not join
     * the transaction on the storage connection. An ordinary record asks the
     * store nothing.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  bool  $failClosed
     * @return void
     *
     * @throws \LogicException
     */
    private function checkCapabilities(Timing $timing, bool $failClosed): void
    {
        $capabilities = new StoreCapabilities($this->container);

        if ($failClosed && !$capabilities->isDurable()) {
            throw new \LogicException(sprintf('A fail-closed record needs a durable store, and %s does not say it is. Bind one, or use the outbox.', $capabilities->storeClass()));
        }

        if ($timing !== Timing::TRANSACTIONAL) {
            return;
        }

        $storage = StorageConnection::resolvedName();

        if (!$capabilities->participatesIn($storage)) {
            $message = 'A transactional record needs a store that joins the transaction on [%s], and %s does not. Bind one, or use the outbox.';

            throw new \LogicException(sprintf($message, $storage, $capabilities->storeClass()));
        }
    }

    /**
     * Leave a record made inside the write guard unwritten: a strict one is
     * refused, so it never returns unwritten even when no check came first, and
     * any other is reported, once for each window, by a report that goes no
     * further.
     *
     * @param  \SineMacula\Laravel\AuditLog\Runtime\WriteGuard  $guard
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  bool  $strict
     * @return void
     *
     * @throws \LogicException
     */
    private function refuse(WriteGuard $guard, #[\SensitiveParameter] AuditRecord $record, bool $strict): void
    {
        if ($strict) {
            throw new \LogicException(self::STRICT_RECORD_IN_A_WRITE);
        }

        if (!$guard->isFirstRefusal()) {
            return;
        }

        $message = sprintf('An audit record `%s` was made while an audit record was being written or its failure handled, so it was not written.', $record->event);

        try {
            $this->container->make(ExceptionHandler::class)->report(new \LogicException($message));
        } catch (\Throwable) {
            // A broken reporter has nowhere left to say so, and must not fail
            // the code that recorded or add to the failure being handled
        }
    }

    /**
     * Write the record a commit callback holds sealed. The commit's own frames
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
    private function writeSealed(\SensitiveParameterValue $sealed, FailureRule $rule): void
    {
        /** @var \SineMacula\Laravel\AuditLog\Records\AuditRecord $record */
        $record = $sealed->getValue();

        $this->write($record, $rule, true);
    }

    /**
     * Report the record a commit callback holds sealed, whose commit proved to
     * be a rollback, so it is not written.
     *
     * @param  \SensitiveParameterValue  $sealed
     * @param  \Throwable  $aborted
     * @return void
     */
    private function abandonSealed(\SensitiveParameterValue $sealed, #[\SensitiveParameter] \Throwable $aborted): void
    {
        /** @var \SineMacula\Laravel\AuditLog\Records\AuditRecord $record */
        $record = $sealed->getValue();

        (new FailureHandler($this->container))->abandon($record, $aborted, FailedOperation::STORE, AuditStore::class);
    }

    /**
     * Finalise the record once, store it inside the write guard and notify, or
     * hand any failure to the failure handler under the rule, which notifies
     * nothing.
     *
     * Whether a transaction is open on the storage connection, which decides
     * what the write's own failure ended, every connection with one open, which
     * decides what a listener's or a failure step's failure ended, and which
     * one an after-commit record's spill is bound to, are read before the
     * attempt: Laravel forgets an open transaction when its connection is lost,
     * and a transaction open when the write runs holds its row, so it must hold
     * its spill too.
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
    private function write(#[\SensitiveParameter] AuditRecord $record, FailureRule $rule, bool $afterCommit): void
    {
        $connection  = $this->storageConnection();
        $name        = $connection === null ? null : $connection->getName() ?? StorageConnection::resolvedName();
        $hostOpen    = $connection !== null && $connection->transactionLevel() > 0;
        $open        = (new OpenTransactions($this->connections))->names();
        $commitBound = $afterCommit && $hostOpen ? $this->transactions()->selected($name) : null;
        $finalised   = null;
        $store       = null;

        try {
            $finalised = $this->container->make(RecordFinaliser::class)->finalise($record);
            $store     = $this->container->make(AuditStore::class);

            $this->container->make(WriteGuard::class)->during(static function () use ($store, $finalised): void {
                $store->store($finalised);
            });
        } catch (\Throwable $failure) {
            $operation = $finalised === null ? FailedOperation::FINALISE : FailedOperation::STORE;
            $class     = $store     === null ? AuditStore::class : get_debug_type($store);
            $failed    = new FailedWrite($record, $finalised, $failure, $operation, $class, $name, $hostOpen, $open);

            (new FailureHandler($this->container))->handle($failed, $rule, $commitBound);

            return;
        }

        (new RecordedNotifier($this->container))->notify($record->id, $record->event, $record->category, $open);
    }

    /**
     * The storage connection, or `null` when it is not a database connection or
     * cannot be resolved, which has no transaction to read and which a store
     * writing to it then fails on inside its attempt.
     *
     * @return ?\Illuminate\Database\Connection
     */
    private function storageConnection(): ?Connection
    {
        try {
            $connection = $this->connections->connection(StorageConnection::resolvedName());
        } catch (\Throwable) {
            // The store fails on the same setting, inside its attempt, so the
            // failure follows the rule rather than escaping from here
            return null;
        }

        return $connection instanceof Connection ? $connection : null;
    }

    /**
     * The adapter that selects a transaction from the delivery's own container.
     *
     * @return \SineMacula\Laravel\AuditLog\Database\AfterCommit
     */
    private function transactions(): AfterCommit
    {
        $container = $this->container;

        return new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null);
    }
}
