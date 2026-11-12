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
 * Delivers one captured record by its timing and the delivery mode: in sync
 * mode it finalises, stores and dispatches `AuditRecorded`, and in outbox mode
 * it hands the record to the outbox writer.
 *
 * The failure and delivery modes are read before anything is deferred, so a
 * malformed one is refused at the capture, never thrown from a commit callback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordDelivery
{
    /** @var string Why a strict record made inside the write guard is refused. */
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

        /** Resolves connection names without opening a connection. */
        private ConnectionResolverInterface $connections,
    ) {}

    /**
     * Refuse what cannot be honoured before anything is consumed: a strict
     * capture, a malformed mode, a strict record inside the write guard, a
     * transactional record without its transaction, a store that cannot keep a
     * strict record's guarantee, or an unknown after-commit connection.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $connection
     * @param  bool  $failClosed
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @return void
     *
     * @throws \LogicException
     */
    public function check(Timing $timing, ?string $connection, bool $failClosed = false, #[\SensitiveParameter] ?CaptureSignal $capture = null): void
    {
        self::refuseAStrictCapture($timing, $failClosed, $capture);

        if ($capture === null) {
            $this->container->make(FailureSettings::class)->mode();
        }

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
     * now. Inside the write guard a strict record is refused and any other left
     * unwritten.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $connection
     * @param  bool  $failClosed
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\PackageWrite  $package
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    public function deliver(
        #[\SensitiveParameter] AuditRecord $record,
        Timing $timing,
        ?string $connection,
        bool $failClosed = false,
        #[\SensitiveParameter] ?CaptureSignal $capture = null,
        #[\SensitiveParameter] ?PackageWrite $package = null,
    ): void {
        self::refuseAStrictCapture($timing, $failClosed, $capture);
        self::refuseALoosePackageWrite($timing, $failClosed, $capture, $package);

        $guard = $this->container->make(WriteGuard::class);

        if ($guard->isActive()) {

            $this->refuse($guard, $record, $failClosed || $timing === Timing::TRANSACTIONAL);

            return;
        }

        $rule = $capture === null ? FailureRule::for($timing, $failClosed, $this->container->make(FailureSettings::class)->mode()) : FailureRule::REPORT;

        if ($this->container->make(DeliverySettings::class)->mode() === DeliveryMode::OUTBOX) {

            (new OutboxWriter($this->container, $this->container->make(Outbox::class)))->write($record, $timing, $this->transactionNameOf($connection), $rule, $capture, $package);

            return;
        }

        if ($timing === Timing::AFTER_COMMIT) {
            $this->writeAfterCommit($record, $rule, $this->transactions()->selected($this->transactionNameOf($connection)), $capture);
        } elseif ($timing === Timing::AFTER_TRANSACTION) {
            $this->writeAfterTransaction($record, $rule, $capture);
        } else {
            $this->write($record, $rule, false, $capture, $package);
        }
    }

    /**
     * Refuse a fail-closed or transactional capture, which the `REPORT` rule a
     * capture follows cannot honour.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  bool  $failClosed
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @return void
     *
     * @throws \LogicException
     */
    private static function refuseAStrictCapture(Timing $timing, bool $failClosed, #[\SensitiveParameter] ?CaptureSignal $capture): void
    {
        if ($capture !== null && ($failClosed || $timing === Timing::TRANSACTIONAL)) {
            throw new \LogicException('A captured record is written immediately or after commit, never fail-closed or transactional.');
        }
    }

    /**
     * Refuse a package write that is not immediate and fail-closed, or comes
     * with a capture's signal, since nothing else can hold the read until
     * acknowledged.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  bool  $failClosed
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\PackageWrite  $package
     * @return void
     *
     * @throws \LogicException
     */
    private static function refuseALoosePackageWrite(
        Timing $timing,
        bool $failClosed,
        #[\SensitiveParameter] ?CaptureSignal $capture,
        #[\SensitiveParameter] ?PackageWrite $package,
    ): void {
        if ($package === null || ($timing === Timing::IMMEDIATE && $failClosed && $capture === null)) {
            return;
        }

        throw new \LogicException('A package write is delivered immediately and fail-closed.');
    }

    /**
     * Write the record when the selected transaction commits, unless the commit
     * proves a rollback, or now when there is none.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  ?\Illuminate\Database\DatabaseTransactionRecord  $selected
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function writeAfterCommit(
        #[\SensitiveParameter] AuditRecord $record,
        FailureRule $rule,
        ?DatabaseTransactionRecord $selected,
        #[\SensitiveParameter] ?CaptureSignal $capture,
    ): void {
        if ($selected === null) {

            $this->write($record, $rule, true, $capture);

            return;
        }

        $sealed = new \SensitiveParameterValue($record);

        $capture?->defer();

        $this->container->make(CommitQueue::class)->defer(
            $selected,
            function () use ($sealed, $rule, $capture): void {
                $this->writeSealed($sealed, $rule, $capture);
            },
            function (#[\SensitiveParameter] \Throwable $aborted) use ($sealed): void {
                $this->abandonSealed($sealed, $aborted);
            },
        );
    }

    /**
     * Write the record once the outermost storage transaction ends, under its
     * rule on commit and contained on rollback, or now when none is open.
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
    private function writeAfterTransaction(#[\SensitiveParameter] AuditRecord $record, FailureRule $rule, #[\SensitiveParameter] ?CaptureSignal $capture): void
    {
        $connection = $this->storageConnection();

        // A selector's other instance under this name cannot hold the write
        $selected = $connection === null || $connection->transactionLevel() === 0
            ? null
            : $this->transactions()->selected($connection->getName() ?? StorageConnection::resolvedName());

        if ($selected === null) {

            $this->write($record, $rule, false, $capture);

            return;
        }

        $sealed = new \SensitiveParameterValue($record);

        $capture?->defer();

        $this->container->make(CommitQueue::class)->deferToEnd(
            $selected,
            function () use ($sealed, $rule, $capture): void {
                $this->writeSealed($sealed, $rule, $capture);
            },
            function () use ($sealed, $capture): void {
                $this->writeRolledBack($sealed, $capture);
            },
        );
    }

    /**
     * The name a transaction on the named connection is known by: a transaction
     * records the connection's own name, never a selector such as
     * `reporting::write`.
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
     * In sync mode, refuse a transactional record not on the storage
     * connection, or with no transaction open there; a test's wrapping
     * transaction counts.
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
     * In outbox mode, refuse a transactional record not on the outbox
     * connection, or with no transaction open there.
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
     * In sync mode, refuse a fail-closed record whose store is not durable, and
     * a transactional record whose store does not join the storage transaction.
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
     * Leave a record made inside the write guard unwritten: refuse a strict
     * one, and report any other once per window.
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
            // A broken reporter must not fail the code that recorded or add to
            // the failure being handled
        }
    }

    /**
     * Write the record a commit callback holds sealed, so a failure's trace
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
    private function writeSealed(\SensitiveParameterValue $sealed, FailureRule $rule, #[\SensitiveParameter] ?CaptureSignal $capture): void
    {
        /** @var \SineMacula\Laravel\AuditLog\Records\AuditRecord $record */
        $record = $sealed->getValue();

        if ($capture === null) {

            $this->write($record, $rule, true);

            return;
        }

        try {
            $this->write($record, $rule, true, $capture);
        } catch (\Throwable $failure) {
            (new FailureHandler($this->container))->contain($record, $failure, FailedOperation::STORE, AuditStore::class, $capture);
        }
    }

    /**
     * Write a sealed record past a rollback under `REPORT`, letting nothing
     * out, so the host's own exception is not masked.
     *
     * @param  \SensitiveParameterValue  $sealed
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @return void
     */
    private function writeRolledBack(\SensitiveParameterValue $sealed, #[\SensitiveParameter] ?CaptureSignal $capture): void
    {
        /** @var \SineMacula\Laravel\AuditLog\Records\AuditRecord $record */
        $record = $sealed->getValue();

        try {
            $this->write($record, FailureRule::REPORT, false, $capture);
        } catch (\Throwable $failure) {
            $handler = new FailureHandler($this->container);

            $capture === null
                ? $handler->abandon($record, $failure, FailedOperation::STORE, AuditStore::class)
                : $handler->contain($record, $failure, FailedOperation::STORE, AuditStore::class, $capture);
        }
    }

    /**
     * Report a sealed record whose commit proved a rollback, so it is not
     * written.
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
     * hand the failure to the failure handler, which notifies nothing. A
     * package write is acknowledged once stored, before the notification.
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
    private function write(
        #[\SensitiveParameter] AuditRecord $record,
        FailureRule $rule,
        bool $afterCommit,
        #[\SensitiveParameter] ?CaptureSignal $capture = null,
        #[\SensitiveParameter] ?PackageWrite $package = null,
    ): void {
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

            if ($record->attachment !== null) {
                (new StoreCapabilities($this->container))->assertAcceptsAttachments();
            }

            $this->container->make(WriteGuard::class)->during(static function () use ($store, $finalised): void {
                $store->store($finalised);
            });
        } catch (\Throwable $failure) {
            $operation = $finalised === null ? FailedOperation::FINALISE : FailedOperation::STORE;
            $class     = $store     === null ? AuditStore::class : get_debug_type($store);
            $failed    = new FailedWrite($record, $finalised, $failure, $operation, $class, $name, $hostOpen, $open);

            (new FailureHandler($this->container))->handle($failed, $rule, $commitBound, $capture);

            return;
        }

        $package?->acknowledge($finalised);

        (new RecordedNotifier($this->container))->notify($record->id, $record->event, $record->category, $open);
    }

    /**
     * The storage connection, or `null` when it is not a database connection or
     * cannot be resolved; the store then fails inside its attempt.
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
