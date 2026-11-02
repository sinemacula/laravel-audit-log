<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\AfterCommit;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;

/**
 * Delivers one captured record according to its timing: finalises it once,
 * stores it, then says so with `AuditRecorded`.
 *
 * It is made from the current container for each capture, and a deferred write
 * holds it only until its transaction ends, so it keeps no request's objects
 * beyond that. The finaliser and the store are resolved when the write happens,
 * so a record is stamped when it is written, and a store bound after the record
 * was captured is the one used.
 *
 * A failed write propagates to whoever runs it, the code that commits when it
 * was deferred, and notifies nothing. The notification sits outside the write:
 * a listener's failure is reported and goes no further, and a failed report is
 * dropped, so neither causes another write nor stops a later after-commit
 * callback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordDelivery
{
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
     * Refuse a timing that cannot be honoured, before anything is consumed: an
     * after-commit record naming a connection that does not exist, and a
     * transactional record that does not name the storage connection or has no
     * transaction open on it. An immediate record has nothing to check.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $connection
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function check(Timing $timing, ?string $connection): void
    {
        if ($timing === Timing::TRANSACTIONAL) {
            $this->checkTransactional($connection);
        }

        if ($timing !== Timing::AFTER_COMMIT || $connection === null) {
            return;
        }

        $this->connections->connection($connection);
    }

    /**
     * Deliver the record: an after-commit record once the selected transaction
     * commits, or now when there is none, and any other now. A connection named
     * with a read or write selector is the connection it selects.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Timing  $timing
     * @param  ?string  $connection
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \SineMacula\Laravel\AuditLog\Stores\RecordConflictException
     */
    public function deliver(AuditRecord $record, Timing $timing, ?string $connection): void
    {
        if ($timing !== Timing::AFTER_COMMIT) {

            $this->write($record);

            return;
        }

        $container = $this->container;

        (new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null))
            ->run($this->transactionNameOf($connection), function () use ($record): void {
                $this->write($record);
            });
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
     * Refuse a transactional record that does not name the storage connection,
     * since another connection needs the outbox, or that has no transaction
     * open on it. The transaction may be a test's wrapping one.
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

        $resolved = $this->connections->connection($storage);

        if (!$resolved instanceof Connection || $resolved->transactionLevel() < 1) {
            throw new \LogicException(sprintf('A transactional record needs a transaction open on the storage connection [%s].', $storage));
        }
    }

    /**
     * Finalise the record, once, store it, then notify. Nothing is caught, so a
     * failure propagates and notifies nothing.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     * @throws \SineMacula\Laravel\AuditLog\Stores\RecordConflictException
     */
    private function write(AuditRecord $record): void
    {
        $finalised = $this->container->make(RecordFinaliser::class)->finalise($record);

        $this->container->make(AuditStore::class)->store($finalised);

        $this->notify($record);
    }

    /**
     * Say the store accepted the record. A listener's failure is reported, not
     * propagated: the record is already stored, so it must not look like a
     * failed write.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return void
     */
    private function notify(AuditRecord $record): void
    {
        try {
            $this->container->make(Dispatcher::class)->dispatch(new AuditRecorded($record->id, $record->event, $record->category));
        } catch (\Throwable $exception) {
            $this->report($exception);
        }
    }

    /**
     * Report a listener's failure. A reporter that fails too is ignored: there
     * is nowhere left to say so, and the record is already stored.
     *
     * @param  \Throwable  $exception
     * @return void
     */
    private function report(\Throwable $exception): void
    {
        try {
            $this->container->make(ExceptionHandler::class)->report($exception);
        } catch (\Throwable) {
            // The record is stored; a broken reporter must not undo that for
            // the caller, or stop a later after-commit callback
        }
    }
}
