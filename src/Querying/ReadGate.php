<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\DatabaseTransactionsManager;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\OpenTransactions;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\DeliverySettings;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Delivery\StoreCapabilities;
use SineMacula\Laravel\AuditLog\Runtime\ReadGuard;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;

/**
 * The gate every read of the trail passes before anything is queried: a count,
 * a page, an export and the verification of an export alike. It refuses, with
 * `AuditReadRefusedException`, what could not end in a durable record of the
 * read, so nothing is disclosed that the trail might never hold.
 *
 * A read is refused when it is entered inside the read guard, the write guard,
 * which also covers a failed write being handled, or an event mapper, where its
 * record would be refused only after the query. The first refusal in a read or
 * a write window is reported, so a recursion refused many times is diagnosed
 * once, and a mapper's refusal is reported through the report latch; a reporter
 * that fails is ignored, and the read is refused all the same.
 *
 * In sync mode a read is refused when the bound store does not say a return is
 * durable, or keeps no attachment, since every read record carries one and
 * would otherwise fail only after the query. The failure mode is never read,
 * since a read's record is fail-closed whatever it says; a malformed delivery
 * mode is refused as it is read.
 *
 * A read is refused, too, while a transaction is open that the framework would
 * not yet call committed, on the storage connection, which the read uses, so a
 * page never shows a row its caller's own transaction could still roll back,
 * or, in outbox mode, on the outbox connection, whose committed row is the
 * read's acknowledgement. The framework's own rule judges it: the transactions
 * manager's `afterCommitCallbacksShouldBeExecuted()` at the connection's level,
 * so the base transaction Laravel's testing manager wraps a test in counts as
 * committed, and any transaction counts as open where no manager is bound. In
 * sync mode the same rule judges every other connection with a transaction open
 * that the bound store says it joins, since such a store's write is durable
 * only once that transaction commits. The same rule runs again just before the
 * read's record is written, and once more before its acknowledgement is
 * accepted, since the policy that authorised the read and the contributors its
 * record runs are the application's code and may have opened one.
 *
 * The gate queries nothing, and opens no connection: it resolves everything
 * from the container on every call, so it outlives requests safely.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReadGate
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     */
    public function __construct(

        /** The container the guards, the settings, the store, the transactions manager and the reporter are resolved from on every call. */
        private Container $container,

        /** Resolves connection names, without opening a connection. */
        private ConnectionResolverInterface $connections,
    ) {}

    /**
     * Let a read in, or refuse it before anything is queried: inside a read or
     * a write window or an event mapper, with a store that cannot keep its
     * record in sync mode, and with a transaction open that could still roll
     * its record back.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    public function enter(): void
    {
        $this->refuseReentry();

        $mode = $this->container->make(DeliverySettings::class)->mode();

        if ($mode === DeliveryMode::SYNC) {
            $this->refuseAStoreThatCannotKeepIt();
        }

        $this->confirmDurableUnder($mode);
    }

    /**
     * Refuse a read while a transaction is open, on the storage connection, in
     * outbox mode on the outbox connection, and in sync mode on any connection
     * the bound store says it joins, that the framework would not yet call
     * committed. It is the check made before a read's record is written and
     * before its acknowledgement is accepted.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    public function confirmDurable(): void
    {
        $this->confirmDurableUnder($this->container->make(DeliverySettings::class)->mode());
    }

    /**
     * Run the work inside the read guard's window and return what it returns,
     * closing the window however the work ends.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $work
     * @return TResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     *
     * @param-immediately-invoked-callable $work
     */
    public function window(#[\SensitiveParameter] \Closure $work): mixed
    {
        return $this->container->make(ReadGuard::class)->during($work);
    }

    /**
     * Refuse a read inside a read window, a write window or an event mapper,
     * reporting the first refusal in a window and a mapper's through the report
     * latch.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function refuseReentry(): void
    {
        $reads  = $this->container->make(ReadGuard::class);
        $writes = $this->container->make(WriteGuard::class);

        if ($reads->isActive()) {
            $this->refuse($reads->isFirstRefusal());
        }

        if ($writes->isActive()) {
            $this->refuse($writes->isFirstRefusal());
        }

        if (!$this->container->make(CapturedEvents::class)->isMapping()) {
            return;
        }

        $refusal = AuditReadRefusedException::reentrant();

        $this->container->make(ReportLatch::class)->once(function () use ($refusal): void {
            $this->report($refusal);
        });

        throw $refusal;
    }

    /**
     * Refuse a re-entered read, reporting it first when it is the window's
     * first refusal.
     *
     * @param  bool  $first
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function refuse(bool $first): never
    {
        $refusal = AuditReadRefusedException::reentrant();

        if ($first) {
            $this->report($refusal);
        }

        throw $refusal;
    }

    /**
     * Report the refusal, ignoring a reporter that fails.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException  $refusal
     * @return void
     */
    private function report(AuditReadRefusedException $refusal): void
    {
        try {
            $this->container->make(ExceptionHandler::class)->report($refusal);
        } catch (\Throwable) {
            // The read is refused all the same; a broken reporter has nowhere
            // left to say so, and must not replace the refusal
        }
    }

    /**
     * Refuse, in sync mode, a store that does not say a return is durable or
     * that keeps no attachment, naming its class.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function refuseAStoreThatCannotKeepIt(): void
    {
        $capabilities = new StoreCapabilities($this->container);

        if (!$capabilities->isDurable()) {
            throw AuditReadRefusedException::notDurable($capabilities->storeClass());
        }

        if (!$capabilities->acceptsAttachments()) {
            throw AuditReadRefusedException::keepsNoArtifacts($capabilities->storeClass());
        }
    }

    /**
     * Refuse a read while the storage connection, in outbox mode the outbox
     * connection, or in sync mode a connection the bound store joins, holds a
     * transaction the framework would not yet call committed, naming that
     * connection.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function confirmDurableUnder(DeliveryMode $mode): void
    {
        foreach ($this->acknowledgingConnections($mode) as $name) {
            if ($this->holdsAnUncommittedTransaction($name)) {
                throw AuditReadRefusedException::inTransaction($name);
            }
        }
    }

    /**
     * The connections a read's record could be rolled back with: the storage
     * connection, which the read reads, and, in outbox mode, the outbox
     * connection, or, in sync mode, each connection with a transaction open
     * that the bound store says it joins.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return non-empty-list<string>
     */
    private function acknowledgingConnections(DeliveryMode $mode): array
    {
        $storage = StorageConnection::resolvedName();

        if ($mode === DeliveryMode::OUTBOX) {
            return [$storage, DeliveryTables::resolvedOutboxConnection()];
        }

        $capabilities = new StoreCapabilities($this->container);
        $open         = (new OpenTransactions($this->connections))->names();
        $joined       = array_filter($open, static fn (string $name): bool => $name !== $storage && $capabilities->participatesIn($name));

        return [$storage, ...array_values($joined)];
    }

    /**
     * Whether the named connection is a database connection with a transaction
     * open that the framework would not yet call committed: no transactions
     * manager is bound, or the bound one would not yet run the callbacks of a
     * commit at the connection's level.
     *
     * @param  string  $name
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function holdsAnUncommittedTransaction(string $name): bool
    {
        $connection = $this->connections->connection($name);

        if (!$connection instanceof Connection || $connection->transactionLevel() < 1) {
            return false;
        }

        $manager = $this->container->bound('db.transactions') ? $this->container->make('db.transactions') : null;

        return !$manager instanceof DatabaseTransactionsManager || !$manager->afterCommitCallbacksShouldBeExecuted($connection->transactionLevel());
    }
}
