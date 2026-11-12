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
 * The gate every read passes before anything is queried, refusing what could
 * not end in a durable record of the read.
 *
 * An open transaction is judged as Laravel judges after-commit callbacks, so
 * the testing manager's base transaction counts as committed.
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

        /** Resolved from on every call, so the gate outlives requests safely. */
        private Container $container,

        /** Resolves connection names, without opening a connection. */
        private ConnectionResolverInterface $connections,
    ) {}

    /**
     * Let a read in, or refuse it before anything is queried.
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
     * Refuse a read while a transaction that could roll its record back is
     * open; rechecked around the write, as the policy and contributors may open
     * one.
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
     * Run the work inside the read guard's window.
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
     * Refuse a read inside a read or write window or an event mapper, reporting
     * a recursion once.
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
     * Refuse a re-entered read, reporting the window's first refusal.
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
            // A broken reporter must not replace the refusal
        }
    }

    /**
     * Refuse a store that is not durable or keeps no attachment, so the read
     * does not fail only after the query.
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
     * Refuse a read while an acknowledging connection holds an uncommitted
     * transaction.
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
     * The storage connection, plus the outbox connection, or in sync mode each
     * open connection the store joins.
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
     * Whether the connection has a transaction open that Laravel would not yet
     * call committed; any counts where no transactions manager is bound.
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
