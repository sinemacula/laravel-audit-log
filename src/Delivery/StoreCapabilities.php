<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;

/**
 * What the bound audit store says of itself: whether a return is durable,
 * whether a write joins a transaction on a connection, and its class.
 *
 * The store is resolved from the container on every call, so a store bound
 * later is the one read, and nothing is kept between calls. A store that does
 * not implement `Contracts\DurableAuditStore` is neither durable nor joins any
 * transaction. Reading through this class is the only way the package outside
 * the delivery reaches the store, so only the delivery writes to it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StoreCapabilities
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the store is resolved from on every call. */
        private Container $container,
    ) {}

    /**
     * Whether the bound store says a return is a durable acknowledgement.
     *
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function isDurable(): bool
    {
        $store = $this->store();

        return $store instanceof DurableAuditStore && $store->isDurable();
    }

    /**
     * Whether the bound store says a write joins a transaction on the
     * connection.
     *
     * @param  string  $connection
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function participatesIn(string $connection): bool
    {
        $store = $this->store();

        return $store instanceof DurableAuditStore && $store->participatesIn($connection);
    }

    /**
     * The bound store's class, as `get_debug_type()` names it, so an anonymous
     * store names no file path.
     *
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function storeClass(): string
    {
        return get_debug_type($this->store());
    }

    /**
     * The store the container binds now.
     *
     * @return \SineMacula\Laravel\AuditLog\Contracts\AuditStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function store(): AuditStore
    {
        return $this->container->make(AuditStore::class);
    }
}
