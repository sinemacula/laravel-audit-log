<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;

/**
 * What the bound audit store says of itself, resolved on every call so a later
 * binding is the one read.
 *
 * The package outside the delivery reaches the store only through this class,
 * so only the delivery writes to it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StoreCapabilities
{
    /** @var string The refusal of an attachment, by the store's class. */
    private const string NO_ATTACHMENTS = 'The store %s does not keep attachments, so a bulk operation cannot be stored there. Bind one that does, such as the database store.';

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
     * Whether the bound store keeps a record's attachment with its entry.
     *
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function acceptsAttachments(): bool
    {
        return self::keepsAttachments($this->store());
    }

    /**
     * Refuse a record's attachment when the bound store keeps none, naming the
     * store's class.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    public function assertAcceptsAttachments(): void
    {
        $store = $this->store();

        if (!self::keepsAttachments($store)) {
            throw self::refuseAttachmentsTo($store);
        }
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
     * The class of each destination by id: a stack's destinations, or the store
     * under `store`.
     *
     * @return non-empty-array<string, string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function destinationClasses(): array
    {
        $store        = $this->store();
        $destinations = $store instanceof StackAuditStore ? $store->destinations() : [DeliveryCoordinator::STORE_DESTINATION => $store];

        return array_map(get_debug_type(...), $destinations);
    }

    /**
     * Whether the store implements `Contracts\AcceptsAttachments` and says it
     * keeps attachments.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditStore  $store
     * @return bool
     */
    public static function keepsAttachments(AuditStore $store): bool
    {
        return $store instanceof AcceptsAttachments && $store->acceptsAttachments();
    }

    /**
     * The refusal of an attachment to a store that keeps none, naming its debug
     * type so an anonymous store names no file path.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditStore  $store
     * @return \LogicException
     */
    public static function refuseAttachmentsTo(AuditStore $store): \LogicException
    {
        return new \LogicException(sprintf(self::NO_ATTACHMENTS, get_debug_type($store)));
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
