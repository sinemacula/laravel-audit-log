<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryOutcome;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics;

/**
 * Delivers a claimed outbox row's record to each destination of the store,
 * keeping a receipt per destination so a retry reaches only those without it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeliveryCoordinator
{
    /** @var string The destination id of a store that is not a stack. */
    public const string STORE_DESTINATION = 'store';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Outbox  $outbox
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Receipts  $receipts
     */
    public function __construct(

        /** Resolves the store, the guard and the reporter for each row. */
        private Container $container,

        /** Where the claim is renewed. */
        private Outbox $outbox,

        /** The receipts of each destination. */
        private Receipts $receipts,
    ) {}

    /**
     * Deliver the record to every destination still without it: complete,
     * incomplete, or stale once the claim is lost.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @return \SineMacula\Laravel\AuditLog\Delivery\DeliveryResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function deliver(#[\SensitiveParameter] FinalisedRecord $record, #[\SensitiveParameter] OutboxClaim $claim): DeliveryResult
    {
        $store        = $this->container->make(AuditStore::class);
        $destinations = $store instanceof StackAuditStore ? $store->destinations() : [self::STORE_DESTINATION => $store];

        try {
            $receipts = $this->receipts->forEntry($record->record->id);
        } catch (\Throwable $failure) {
            return DeliveryResult::incomplete(WriteDiagnostics::of($failure, $record->record->id, $record->record->event, FailedOperation::DRAIN, get_debug_type($store)));
        }

        $result = $this->deliverEach($record, $claim, $destinations, $receipts, $store instanceof StackAuditStore);

        if ($result->outcome === DeliveryOutcome::COMPLETE) {
            $this->reportDisappeared($record->record->id, $receipts, $destinations);
        }

        return $result;
    }

    /**
     * Deliver to each destination in order, skipping one already delivered and
     * stopping once the claim is lost.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  array<string, \SineMacula\Laravel\AuditLog\Contracts\AuditStore>  $destinations
     * @param  array<string, \SineMacula\Laravel\AuditLog\Delivery\Receipt>  $receipts
     * @param  bool  $stacked
     * @return \SineMacula\Laravel\AuditLog\Delivery\DeliveryResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function deliverEach(
        #[\SensitiveParameter]
        FinalisedRecord $record,
        #[\SensitiveParameter]
        OutboxClaim $claim,
        array $destinations,
        array $receipts,
        bool $stacked,
    ): DeliveryResult {
        $failure = null;

        foreach ($destinations as $name => $destination) {

            $receipt = $receipts[$name] ?? null;

            if ($receipt !== null && $receipt->delivered) {
                continue;
            }

            $attempt = $this->renewedAttempt($record, $claim, $name, $destination, $receipt, $stacked);

            if ($attempt->outcome === DeliveryOutcome::STALE) {
                return $attempt;
            }

            $failure = $attempt->outcome === DeliveryOutcome::INCOMPLETE ? $attempt->failure() : $failure;
        }

        return $failure === null ? DeliveryResult::complete() : DeliveryResult::incomplete($failure);
    }

    /**
     * Renew the claim and attempt the destination; stale if the claim is lost.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  string  $name
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditStore  $destination
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\Receipt  $receipt
     * @param  bool  $stacked
     * @return \SineMacula\Laravel\AuditLog\Delivery\DeliveryResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function renewedAttempt(
        #[\SensitiveParameter]
        FinalisedRecord $record,
        #[\SensitiveParameter]
        OutboxClaim $claim,
        string $name,
        AuditStore $destination,
        ?Receipt $receipt,
        bool $stacked,
    ): DeliveryResult {
        return $this->outbox->renew($claim) ? $this->attempt($record, $claim, $name, $destination, $receipt, $stacked) : DeliveryResult::stale();
    }

    /**
     * Count the attempt on the receipt, then call the destination and mark it
     * delivered, sharing a transaction with the receipt when the destination
     * joins the storage connection's.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  string  $name
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditStore  $destination
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\Receipt  $receipt
     * @param  bool  $stacked
     * @return \SineMacula\Laravel\AuditLog\Delivery\DeliveryResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function attempt(
        #[\SensitiveParameter]
        FinalisedRecord $record,
        #[\SensitiveParameter]
        OutboxClaim $claim,
        string $name,
        AuditStore $destination,
        ?Receipt $receipt,
        bool $stacked,
    ): DeliveryResult {
        try {
            $this->receipts->attempting($record->record->id, $name, $receipt);

            self::refuseAnAttachmentTo($destination, $record);

            $delivered = $destination instanceof DurableAuditStore && $destination->participatesIn(StorageConnection::resolvedName())
                ? $this->deliverInTransaction($record, $claim, $name, $destination)
                : $this->deliverAlone($record, $claim, $name, $destination);
        } catch (StaleClaimException) {
            return DeliveryResult::stale();
        } catch (\Throwable $failure) {
            return $this->failed($record, $claim, $name, $destination, $stacked, $failure);
        }

        return $delivered ? DeliveryResult::complete() : DeliveryResult::stale();
    }

    /**
     * Call the destination and mark its receipt delivered in one transaction on
     * the storage connection; a lost claim throws to roll it back, so this
     * returns `true`.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  string  $name
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditStore  $destination
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\AuditLog\Delivery\StaleClaimException
     * @throws \Throwable
     *
     * @imperative
     */
    private function deliverInTransaction(#[\SensitiveParameter] FinalisedRecord $record, #[\SensitiveParameter] OutboxClaim $claim, string $name, AuditStore $destination): bool
    {
        return $this->receipts->connection()->transaction(function () use ($record, $claim, $name, $destination): bool {
            if ($this->deliverAlone($record, $claim, $name, $destination)) {
                return true;
            }

            throw new StaleClaimException;
        });
    }

    /**
     * Call the destination, then mark its receipt delivered if the claim still
     * owns the row, which is returned.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  string  $name
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditStore  $destination
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @imperative
     */
    private function deliverAlone(#[\SensitiveParameter] FinalisedRecord $record, #[\SensitiveParameter] OutboxClaim $claim, string $name, AuditStore $destination): bool
    {
        $this->store($destination, $record);

        if (!$this->outbox->renew($claim)) {
            return false;
        }

        $this->receipts->delivered($record->record->id, $name);

        return true;
    }

    /**
     * Keep the failure's class on the receipt and in the result, or return
     * stale when the claim is lost.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  string  $name
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditStore  $destination
     * @param  bool  $stacked
     * @param  \Throwable  $failure
     * @return \SineMacula\Laravel\AuditLog\Delivery\DeliveryResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function failed(
        #[\SensitiveParameter]
        FinalisedRecord $record,
        #[\SensitiveParameter]
        OutboxClaim $claim,
        string $name,
        AuditStore $destination,
        bool $stacked,
        #[\SensitiveParameter]
        \Throwable $failure,
    ): DeliveryResult {
        if (!$this->outbox->renew($claim)) {
            return DeliveryResult::stale();
        }

        $id = $record->record->id;

        try {
            $this->receipts->failed($id, $name, get_debug_type($failure));
        } catch (\Throwable) {
            // The row keeps the failure, and a retry writes the receipt
        }

        $diagnostics = WriteDiagnostics::of($failure, $id, $record->record->event, FailedOperation::DRAIN, get_debug_type($destination), null, $stacked ? $name : null);

        return DeliveryResult::incomplete($diagnostics);
    }

    /**
     * Hand the record to the destination inside the write guard, so a record it
     * makes is refused.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditStore  $destination
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function store(AuditStore $destination, #[\SensitiveParameter] FinalisedRecord $record): void
    {
        $this->container->make(WriteGuard::class)->during(static function () use ($destination, $record): void {
            $destination->store($record);
        });
    }

    /**
     * Report each undelivered receipt of a destination the store no longer has.
     *
     * @param  string  $id
     * @param  array<string, \SineMacula\Laravel\AuditLog\Delivery\Receipt>  $receipts
     * @param  array<string, \SineMacula\Laravel\AuditLog\Contracts\AuditStore>  $destinations
     * @return void
     */
    private function reportDisappeared(string $id, array $receipts, array $destinations): void
    {
        foreach ($receipts as $name => $receipt) {

            if ($receipt->delivered || array_key_exists($name, $destinations)) {
                continue;
            }

            $message = 'Audit record %s has an undelivered receipt for the destination [%s], which the store no longer has;'
                . ' the record was delivered without it.';

            $this->report(new \LogicException(sprintf($message, $id, $name)));
        }
    }

    /**
     * Report the exception inside the write guard, ignoring a failing reporter.
     *
     * @param  \LogicException  $exception
     * @return void
     */
    private function report(#[\SensitiveParameter] \LogicException $exception): void
    {
        $container = $this->container;

        try {
            $container->make(WriteGuard::class)->during(static function () use ($container, $exception): void {
                $container->make(ExceptionHandler::class)->report($exception);
            });
        } catch (\Throwable) {
            // A delivered record's broken reporter must not stop the drain
        }
    }

    /**
     * Refuse a record with an attachment before calling a destination that
     * keeps none, so a bundle never loses its members.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditStore  $destination
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return void
     *
     * @throws \LogicException
     */
    private static function refuseAnAttachmentTo(AuditStore $destination, #[\SensitiveParameter] FinalisedRecord $record): void
    {
        $refused = $record->record->attachment !== null && !StoreCapabilities::keepsAttachments($destination);
        $refusal = $refused ? StoreCapabilities::refuseAttachmentsTo($destination) : null;

        if ($refusal !== null) {
            throw $refusal;
        }
    }
}
