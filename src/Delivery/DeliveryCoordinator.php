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
 * keeping a receipt for each: a stack's destinations, in order and under their
 * ids, or a single store as the one destination `store`.
 *
 * A destination whose receipt says it has the record is not called again, so a
 * retry reaches only the destinations still without it. For each other, the
 * claim is renewed, the attempt is counted on its receipt, then the destination
 * is called, inside the write guard. A destination that joins a transaction on
 * the storage connection shares one with its receipt, so the record and the
 * receipt saying it was delivered commit or roll back together; any other is
 * called on its own, and its receipt follows. A destination that fails keeps
 * its failure's class on its receipt, never its message, and the others are
 * still tried.
 *
 * A bundle, a record with its attachment, is handed whole to each destination
 * that keeps attachments, and its receipt is marked delivered only once that
 * destination returned, so a bundle is never marked delivered without its entry
 * and its artifact. A destination that keeps none is asked before it is called
 * and refused, its attempt counted: that destination's failure alone, so the
 * others are still tried and the row is retried, then failed and kept, never
 * deleted. A record without an attachment asks no destination.
 *
 * The claim is renewed before every call and every receipt, and once the drain
 * finds it no longer owns the row it stops and writes nothing further, not even
 * the receipt of a call that succeeded: the new owner repeats the call, which
 * at-least-once delivery allows. A shared transaction is rolled back for it.
 *
 * Reading or writing a receipt is part of delivering: when the deliveries table
 * cannot be reached, as in an outage of the storage connection, the delivery is
 * incomplete, so the row retries after its backoff like any other failure.
 *
 * The store is resolved from the current container for each row, so a
 * destination removed from a stack stops blocking its rows at once; a receipt
 * it left undelivered is reported, once, as the row completes. A delivery ends
 * in a `DeliveryResult`, which holds what the last destination to fail failed
 * with, as payload-free diagnostics, when it is incomplete.
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

        /** The container the store, the guard and the reporter are resolved from for each row. */
        private Container $container,

        /** The outbox the claim is renewed on. */
        private Outbox $outbox,

        /** The receipts of each destination. */
        private Receipts $receipts,
    ) {}

    /**
     * Deliver the record to every destination that does not have it yet:
     * complete once each has it, incomplete when one failed or its receipts
     * could not be read, and stale as soon as the claim no longer owns the row.
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
     * Deliver the record to each destination in order, skipping one whose
     * receipt says it has the record, and renewing the claim before each call:
     * stale at once when the claim no longer owns the row, and otherwise
     * incomplete, with what the last failed with, when any failed.
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
     * Renew the claim, then attempt the destination: stale when the claim no
     * longer owns the row.
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
     * Count the attempt on the destination's receipt, then call the destination
     * and mark its receipt delivered: complete when it has the record,
     * incomplete when it failed, keeps no attachment the record carries or a
     * receipt could not be written, and stale when the claim no longer owns the
     * row. A destination that joins a transaction on the storage connection is
     * called inside one it shares with its receipt.
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
     * Call the destination and mark its receipt delivered inside one
     * transaction on the storage connection, rolled back whole when the claim
     * no longer owns the row once the call returns. Returns `true`, since a
     * lost claim is thrown to roll the transaction back.
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
     * Call the destination, then mark its receipt delivered once the claim is
     * renewed. Returns whether the claim still owned the row; when it did not,
     * no receipt is written.
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
     * Keep the class of the destination's failure on its receipt and in the
     * result, once the claim is renewed: incomplete, or stale when the claim no
     * longer owns the row. A receipt that cannot be written does not change
     * that, since the row keeps the class and a retry writes the receipt.
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
            // The deliveries table is out of reach, which a retry will find out
            // again; the row keeps what the destination failed with
        }

        $diagnostics = WriteDiagnostics::of($failure, $id, $record->record->event, FailedOperation::DRAIN, get_debug_type($destination), null, $stacked ? $name : null);

        return DeliveryResult::incomplete($diagnostics);
    }

    /**
     * Hand the record to the destination inside the write guard, so a record
     * made by the destination is refused rather than written.
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
     * Report each receipt left undelivered by a destination the store no longer
     * has, inside the write guard. A reporter that fails is ignored: the record
     * is delivered, and there is nowhere left to say so.
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
     * Report the exception inside the write guard, ignoring a reporter that
     * fails.
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
            // The record is delivered; a broken reporter must not stop the
            // drain, and there is nowhere left to say so
        }
    }

    /**
     * Refuse the record's attachment to a destination that keeps none, before
     * it is called, so a bundle is never handed to a store that would lose its
     * members. A record without an attachment asks the destination nothing.
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
