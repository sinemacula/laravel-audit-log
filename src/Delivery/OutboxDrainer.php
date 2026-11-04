<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Contracts\Events\Dispatcher;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryOutcome;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\EnvelopeRejectedException;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics;

/**
 * Drains the outbox: claims each row that is due, decrypts and verifies the
 * envelope it holds, delivers the record to every destination of the store, and
 * deletes the row once each has it.
 *
 * A run takes the rows due when it starts, a batch at a time, so a row added
 * while it runs waits for the next run and a run until the outbox is empty
 * always ends. A row another drain claimed first is missed, and one another
 * drain took over while this one worked it is stale: this drain changes nothing
 * of it further. A row is never re-signed or finalised again.
 *
 * A row whose record retention has already pruned is deleted and counted
 * pruned, and nothing else: no destination is called and `AuditRecorded` is not
 * dispatched, so a pruned record is never stored again. Every row whose record
 * is read is checked against the tombstones, one statement each, since a row
 * requeued by `audit-log:replay --outbox` starts its attempts again and may
 * hold a record that was stored, sealed and pruned since.
 *
 * A row holding a bundle, a record with its attachment, is delivered whole:
 * each destination that keeps attachments stores the entry and its artifact
 * together, and its receipt follows them. A destination that keeps none is
 * refused before it is called, as that destination's failure, so the row is
 * retried, then failed and kept for a replay, never deleted.
 *
 * A row whose destination failed is retried after a wait that doubles with each
 * attempt, from `delivery.outbox.backoff_seconds` up to an hour, without a
 * report: the class of the failure is kept on the row and the receipt. At
 * `delivery.outbox.max_attempts` the row is failed and kept for a replay, the
 * failure is reported and `AuditWriteFailed` is dispatched. A row that cannot
 * be decrypted (its key removed, or the payload corrupt), an envelope that does
 * not verify, or a row that has already had more attempts than it may, its
 * worker killed each time, is failed and kept at once and reported by its id.
 * Every report holds the record's id and code and the failure's class, never a
 * value of the record or the failure's message, and runs, as does every
 * dispatch of `AuditWriteFailed`, inside the write guard. A row whose work
 * stops for a reason a delivery does not expect, or whose claim fails, is
 * reported the same way and stops no other: the former retries after its
 * backoff, and keeps its lease only when that retry cannot be written either.
 *
 * A drain never runs inside a transaction on the outbox or the storage
 * connection: a receipt and its entry would wait for that commit while the
 * outbox row was deleted, and a rollback would lose the record.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OutboxDrainer
{
    /** @var int Longest wait before a retry, in seconds: an hour. */
    public const int MAX_BACKOFF_SECONDS = 3600;

    /** @var int The most doublings of the first wait, so the wait is computed without overflow. */
    private const int MAX_DOUBLINGS = 16;

    /** @var string Why a row that has had more attempts than it may is failed. */
    private const string ABANDONED = 'abandoned';

    /** @var string Why a row whose payload cannot be decrypted is failed. */
    private const string UNDECRYPTABLE = 'undecryptable';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Outbox  $outbox
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DeliveryCoordinator  $coordinator
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DeliverySettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\AuditLog\Delivery\RecordedNotifier  $notifier
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones  $tombstones
     */
    public function __construct(

        /** The container the encrypter, the codec, the guard, the reporter and the dispatcher are resolved from. */
        private Container $container,

        /** The outbox the rows are claimed from. */
        private Outbox $outbox,

        /** The coordinator that delivers each record to the store's destinations. */
        private DeliveryCoordinator $coordinator,

        /** The settings the attempts and the wait before a retry are read from. */
        private DeliverySettings $settings,

        /** The clock that fixes which rows are due and when a retry comes. */
        private Clock $clock,

        /** The notifier that dispatches `AuditRecorded` for a delivered record. */
        private RecordedNotifier $notifier,

        /** The tombstones that say whether retention has already pruned a row's record. */
        private PruneTombstones $tombstones,
    ) {}

    /**
     * Drain at most the limit of rows due now, or, until empty, batch after
     * batch of them until none is left that this drain can claim, and tally how
     * each ended. A failure reading the rows stops the run; a tally passed in
     * still holds the rows already worked.
     *
     * @param  int  $limit
     * @param  bool  $untilEmpty
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return \SineMacula\Laravel\AuditLog\Delivery\DrainResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function drain(int $limit, bool $untilEmpty, ?DrainResult $result = null): DrainResult
    {
        $this->refuseInsideATransaction();

        $encrypter = $this->container->make(StringEncrypter::class);
        $codec     = $this->container->make(EnvelopeCodec::class);
        $due       = $this->clock->now();
        $result ??= new DrainResult;

        do {
            $claimed = false;

            foreach ($this->outbox->candidates($limit, $due) as $id) {

                $claim = $this->claimOrMiss($id, $due, $result);

                if ($claim === null) {
                    continue;
                }

                $claimed = true;

                $this->processSafely($claim, $encrypter, $codec, $result);
            }
        } while ($untilEmpty && $claimed);

        return $result;
    }

    /**
     * Refuse to drain while a transaction is open on the outbox or the storage
     * connection.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function refuseInsideATransaction(): void
    {
        if (!$this->outbox->isInTransaction() && $this->container->make(Receipts::class)->connection()->transactionLevel() === 0) {
            return;
        }

        throw new \LogicException('The outbox is drained outside any transaction, so a receipt and its delete are never held by a commit that may not come.');
    }

    /**
     * Claim the row, or count it missed when another drain claimed it first or
     * the claim failed; a failed claim is reported, and stops no other row.
     *
     * @param  string  $id
     * @param  \Carbon\CarbonImmutable  $due
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return ?\SineMacula\Laravel\AuditLog\Delivery\OutboxClaim
     */
    private function claimOrMiss(string $id, CarbonImmutable $due, DrainResult $result): ?OutboxClaim
    {
        try {
            $claim = $this->outbox->claim($id, $due);
        } catch (\Throwable $exception) {
            $this->report(WriteDiagnostics::of($exception, $id, null, FailedOperation::DRAIN, get_debug_type($this->outbox)));

            $claim = null;
        }

        if ($claim === null) {
            $result->addMissed();
        }

        return $claim;
    }

    /**
     * Work the claimed row, so one row that cannot be worked stops no other;
     * whatever stops it is reported payload-free and handled as a failed
     * delivery, so the row retries after its backoff.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  \Illuminate\Contracts\Encryption\StringEncrypter  $encrypter
     * @param  \SineMacula\Laravel\AuditLog\Records\EnvelopeCodec  $codec
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return void
     */
    private function processSafely(#[\SensitiveParameter] OutboxClaim $claim, StringEncrypter $encrypter, EnvelopeCodec $codec, DrainResult $result): void
    {
        try {
            $this->process($claim, $encrypter, $codec, $result);
        } catch (\Throwable $exception) {
            $this->recover($claim, $this->diagnosticsOf($exception, $claim), $result);
        }
    }

    /**
     * Report what stopped the row, then retry it after its backoff, or fail it
     * at its last attempt, which reports it itself. Only a row that cannot take
     * either keeps its claim until the lease passes, counted failed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics  $diagnostics
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return void
     */
    private function recover(#[\SensitiveParameter] OutboxClaim $claim, WriteDiagnostics $diagnostics, DrainResult $result): void
    {
        $reported = false;

        try {
            if ($claim->attempts < $this->settings->maxAttempts()) {
                $this->report($diagnostics);

                $reported = true;
            }

            $this->incomplete($claim, $diagnostics, $result);
        } catch (\Throwable) {
            // Nothing can be written to the outbox, so the lease is what brings
            // the row back, and the report is all that is left
            if (!$reported) {
                $this->report($diagnostics);
            }

            $result->addFailed();
        }
    }

    /**
     * Work the claimed row: abandon it past its attempts, and otherwise read
     * its record, then complete it as pruned when retention has pruned that
     * record, and deliver it when not.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  \Illuminate\Contracts\Encryption\StringEncrypter  $encrypter
     * @param  \SineMacula\Laravel\AuditLog\Records\EnvelopeCodec  $codec
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function process(#[\SensitiveParameter] OutboxClaim $claim, StringEncrypter $encrypter, EnvelopeCodec $codec, DrainResult $result): void
    {
        if ($claim->attempts > $this->settings->maxAttempts()) {
            $this->fail($claim, self::ABANDONED, $this->abandoned($claim), $result);

            return;
        }

        $record = $this->recordOf($claim, $encrypter, $codec, $result);

        if ($record === null) {
            return;
        }

        if ($this->tombstones->isPruned($claim->id)) {
            $this->completePruned($claim, $result);

            return;
        }

        $this->deliver($record, $claim, $result);
    }

    /**
     * The record the claimed row holds, once its payload is decrypted and its
     * envelope verifies, or `null` once the row is failed because it does not:
     * as undecryptable, or for the reason the envelope was refused.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  \Illuminate\Contracts\Encryption\StringEncrypter  $encrypter
     * @param  \SineMacula\Laravel\AuditLog\Records\EnvelopeCodec  $codec
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return ?\SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function recordOf(#[\SensitiveParameter] OutboxClaim $claim, StringEncrypter $encrypter, EnvelopeCodec $codec, DrainResult $result): ?FinalisedRecord
    {
        try {
            return $codec->decode($encrypter->decryptString($claim->payload), $claim->id);
        } catch (DecryptException $exception) {
            $this->fail($claim, self::UNDECRYPTABLE, $this->diagnosticsOf($exception, $claim), $result);
        } catch (EnvelopeRejectedException $exception) {
            $this->fail($claim, $exception->failure->value, $this->diagnosticsOf($exception, $claim), $result);
        }

        return null;
    }

    /**
     * Deliver the record to the store's destinations, then delete the row when
     * every destination has it, and otherwise retry or fail it; nothing more
     * when the claim was lost on the way.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function deliver(#[\SensitiveParameter] FinalisedRecord $record, #[\SensitiveParameter] OutboxClaim $claim, DrainResult $result): void
    {
        $delivery = $this->coordinator->deliver($record, $claim);

        match ($delivery->outcome) {
            DeliveryOutcome::COMPLETE   => $this->complete($record, $claim, $result),
            DeliveryOutcome::INCOMPLETE => $this->incomplete($claim, $delivery->failure(), $result),
            DeliveryOutcome::STALE      => $result->addStale(),
        };
    }

    /**
     * Delete the row every destination has, then dispatch `AuditRecorded`; stale
     * when the claim no longer owns the row, and then nothing is dispatched.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function complete(#[\SensitiveParameter] FinalisedRecord $record, #[\SensitiveParameter] OutboxClaim $claim, DrainResult $result): void
    {
        if (!$this->outbox->delete($claim)) {
            $result->addStale();

            return;
        }

        $result->addDelivered();

        $this->notifier->notify($record->record->id, $record->record->event, $record->record->category);
    }

    /**
     * Delete the row whose record retention has pruned, delivering it nowhere
     * and dispatching nothing; stale when the claim no longer owns the row.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function completePruned(#[\SensitiveParameter] OutboxClaim $claim, DrainResult $result): void
    {
        if (!$this->outbox->delete($claim)) {
            $result->addStale();

            return;
        }

        $result->addPruned();
    }

    /**
     * Fail the row whose destination failed on its last attempt, and otherwise
     * release it for a retry after the backoff, keeping the class of the last
     * failure either way.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics  $failure
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function incomplete(#[\SensitiveParameter] OutboxClaim $claim, #[\SensitiveParameter] WriteDiagnostics $failure, DrainResult $result): void
    {
        if ($claim->attempts >= $this->settings->maxAttempts()) {
            $this->fail($claim, $failure->exceptionClass, $failure, $result);

            return;
        }

        $availableAt = $this->clock->now()->addSeconds($this->backoffSeconds($claim->attempts));

        if (!$this->outbox->retry($claim, $availableAt, $failure->exceptionClass)) {
            $result->addStale();

            return;
        }

        $result->addRetried();
    }

    /**
     * Fail and keep the row for the reason given, then report it, and dispatch
     * `AuditWriteFailed` when its code is known; stale when the claim no longer
     * owns the row, and then nothing is reported or dispatched.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @param  string  $reason
     * @param  \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics  $diagnostics
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function fail(#[\SensitiveParameter] OutboxClaim $claim, string $reason, WriteDiagnostics $diagnostics, DrainResult $result): void
    {
        if (!$this->outbox->fail($claim, $reason)) {
            $result->addStale();

            return;
        }

        $result->addFailed();

        $this->report($diagnostics);

        if ($diagnostics->eventCode === null || $diagnostics->recordId === null) {
            return;
        }

        $event = new AuditWriteFailed($diagnostics->recordId, $diagnostics->eventCode, $diagnostics->store, $diagnostics->exceptionClass);

        $this->guarded(static function (Container $container) use ($event): void {
            $container->make(Dispatcher::class)->dispatch($event);
        });
    }

    /**
     * Report the failure the diagnostics describe, as a payload-free
     * `AuditWriteFailedException`.
     *
     * @param  \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics  $diagnostics
     * @return void
     */
    private function report(WriteDiagnostics $diagnostics): void
    {
        $exception = new AuditWriteFailedException($diagnostics);

        $this->guarded(static function (Container $container) use ($exception): void {
            $container->make(ExceptionHandler::class)->report($exception);
        });
    }

    /**
     * Run the step inside the write guard, so a record made from it is refused,
     * ignoring whatever it throws.
     *
     * @param  \Closure(\Illuminate\Contracts\Container\Container): void  $step
     * @return void
     */
    private function guarded(#[\SensitiveParameter] \Closure $step): void
    {
        $container = $this->container;

        try {
            $container->make(WriteGuard::class)->during(static function () use ($container, $step): void {
                $step($container);
            });
        } catch (\Throwable) {
            // A broken reporter or listener must not stop the drain, and there
            // is nowhere left to say so
        }
    }

    /**
     * The diagnostics of a row abandoned past its attempts, which no exception
     * describes, so the reason stands in for the class.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @return \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics
     */
    private function abandoned(#[\SensitiveParameter] OutboxClaim $claim): WriteDiagnostics
    {
        return new WriteDiagnostics($claim->id, null, FailedOperation::DRAIN, get_debug_type($this->outbox), self::ABANDONED, null, null, null, null);
    }

    /**
     * The payload-free diagnostics of a failure working the claimed row, whose
     * record was not read, so its code is unknown.
     *
     * @param  \Throwable  $exception
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @return \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics
     */
    private function diagnosticsOf(#[\SensitiveParameter] \Throwable $exception, #[\SensitiveParameter] OutboxClaim $claim): WriteDiagnostics
    {
        return WriteDiagnostics::of($exception, $claim->id, null, FailedOperation::DRAIN, get_debug_type($this->outbox));
    }

    /**
     * How long a row waits before its next attempt, in seconds: the first wait
     * after the first attempt, which a claim always counts, doubled after each
     * attempt since, and never more than an hour.
     *
     * @param  int  $attempts
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function backoffSeconds(int $attempts): int
    {
        return min(self::MAX_BACKOFF_SECONDS, $this->settings->backoffSeconds() * 2 ** min($attempts - 1, self::MAX_DOUBLINGS));
    }
}
