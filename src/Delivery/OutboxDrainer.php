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
 * Drains the outbox: claims each due row, decrypts and verifies its envelope,
 * delivers the record to every destination and deletes the row.
 *
 * It never runs inside a transaction on the outbox or storage connection, where
 * a rollback would lose a record whose row was deleted.
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

    /** @var int Most doublings of the first wait, so the wait cannot overflow. */
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

        /** Resolves the encrypter, codec, guard, reporter and dispatcher. */
        private Container $container,

        /** The outbox the rows are claimed from. */
        private Outbox $outbox,

        /** Delivers each record to the store's destinations. */
        private DeliveryCoordinator $coordinator,

        /** Where the attempts and the backoff are read from. */
        private DeliverySettings $settings,

        /** Fixes which rows are due and when a retry comes. */
        private Clock $clock,

        /** Dispatches `AuditRecorded` for a delivered record. */
        private RecordedNotifier $notifier,

        /** Say whether retention has already pruned a row's record. */
        private PruneTombstones $tombstones,
    ) {}

    /**
     * Drain at most the limit of rows due now, or batches until none is left to
     * claim, and tally how each ended; a passed-in tally keeps the rows worked
     * before a failure stops the run.
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
     * Refuse to drain inside a transaction on the outbox or storage connection.
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
     * the claim failed, which is reported.
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
     * Work the claimed row, reporting whatever stops it and retrying it after
     * its backoff, so one row stops no other.
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
     * Report what stopped the row, then retry it or fail it at its last
     * attempt; a row that can take neither keeps its claim until the lease
     * passes.
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
            // Nothing can be written to the outbox, so the lease brings the row
            // back and the report is all that is left
            if (!$reported) {
                $this->report($diagnostics);
            }

            $result->addFailed();
        }
    }

    /**
     * Work the claimed row: abandon it past its attempts, else complete it as
     * pruned or deliver it. Every row is checked against the tombstones, since
     * a requeued row may hold a record pruned since.
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
     * The row's record once decrypted and verified, or `null` once the row is
     * failed because it was not.
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
     * Deliver the record, then delete, retry or fail the row by the outcome.
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
     * Delete the delivered row, then dispatch `AuditRecorded`; stale,
     * dispatching nothing, when the claim is lost.
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
     * Delete a row whose record retention pruned, delivering and dispatching
     * nothing; stale when the claim is lost.
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
     * Fail the row on its last attempt, or release it for a retry after the
     * backoff, keeping the failure's class.
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
     * Fail and keep the row, report it, and dispatch `AuditWriteFailed` when
     * its code is known; stale, with nothing reported, when the claim is lost.
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
     * Run the step inside the write guard, ignoring whatever it throws.
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
            // A broken reporter or listener must not stop the drain
        }
    }

    /**
     * Diagnostics for a row abandoned past its attempts, with the reason
     * standing in for the exception class.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\OutboxClaim  $claim
     * @return \SineMacula\Laravel\AuditLog\Stores\WriteDiagnostics
     */
    private function abandoned(#[\SensitiveParameter] OutboxClaim $claim): WriteDiagnostics
    {
        return new WriteDiagnostics($claim->id, null, FailedOperation::DRAIN, get_debug_type($this->outbox), self::ABANDONED, null, null, null, null);
    }

    /**
     * Payload-free diagnostics of a failure working the row, whose record, and
     * so its code, is unknown.
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
     * Seconds before a row's next attempt: the first wait, doubled after each
     * attempt since the first, capped at an hour.
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
