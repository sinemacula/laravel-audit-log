<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\OpenTransactions;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Delivery\DeliverySettings;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Delivery\PackageWrite;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\RecordPipeline;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;

/**
 * Writes the record of a lifecycle operation, a prune, a hold, a release or an
 * import, through the package's own write path once the operation's transaction
 * has committed: fail-closed and immediate whatever the failure mode says, by
 * the operator who asked for it, or by no one for a prune, in explicitly no
 * tenant, so an ambient one is never inherited, and keeping its evidence
 * exactly or refused before anything is delivered.
 *
 * "Fail-closed" names the recording attempt alone: the operation has committed
 * already, with the journal row that describes it, and the journal is the
 * authority, so a record that cannot be written never undoes it. A record is
 * not attempted while a transaction is open on the connection that would
 * acknowledge it, the storage connection in sync mode and the outbox
 * connection in outbox mode, since its acknowledgement could still roll back;
 * that is confirmed again once the write returns, since the contributors it
 * runs are the application's code. A refusal, a failed write, which the
 * fail-closed rule spills, and a write never acknowledged are each reported
 * once, through the report latch, as a payload-free
 * `LifecycleRecordFailedException`, and answered `false`; nothing is rethrown,
 * and `audit-log:reconcile` records what is missing.
 *
 * Each record's id is derived from its code and its operation id, a UUID of
 * version 8 from their SHA-256, so one operation's record of one code has one
 * id wherever it is written: queued in the outbox or stored, by the operation
 * or by a reconciliation, a second write of it is refused by the outbox's or
 * the entries' primary key, or is the record stored already, and never a second
 * record.
 *
 * It resolves everything from the container on every call, so it outlives
 * requests safely.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LifecycleRecorder
{
    /** @var string What every record id is derived under, before its code and operation id. */
    private const string ID_INFO = 'audit-log lifecycle record id v1';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the settings, the definitions, the contributors and the reporter are resolved from on every call. */
        private Container $container,
    ) {}

    /**
     * Record the activity by the actor, keeping the evidence exactly, with its
     * outcome and the reason given for a failure or a denial, and say whether
     * the store or the outbox acknowledged it; a record that was refused,
     * failed or was never acknowledged is reported once and answered `false`.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence  $evidence
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @return bool
     *
     * @imperative
     */
    public function record(PackageActivity $activity, ?Reference $actor, #[\SensitiveParameter] LifecycleEvidence $evidence, Outcome $outcome, ?string $reason = null): bool
    {
        try {
            $failure = $this->attempt($activity, $actor, $evidence, $outcome, $reason);
        } catch (\Throwable $exception) {
            $failure = LifecycleRecordFailedException::of($evidence->operationId, $activity, get_debug_type($exception));
        }

        if ($failure === null) {
            return true;
        }

        $this->report($failure);

        return false;
    }

    /**
     * The id of the record of the code for the operation: a lower-case UUID of
     * version 8 and the RFC 9562 variant, from the SHA-256 of the derivation's
     * info, the code and the operation id, each ended by a NUL.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @param  string  $operationId
     * @return string
     */
    public static function recordIdOf(PackageActivity $activity, string $operationId): string
    {
        $bytes = substr(hash('sha256', self::ID_INFO . "\0" . $activity->value . "\0" . $operationId . "\0", true), 0, 16);

        $bytes[6] = chr((ord($bytes[6]) & 0x0F) | 0x80);
        $bytes[8] = chr((ord($bytes[8]) & 0x3F) | 0x80);

        $hex = bin2hex($bytes);

        return sprintf('%s-%s-%s-%s-%s', substr($hex, 0, 8), substr($hex, 8, 4), substr($hex, 12, 4), substr($hex, 16, 4), substr($hex, 20));
    }

    /**
     * Attempt the record, outside any transaction on the acknowledging
     * connection, and return why it is not written, or `null` once it is
     * acknowledged with no such transaction open.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence  $evidence
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecordFailedException
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function attempt(
        PackageActivity $activity,
        ?Reference $actor,
        #[\SensitiveParameter]
        LifecycleEvidence $evidence,
        Outcome $outcome,
        ?string $reason,
    ): ?LifecycleRecordFailedException {
        $open = $this->openAcknowledgingConnection();

        if ($open !== null) {
            return LifecycleRecordFailedException::inTransaction($evidence->operationId, $activity, $open);
        }

        if (!$this->write(self::pending($activity, $actor, $evidence, $outcome, $reason), $evidence)) {
            return LifecycleRecordFailedException::unacknowledged($evidence->operationId, $activity);
        }

        $open = $this->openAcknowledgingConnection();

        return $open === null ? null : LifecycleRecordFailedException::inTransaction($evidence->operationId, $activity, $open);
    }

    /**
     * Write the builder's record through the record pipeline with a package
     * write that refuses it unless it keeps the evidence exactly, under the
     * definitions and contributors registered while the application booted, and
     * say whether the store or the outbox acknowledged it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence  $evidence
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    private function write(#[\SensitiveParameter] PendingRecord $pending, #[\SensitiveParameter] LifecycleEvidence $evidence): bool
    {
        $acknowledged = false;

        $package = new PackageWrite(
            static function (#[\SensitiveParameter] AuditRecord $record) use ($evidence): void {
                $evidence->assertKeptBy($record);
            },
            static function () use (&$acknowledged): void {
                $acknowledged = true;
            },
        );

        $pipeline = new RecordPipeline($this->container->make(EventCatalogue::class), $this->container->make(ContributorRegistry::class));

        $pipeline->write($pending, null, $package);

        return $acknowledged;
    }

    /**
     * The name of the connection that would acknowledge the record, when a
     * transaction is open on it: the storage connection in sync mode, and the
     * outbox connection in outbox mode; `null` when none is open.
     *
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function openAcknowledgingConnection(): ?string
    {
        $mode       = $this->container->make(DeliverySettings::class)->mode();
        $connection = $mode === DeliveryMode::OUTBOX ? DeliveryTables::resolvedOutboxConnection() : StorageConnection::resolvedName();
        $open       = $this->container->make(OpenTransactions::class)->names();

        return in_array($connection, $open, true) ? $connection : null;
    }

    /**
     * Report the failure once, through the report latch, ignoring a reporter
     * that fails.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleRecordFailedException  $failure
     * @return void
     */
    private function report(LifecycleRecordFailedException $failure): void
    {
        try {
            $handler = $this->container->make(ExceptionHandler::class);

            $this->container->make(ReportLatch::class)->once(static function () use ($handler, $failure): void {
                $handler->report($failure);
            });
        } catch (\Throwable) {
            // The operation stands all the same; a broken reporter has nowhere
            // left to say so, and must not undo it
        }
    }

    /**
     * The builder of the record: the activity's code, by the actor or
     * explicitly no one, in explicitly no tenant, with the evidence's
     * properties, the outcome and its reason, fail-closed, and so immediate.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleEvidence  $evidence
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function pending(
        PackageActivity $activity,
        ?Reference $actor,
        #[\SensitiveParameter]
        LifecycleEvidence $evidence,
        Outcome $outcome,
        ?string $reason,
    ): PendingRecord {
        $pending = (new PendingRecord)
            ->forPackage($activity)
            ->identifiedAs(self::recordIdOf($activity, $evidence->operationId))
            ->by($actor)
            ->forTenant(null)
            ->withProperties($evidence->properties);

        $ended = match ($outcome) {
            Outcome::SUCCESS => $pending->succeeded(),
            Outcome::FAILURE => $pending->failed($reason),
            Outcome::DENIED  => $pending->denied($reason),
        };

        return $ended->failClosed();
    }
}
