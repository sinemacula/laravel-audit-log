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
 * Writes a lifecycle operation's record once its transaction commits:
 * fail-closed and immediate, in no tenant, by its operator or no one.
 *
 * Nothing is attempted while the acknowledging connection is in a transaction,
 * since the acknowledgement could still roll back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LifecycleRecorder
{
    /** @var string The info every record id is derived under. */
    private const string ID_INFO = 'audit-log lifecycle record id v1';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container everything is resolved from on every call, so it outlives requests. */
        private Container $container,
    ) {}

    /**
     * Record the activity, keeping the evidence exactly, and say whether it was
     * acknowledged; a failure is reported once.
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
     * A UUIDv8 from the SHA-256 of the code and operation id, so every write of
     * one record has one id.
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
     * Attempt the record and return why it was not written, or `null`;
     * rechecked after the write, as contributors are application code.
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
     * Write the record through the pipeline, refused unless it keeps the
     * evidence, and say whether it was acknowledged.
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
     * The acknowledging connection's name, storage or outbox by mode, when a
     * transaction is open on it.
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
     * Report the failure once, ignoring a reporter that fails.
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
            // A broken reporter must not undo the operation
        }
    }

    /**
     * The record's builder, in explicitly no tenant so an ambient one is never
     * inherited.
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
