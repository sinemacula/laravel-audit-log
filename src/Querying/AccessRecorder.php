<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Delivery\PackageWrite;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\RecordPipeline;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;

/**
 * Writes the record of a read of the trail, a count, an export, the
 * verification of an export or an export's failed publication, through the
 * package's own write path, fail-closed whatever the failure mode says, and
 * returns it only once the store or the outbox has acknowledged it, so nothing
 * a read would disclose leaves the package before its record is durable.
 *
 * The transaction rule is confirmed again just before the write, since the
 * policy that authorised the read is the application's code and may have opened
 * a transaction; its refusal records nothing. It is confirmed once more after
 * the write, before the acknowledgement is accepted, since the contributors the
 * write runs are the application's code too and may have left a transaction
 * open that the record's insert joined: an acknowledgement that could still
 * roll back is never accepted, and the read is refused with the transaction's
 * refusal, reported once. The record is the viewer's, by the viewer's
 * reference, in the tenant a scope of exactly one tenant names, or explicitly
 * in none, so an ambient tenant is never inherited. It keeps the evidence
 * exactly or is refused before anything is delivered.
 *
 * A write that failed, spilled under the fail-closed rule, a write the delivery
 * refused before writing, and a write that returned without being acknowledged
 * are each reported once, through the report latch, and refuse the read with
 * `AuditReadRefusedException`, which names nothing of the record. A failure
 * fatal to an open transaction propagates as the write path threw it, already
 * sanitised.
 *
 * It resolves everything from the container on every call, so it outlives
 * requests safely.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AccessRecorder
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the gate, the definitions, the contributors and the reporter are resolved from on every call. */
        private Container $container,
    ) {}

    /**
     * Record the activity of the viewer under the scope, keeping the evidence
     * exactly, with its outcome and the reason given for a failure or a denial,
     * and return the finalised record the store or the outbox acknowledged.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  ?\SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\AccessEvidence  $evidence
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    public function record(
        PackageActivity $activity,
        #[\SensitiveParameter]
        Viewer $viewer,
        ?AccessScope $scope,
        #[\SensitiveParameter]
        AccessEvidence $evidence,
        Outcome $outcome,
        ?string $reason = null,
    ): FinalisedRecord {
        $this->container->make(ReadGate::class)->confirmDurable();

        $acknowledged = null;

        $package = new PackageWrite(
            static function (#[\SensitiveParameter] AuditRecord $record) use ($evidence): void {
                $evidence->assertKeptBy($record);
            },
            static function (#[\SensitiveParameter] FinalisedRecord $finalised) use (&$acknowledged): void {
                $acknowledged = $finalised;
            },
        );

        $this->write(self::pending($activity, $viewer, $scope, $evidence, $outcome, $reason), $package);

        if (!$acknowledged instanceof FinalisedRecord) {
            $this->refuseUnrecorded(AuditReadRefusedException::unrecorded());
        }

        $this->confirmAcknowledgementDurable();

        return $acknowledged;
    }

    /**
     * Write the builder's record through the record pipeline with the package
     * write, under the definitions and contributors registered while the
     * application booted, refusing the read, once the failure is reported, when
     * the write failed or the delivery refused it.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  \SineMacula\Laravel\AuditLog\Delivery\PackageWrite  $package
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function write(#[\SensitiveParameter] PendingRecord $pending, #[\SensitiveParameter] PackageWrite $package): void
    {
        $pipeline = new RecordPipeline($this->container->make(EventCatalogue::class), $this->container->make(ContributorRegistry::class));

        try {
            $pipeline->write($pending, null, $package);
        } catch (AuditWriteFailedException|\LogicException $failure) {
            $this->refuseUnrecorded($failure);
        }
    }

    /**
     * Refuse the read when a transaction is open, after the write, that the
     * acknowledged record could still be rolled back with, once the refusal is
     * reported.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function confirmAcknowledgementDurable(): void
    {
        try {
            $this->container->make(ReadGate::class)->confirmDurable();
        } catch (AuditReadRefusedException $refusal) {
            $this->report($refusal);

            throw $refusal;
        }
    }

    /**
     * Report the failure once, through the report latch, and refuse the read as
     * unrecorded.
     *
     * @param  \Throwable  $failure
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function refuseUnrecorded(\Throwable $failure): never
    {
        $this->report($failure);

        throw AuditReadRefusedException::unrecorded();
    }

    /**
     * Report the failure once, through the report latch, ignoring a reporter
     * that fails.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    private function report(\Throwable $failure): void
    {
        try {
            $handler = $this->container->make(ExceptionHandler::class);

            $this->container->make(ReportLatch::class)->once(static function () use ($handler, $failure): void {
                $handler->report($failure);
            });
        } catch (\Throwable) {
            // The read is refused all the same; a broken reporter has nowhere
            // left to say so, and must not replace the refusal
        }
    }

    /**
     * The builder of the record: the activity's code, by the viewer's
     * reference, in the scope's single tenant or explicitly none, with the
     * evidence's properties and manifest, the outcome and its reason,
     * fail-closed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity  $activity
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  ?\SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\AccessEvidence  $evidence
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @param  ?string  $reason
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function pending(
        PackageActivity $activity,
        #[\SensitiveParameter] Viewer $viewer,
        ?AccessScope $scope,
        #[\SensitiveParameter] AccessEvidence $evidence,
        Outcome $outcome,
        ?string $reason,
    ): PendingRecord {
        $pending = (new PendingRecord)->forPackage($activity)->by($viewer->reference)->forTenant($scope?->singleTenant())->withProperties($evidence->properties);

        if ($evidence->manifest !== null) {
            $pending->withManifest($evidence->manifest);
        }

        $ended = match ($outcome) {
            Outcome::SUCCESS => $pending->succeeded(),
            Outcome::FAILURE => $pending->failed($reason),
            Outcome::DENIED  => $pending->denied($reason),
        };

        return $ended->failClosed();
    }
}
