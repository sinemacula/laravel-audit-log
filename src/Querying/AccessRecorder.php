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
 * Writes the record of a read fail-closed and returns it only once the store or
 * the outbox has acknowledged it, so nothing is disclosed before it is durable.
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

        /** Resolved from on every call, so the recorder outlives requests safely. */
        private Container $container,
    ) {}

    /**
     * Record the viewer's activity and return the acknowledged record.
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
     * Write the record through the pipeline, refusing the read when the write
     * fails or the delivery refuses it.
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
     * Refuse the read when a transaction the contributors left open could still
     * roll the acknowledged record back.
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
     * Report the failure once and refuse the read as unrecorded.
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
     * Report the failure once, ignoring a reporter that fails.
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
            // A broken reporter must not replace the refusal
        }
    }

    /**
     * The fail-closed record, in the scope's single tenant or explicitly none
     * so an ambient tenant is never inherited.
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
