<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Listeners;

use Illuminate\Container\Container;
use Illuminate\Log\Context\Repository;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Jobs\SyncJob;
use SineMacula\Laravel\AuditLog\Contributors\AmbientActor;
use SineMacula\Laravel\AuditLog\Runtime\CarriedContext;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;

/**
 * Enters an execution frame when a queued job starts and leaves it when the job
 * ends, on success and on failure, on a worker and on the sync queue.
 *
 * A failed job fires both `JobFailed` and `JobExceptionOccurred`, in an order
 * that depends on where it runs, so whichever comes first leaves the frame and
 * the other finds nothing to leave. Ending a frame reads nothing of the job's
 * payload, and a payload's name that is not a string is kept as none, so a job
 * that can run still has its frame.
 *
 * The frame keeps what the job carried, which Laravel has just hydrated into
 * Context, since a sync job inside this one replaces it there. A job on a
 * worker is the work of whoever dispatched it and nobody else, so its frame
 * also notes the users the guards still hold and the identifiers an earlier job
 * left. A sync job is left with its caller's, which are its dispatcher's.
 *
 * The frames are reached through the current container on every event, since a
 * dispatcher built with the booted application outlives the request a sync job
 * runs in under Octane. Only the package's own state changes: neither Context
 * nor the guards are touched.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TrackJobFrames
{
    /**
     * Handle the `JobProcessing`, `JobProcessed`, `JobFailed` and
     * `JobExceptionOccurred` events.
     *
     * @param  \Illuminate\Queue\Events\JobExceptionOccurred|\Illuminate\Queue\Events\JobFailed|\Illuminate\Queue\Events\JobProcessed|\Illuminate\Queue\Events\JobProcessing  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __invoke(JobExceptionOccurred|JobFailed|JobProcessed|JobProcessing $event): void
    {
        $container = Container::getInstance();
        $frames    = $container->make(ExecutionFrames::class);

        if (!$event instanceof JobProcessing) {

            $frames->leave($event->job);

            return;
        }

        $onWorker = !$event->job instanceof SyncJob;

        if ($onWorker) {
            $container->make(RequestIdentity::class)->forgetResolved();
        }

        $carried = CarriedContext::actor($container->make(Repository::class));

        $frames->enterJob($event->job, self::nameFrom($event->job->resolveName()), $carried, $onWorker ? self::leftovers($container) : []);
    }

    /**
     * The users the guards hold as a job on a worker starts. A setting or a
     * guard that cannot be read must not stop a job that may record nothing: it
     * gives none here, and a record the job makes fails closed on it.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return array<string, object>
     */
    private static function leftovers(Container $container): array
    {
        try {
            return $container->make(AmbientActor::class)->held();
        } catch (\Throwable) {
            return [];
        }
    }

    /**
     * The job's name, which is its class or its `displayName()` as the payload
     * gives it, or `null` for anything but a string: the payload's display name
     * is handed back as it was found, and a queued payload is not to be trusted
     * to have one that is.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $name
     * @return ?string
     */
    private static function nameFrom(mixed $name): ?string
    {
        return is_string($name) ? $name : null;
    }
}
